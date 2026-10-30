//! Vault (`.svault`), DESIGN.md §4.4.
//!
//! ```text
//! [Header 116 bytes]
//!   0   8  magic "SVAULT\0\1"
//!   8   2  format_version (u16 LE) = 1
//!   10  2  flags (u16 LE) = 0
//!   12  16 vault_id     (random, never changes)
//!   28  16 key_id       (changes on rekey)
//!   44  24 fek_nonce
//!   68  48 XChaCha20-Poly1305(MK, fek_nonce, FEK) ; AAD = bytes 0..44
//! [Entry streams]   STREAM(FEK), 1 MiB chunks ; AAD = bytes 0..28 || "SV-ENTRY"
//! [Index block]     nonce(24) || XChaCha20-Poly1305(FEK) ; AAD = bytes 0..28 || "SV-INDEX"
//! [Trailer 24 bytes] index_offset u64, index_length u64, "SVEND\0\0\1"
//! ```
//!
//! Every change (add, replace, remove) rewrites the whole vault to a
//! temporary file and renames it over the original. Existing entries are
//! copied as ciphertext, not re-encrypted. Old index blocks therefore never
//! survive, which prevents rolling a vault back to an earlier file list.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::fsutil;
use crate::keyfile::{KeyId, UnlockedKey};
use crate::{index, pathsafe, rng, Error, Result};

pub const EXTENSION: &str = "svault";
pub const HEADER_LEN: usize = 116;
pub const TRAILER_LEN: usize = 24;
pub const CHUNK_SIZE: u32 = 1 << 20;
pub(crate) const TAG_LEN: u64 = 16;
pub(crate) const STREAM_NONCE_LEN: usize = 19;

const MAGIC: &[u8; 8] = b"SVAULT\0\x01";
const TRAILER_MAGIC: &[u8; 8] = b"SVEND\0\0\x01";
const VERSION: u16 = 1;
const IMMUTABLE_LEN: usize = 28;
const FEK_AAD_LEN: usize = 44;
const INDEX_NONCE_LEN: usize = 24;
const MAX_INDEX_LEN: u64 = 256 << 20;
const ZSTD_LEVEL: i32 = 6;
const DOMAIN_INDEX: &[u8] = b"SV-INDEX";
const DOMAIN_ENTRY: &[u8] = b"SV-ENTRY";

/// One file stored in a vault.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Relative path inside the vault, `/`-separated.
    pub path: String,
    /// Original size in bytes.
    pub size: u64,
    /// Size after compression.
    pub compressed_size: u64,
    /// Modification time, Unix seconds.
    pub modified: i64,
    pub(crate) offset: u64,
    pub(crate) length: u64,
    pub(crate) nonce_prefix: [u8; STREAM_NONCE_LEN],
    pub(crate) chunk_size: u32,
}

#[derive(Clone)]
struct Header([u8; HEADER_LEN]);

impl Header {
    fn new(key: &UnlockedKey, fek: &[u8; 32]) -> Result<Self> {
        let mut h = [0u8; HEADER_LEN];
        h[0..8].copy_from_slice(MAGIC);
        h[8..10].copy_from_slice(&VERSION.to_le_bytes());
        h[10..12].copy_from_slice(&0u16.to_le_bytes());
        h[12..28].copy_from_slice(&rng::array::<16>());
        Header(h).rewrap(fek, key)
    }

    fn parse(bytes: [u8; HEADER_LEN]) -> Result<Self> {
        if &bytes[0..8] != MAGIC {
            return Err(Error::NotVault);
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        let flags = u16::from_le_bytes([bytes[10], bytes[11]]);
        if version != VERSION || flags != 0 {
            return Err(Error::Unsupported(format!(
                "vault version {version}, flags {flags:#x}"
            )));
        }
        Ok(Header(bytes))
    }

    fn key_id(&self) -> KeyId {
        KeyId(self.0[28..44].try_into().expect("16 bytes"))
    }

    fn unwrap_fek(&self, key: &UnlockedKey) -> Result<Zeroizing<[u8; 32]>> {
        if self.key_id() != key.key_id() {
            return Err(Error::KeyMismatch {
                expected: self.key_id().to_string(),
                actual: key.key_id().to_string(),
            });
        }
        let pt = Zeroizing::new(
            XChaCha20Poly1305::new(Key::from_slice(key.master()))
                .decrypt(
                    XNonce::from_slice(&self.0[44..68]),
                    Payload {
                        msg: &self.0[68..116],
                        aad: &self.0[..FEK_AAD_LEN],
                    },
                )
                .map_err(|_| Error::Tampered)?,
        );
        let mut fek = Zeroizing::new([0u8; 32]);
        fek.copy_from_slice(&pt);
        Ok(fek)
    }

    /// Same vault_id, new key_id and FEK wrapping. Used on create and rekey.
    fn rewrap(&self, fek: &[u8; 32], key: &UnlockedKey) -> Result<Self> {
        let mut h = self.0;
        h[28..44].copy_from_slice(&key.key_id().0);
        let nonce: [u8; 24] = rng::array();
        h[44..68].copy_from_slice(&nonce);
        let ct = XChaCha20Poly1305::new(Key::from_slice(key.master()))
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: fek,
                    aad: &h[..FEK_AAD_LEN],
                },
            )
            .map_err(|_| Error::Crypto)?;
        h[68..116].copy_from_slice(&ct);
        Ok(Header(h))
    }

    fn aad(&self, domain: &[u8]) -> Vec<u8> {
        let mut a = self.0[..IMMUTABLE_LEN].to_vec();
        a.extend_from_slice(domain);
        a
    }
}

/// An open vault: header, decrypted file list, and the FEK.
pub struct Vault {
    path: PathBuf,
    header: Header,
    fek: Zeroizing<[u8; 32]>,
    entries: Vec<Entry>,
}

impl Vault {
    /// Which key file a vault needs, without any key.
    pub fn peek_key_id(path: &Path) -> Result<KeyId> {
        Ok(read_header(&mut File::open(path)?)?.key_id())
    }

    /// Opens a vault and decrypts its file list.
    pub fn open(path: &Path, key: &UnlockedKey) -> Result<Vault> {
        Self::open_from(path, &mut File::open(path)?, key)
    }

    /// Opens a vault through an already open handle (used while locked:
    /// on Windows a locked file cannot be read through another handle).
    fn open_from(path: &Path, f: &mut File, key: &UnlockedKey) -> Result<Vault> {
        f.seek(SeekFrom::Start(0))?;
        let header = read_header(f)?;
        let fek = header.unwrap_fek(key)?;
        let file_len = f.metadata()?.len();
        if file_len < (HEADER_LEN + TRAILER_LEN) as u64 {
            return Err(Error::Tampered);
        }

        let mut trailer = [0u8; TRAILER_LEN];
        f.seek(SeekFrom::Start(file_len - TRAILER_LEN as u64))?;
        f.read_exact(&mut trailer)?;
        if &trailer[16..24] != TRAILER_MAGIC {
            return Err(Error::Tampered);
        }
        let index_offset = u64::from_le_bytes(trailer[0..8].try_into().expect("8"));
        let index_len = u64::from_le_bytes(trailer[8..16].try_into().expect("8"));
        let min_index = (INDEX_NONCE_LEN as u64) + TAG_LEN + 4;
        if index_len < min_index
            || index_len > MAX_INDEX_LEN
            || index_offset < HEADER_LEN as u64
            || index_offset.checked_add(index_len) != Some(file_len - TRAILER_LEN as u64)
        {
            return Err(Error::Tampered);
        }

        let mut block = vec![0u8; index_len as usize];
        f.seek(SeekFrom::Start(index_offset))?;
        f.read_exact(&mut block)?;
        let (nonce, ct) = block.split_at(INDEX_NONCE_LEN);
        let plain = Zeroizing::new(
            XChaCha20Poly1305::new(Key::from_slice(fek.as_ref()))
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ct,
                        aad: &header.aad(DOMAIN_INDEX),
                    },
                )
                .map_err(|_| Error::Tampered)?,
        );
        let entries = index::decode(&plain, HEADER_LEN as u64, index_offset)?;
        Ok(Vault {
            path: path.to_path_buf(),
            header,
            fek,
            entries,
        })
    }

    /// Creates a new vault at `path` from files and folders. Refuses to
    /// overwrite. Returns the vault and any inputs skipped (symlinks).
    pub fn create(
        path: &Path,
        key: &UnlockedKey,
        inputs: &[PathBuf],
    ) -> Result<(Vault, Vec<PathBuf>)> {
        let (files, skipped) = collect_inputs(inputs)?;
        if files.is_empty() {
            return Err(Error::InvalidInput("nothing to add".into()));
        }
        let fek = Zeroizing::new(rng::array::<32>());
        let header = Header::new(key, &fek)?;
        // Reserve the name first so we never replace a file that appears
        // while we are writing.
        fsutil::reserve_new(path)?;
        let entries = match write_vault(path, &header, &fek, None, &[], &files)
            .and_then(|st| st.commit(path))
        {
            Ok(e) => e,
            Err(e) => {
                fsutil::remove_placeholder(path);
                return Err(e);
            }
        };
        Ok((
            Vault {
                path: path.to_path_buf(),
                header,
                fek,
                entries,
            },
            skipped,
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn key_id(&self) -> KeyId {
        self.header.key_id()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Adds files and folders. With `replace`, entries with the same path
    /// are overwritten; otherwise a clash is an error and nothing changes.
    pub fn add(&mut self, inputs: &[PathBuf], replace: bool) -> Result<Vec<PathBuf>> {
        let (files, skipped) = collect_inputs(inputs)?;
        if files.is_empty() {
            return Err(Error::InvalidInput("nothing to add".into()));
        }
        let incoming: std::collections::HashSet<String> =
            files.iter().map(|(_, n)| pathsafe::fold(n)).collect();
        let mut keep = Vec::new();
        for e in &self.entries {
            if incoming.contains(&pathsafe::fold(&e.path)) {
                if !replace {
                    return Err(Error::EntryExists(e.path.clone()));
                }
            } else {
                keep.push(e.clone());
            }
        }
        self.rewrite(&keep, &files)?;
        Ok(skipped)
    }

    /// Removes entries by exact path or by folder prefix.
    pub fn remove(&mut self, names: &[String]) -> Result<Vec<String>> {
        let selected = self.select(names)?;
        let removed: Vec<String> = selected.iter().map(|e| e.path.clone()).collect();
        let keep: Vec<Entry> = self
            .entries
            .iter()
            .filter(|e| !removed.contains(&e.path))
            .cloned()
            .collect();
        self.rewrite(&keep, &[])?;
        Ok(removed)
    }

    /// Extracts entries into `dest` (all if `only` is empty). Each name in
    /// `only` matches an exact path or a folder prefix. Existing files are
    /// an error unless `overwrite` is set. Returns extracted paths.
    pub fn extract(&self, dest: &Path, only: &[String], overwrite: bool) -> Result<Vec<String>> {
        let selected: Vec<Entry> = if only.is_empty() {
            self.entries.clone()
        } else {
            self.select(only)?
        };
        fs::create_dir_all(dest)?;
        let root = dest.canonicalize()?;
        let mut src = BufReader::new(File::open(&self.path)?);
        let aad = self.header.aad(DOMAIN_ENTRY);
        let mut done = Vec::new();

        for e in &selected {
            let target = pathsafe::prepare_target(&root, &e.path)?;
            match fs::symlink_metadata(&target) {
                Ok(m) if m.is_dir() => {
                    return Err(Error::UnsafePath(format!(
                        "{} is a folder",
                        target.display()
                    )))
                }
                Ok(_) if !overwrite => return Err(Error::DestinationExists(target)),
                _ => {}
            }
            // Never write into an existing file: decrypt into a fresh temp
            // file, then rename it into place. Renaming replaces a link
            // instead of writing through it, and a failed entry never
            // touches the user's original file.
            if !overwrite {
                fsutil::reserve_new(&target)?;
            }
            let (tmp, f) = fsutil::create_tmp(&target)?;
            let result = (|| -> Result<()> {
                let mut w = BufWriter::new(f);
                decrypt_entry(&mut src, e, &self.fek, &aad, &mut w)?;
                let f = w.into_inner().map_err(|e| Error::Io(e.into_error()))?;
                if e.modified > 0 {
                    if let Some(t) = UNIX_EPOCH.checked_add(Duration::from_secs(e.modified as u64))
                    {
                        let _ = f.set_modified(t);
                    }
                }
                f.sync_all()?;
                drop(f);
                fsutil::commit(&tmp, &target)?;
                // Detect a folder swapped for a link while we were writing.
                let parent = target.parent().unwrap_or(&root).canonicalize()?;
                if !parent.starts_with(&root) {
                    let _ = fs::remove_file(&target);
                    return Err(Error::UnsafePath(format!(
                        "{} moved outside the destination during extraction",
                        target.display()
                    )));
                }
                Ok(())
            })();
            if let Err(err) = result {
                let _ = fs::remove_file(&tmp);
                if !overwrite {
                    fsutil::remove_placeholder(&target);
                }
                return Err(err);
            }
            done.push(e.path.clone());
        }
        Ok(done)
    }

    fn select(&self, names: &[String]) -> Result<Vec<Entry>> {
        let mut out: Vec<Entry> = Vec::new();
        for name in names {
            let n = name.trim_end_matches('/');
            let prefix = format!("{n}/");
            let mut hit = false;
            for e in &self.entries {
                if (e.path == n || e.path.starts_with(&prefix))
                    && !out.iter().any(|o| o.path == e.path)
                {
                    out.push(e.clone());
                    hit = true;
                } else if e.path == n || e.path.starts_with(&prefix) {
                    hit = true;
                }
            }
            if !hit {
                return Err(Error::EntryNotFound(name.clone()));
            }
        }
        Ok(out)
    }

    fn rewrite(&mut self, keep: &[Entry], files: &[SourceFile]) -> Result<()> {
        let path = self.path.clone();
        let mut lock = lock_vault(&path)?;
        let old = OldVault {
            reader: &mut lock,
            reencrypt_from: None,
        };
        let staged = write_vault(&path, &self.header, &self.fek, Some(old), keep, files)?;
        drop(lock);
        self.entries = staged.commit(&path)?;
        Ok(())
    }
}

/// Moves a vault to a new key (DESIGN.md §4.5).
///
/// Generates a new FEK and a new `vault_id` and re-encrypts every entry
/// (decrypt chunk with the old FEK, encrypt with the new one; no
/// recompression). Afterwards nothing in the vault can be read with the old
/// key, and old headers cannot be spliced onto the new file.
pub fn rekey(path: &Path, old: &UnlockedKey, new: &UnlockedKey) -> Result<()> {
    let mut lock = lock_vault(path)?;
    let vault = Vault::open_from(path, &mut lock, old)?;
    let new_fek = Zeroizing::new(rng::array::<32>());
    let new_header = Header::new(new, &new_fek)?;
    let old_aad = vault.header.aad(DOMAIN_ENTRY);
    let source = OldVault {
        reader: &mut lock,
        reencrypt_from: Some((&vault.fek, &old_aad)),
    };
    let staged = write_vault(
        path,
        &new_header,
        &new_fek,
        Some(source),
        &vault.entries,
        &[],
    )?;
    drop(lock);
    staged.commit(path)?;
    Ok(())
}

/// Advisory exclusive lock on a vault while it is being rewritten, so two
/// processes cannot change the same vault at once.
fn lock_vault(path: &Path) -> Result<File> {
    let f = File::open(path)?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(fs::TryLockError::WouldBlock) => Err(Error::InvalidInput(format!(
            "{} is being changed by another process",
            path.display()
        ))),
        Err(fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// The existing vault that kept entries are taken from.
struct OldVault<'a> {
    /// Handle to the existing vault (the locked one).
    reader: &'a mut File,
    /// `Some((old FEK, old entry AAD))` to re-encrypt kept entries under the
    /// new FEK (rekey); `None` to copy their ciphertext verbatim.
    reencrypt_from: Option<(&'a [u8; 32], &'a [u8])>,
}

fn read_header(f: &mut File) -> Result<Header> {
    let mut h = [0u8; HEADER_LEN];
    f.read_exact(&mut h).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => Error::NotVault,
        _ => Error::Io(e),
    })?;
    Header::parse(h)
}

/// A fully written and synced temp file, not yet renamed into place.
struct Staged {
    tmp: PathBuf,
    entries: Vec<Entry>,
}

impl Staged {
    fn commit(self, target: &Path) -> Result<Vec<Entry>> {
        match fsutil::commit(&self.tmp, target) {
            Ok(()) => Ok(self.entries),
            Err(e) => {
                let _ = fs::remove_file(&self.tmp);
                Err(e)
            }
        }
    }
}

/// Writes a complete vault to a temp file next to `target`. The caller
/// renames it into place with [`Staged::commit`] (after releasing the lock).
/// `old` is the existing vault from which `keep` entries are taken.
fn write_vault(
    target: &Path,
    header: &Header,
    fek: &[u8; 32],
    old: Option<OldVault<'_>>,
    keep: &[Entry],
    files: &[SourceFile],
) -> Result<Staged> {
    if keep.len() + files.len() > index::MAX_ENTRIES as usize {
        return Err(Error::LimitExceeded("too many files for one vault"));
    }
    let (tmp, tmp_file) = fsutil::create_tmp(target)?;
    let result = (|| -> Result<Vec<Entry>> {
        let mut w = BufWriter::new(tmp_file);
        w.write_all(&header.0)?;
        let mut pos = HEADER_LEN as u64;
        let mut out = Vec::with_capacity(keep.len() + files.len());
        let aad = header.aad(DOMAIN_ENTRY);

        if let Some(old) = old {
            let mut r = BufReader::new(&mut *old.reader);
            for e in keep {
                let ne = match old.reencrypt_from {
                    None => {
                        r.seek(SeekFrom::Start(e.offset))?;
                        let copied = io::copy(&mut (&mut r).take(e.length), &mut w)?;
                        if copied != e.length {
                            return Err(Error::Tampered);
                        }
                        Entry {
                            offset: pos,
                            ..e.clone()
                        }
                    }
                    Some((old_fek, old_aad)) => {
                        reencrypt_entry(&mut r, e, old_fek, old_aad, &mut w, fek, &aad, pos)?
                    }
                };
                pos += ne.length;
                out.push(ne);
            }
        }

        for (src, name) in files {
            let e = encrypt_entry(&mut w, src, name, fek, &aad, pos)?;
            pos += e.length;
            out.push(e);
        }

        let plain = index::encode(&out);
        let nonce: [u8; INDEX_NONCE_LEN] = rng::array();
        let ct = XChaCha20Poly1305::new(Key::from_slice(fek))
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &header.aad(DOMAIN_INDEX),
                },
            )
            .map_err(|_| Error::Crypto)?;
        let index_len = (INDEX_NONCE_LEN + ct.len()) as u64;
        if index_len > MAX_INDEX_LEN {
            return Err(Error::LimitExceeded("file list too large"));
        }
        w.write_all(&nonce)?;
        w.write_all(&ct)?;
        w.write_all(&pos.to_le_bytes())?;
        w.write_all(&index_len.to_le_bytes())?;
        w.write_all(TRAILER_MAGIC)?;

        let f = w.into_inner().map_err(|e| Error::Io(e.into_error()))?;
        f.sync_all()?;
        Ok(out)
    })();
    match result {
        Ok(entries) => Ok(Staged { tmp, entries }),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

struct CountingReader<R> {
    inner: R,
    count: u64,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        Ok(n)
    }
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Compresses and encrypts one file into `w`.
fn encrypt_entry<W: Write>(
    w: &mut W,
    src: &Path,
    name: &str,
    fek: &[u8; 32],
    aad: &[u8],
    offset: u64,
) -> Result<Entry> {
    let file = fsutil::open_regular_nofollow(src)?;
    let modified = file
        .metadata()?
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut zr = zstd::stream::read::Encoder::new(
        CountingReader {
            inner: BufReader::new(file),
            count: 0,
        },
        ZSTD_LEVEL,
    )?;

    let nonce_prefix: [u8; STREAM_NONCE_LEN] = rng::array();
    let mut stream = EncryptorBE32::from_aead(
        XChaCha20Poly1305::new(Key::from_slice(fek)),
        GenericArray::from_slice(&nonce_prefix),
    );
    let cs = CHUNK_SIZE as usize;
    let mut cur = Zeroizing::new(vec![0u8; cs]);
    let mut next = Zeroizing::new(vec![0u8; cs]);
    let mut cur_len = read_full(&mut zr, &mut cur)?;
    let mut compressed = 0u64;
    let mut written = 0u64;

    loop {
        let next_len = if cur_len == cs {
            read_full(&mut zr, &mut next)?
        } else {
            0
        };
        compressed += cur_len as u64;
        if next_len > 0 {
            let ct = stream
                .encrypt_next(Payload {
                    msg: &cur[..cur_len],
                    aad,
                })
                .map_err(|_| Error::Crypto)?;
            w.write_all(&ct)?;
            written += ct.len() as u64;
            std::mem::swap(&mut cur, &mut next);
            cur_len = next_len;
        } else {
            let ct = stream
                .encrypt_last(Payload {
                    msg: &cur[..cur_len],
                    aad,
                })
                .map_err(|_| Error::Crypto)?;
            w.write_all(&ct)?;
            written += ct.len() as u64;
            break;
        }
    }
    let size = zr.finish().into_inner().count;
    debug_assert_eq!(index::stream_len(compressed, CHUNK_SIZE), Some(written));

    Ok(Entry {
        path: name.to_owned(),
        size,
        compressed_size: compressed,
        modified,
        offset,
        length: written,
        nonce_prefix,
        chunk_size: CHUNK_SIZE,
    })
}

#[derive(Debug)]
struct SizeExceeded;
impl std::fmt::Display for SizeExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("entry larger than its declared size")
    }
}
impl std::error::Error for SizeExceeded {}

/// Refuses to write more than the size recorded in the (authenticated) index.
struct LimitWriter<W> {
    inner: W,
    remaining: u64,
}

impl<W: Write> Write for LimitWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() as u64 > self.remaining {
            return Err(io::Error::other(SizeExceeded));
        }
        let n = self.inner.write(buf)?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn map_write_err(e: io::Error) -> Error {
    if e.get_ref().is_some_and(|i| i.is::<SizeExceeded>()) {
        Error::LimitExceeded("entry larger than its declared size")
    } else {
        Error::Io(e)
    }
}

/// Re-encrypts one entry's chunks from `old_fek` to `new_fek` without
/// decompressing. Chunk sizes are unchanged, so the length is unchanged.
#[allow(clippy::too_many_arguments)]
fn reencrypt_entry<R: Read + Seek, W: Write>(
    r: &mut R,
    e: &Entry,
    old_fek: &[u8; 32],
    old_aad: &[u8],
    w: &mut W,
    new_fek: &[u8; 32],
    new_aad: &[u8],
    offset: u64,
) -> Result<Entry> {
    r.seek(SeekFrom::Start(e.offset))?;
    let mut dec = DecryptorBE32::from_aead(
        XChaCha20Poly1305::new(Key::from_slice(old_fek)),
        GenericArray::from_slice(&e.nonce_prefix),
    );
    let nonce_prefix: [u8; STREAM_NONCE_LEN] = rng::array();
    let mut enc = EncryptorBE32::from_aead(
        XChaCha20Poly1305::new(Key::from_slice(new_fek)),
        GenericArray::from_slice(&nonce_prefix),
    );
    let full = e.chunk_size as u64 + TAG_LEN;
    let mut buf = vec![0u8; full as usize];
    let mut remaining = e.length;
    let mut written = 0u64;
    loop {
        if remaining > full {
            r.read_exact(&mut buf)?;
            let pt = Zeroizing::new(
                dec.decrypt_next(Payload {
                    msg: &buf,
                    aad: old_aad,
                })
                .map_err(|_| Error::Tampered)?,
            );
            let ct = enc
                .encrypt_next(Payload {
                    msg: &pt,
                    aad: new_aad,
                })
                .map_err(|_| Error::Crypto)?;
            w.write_all(&ct)?;
            written += ct.len() as u64;
            remaining -= full;
        } else {
            let n = remaining as usize;
            r.read_exact(&mut buf[..n])?;
            let pt = Zeroizing::new(
                dec.decrypt_last(Payload {
                    msg: &buf[..n],
                    aad: old_aad,
                })
                .map_err(|_| Error::Tampered)?,
            );
            let ct = enc
                .encrypt_last(Payload {
                    msg: &pt,
                    aad: new_aad,
                })
                .map_err(|_| Error::Crypto)?;
            w.write_all(&ct)?;
            written += ct.len() as u64;
            break;
        }
    }
    if written != e.length {
        return Err(Error::Crypto);
    }
    Ok(Entry {
        offset,
        nonce_prefix,
        ..e.clone()
    })
}

/// Decrypts, authenticates and decompresses one entry into `out`. Each chunk
/// is authenticated before any of its bytes are decompressed or written.
fn decrypt_entry<R: Read + Seek, W: Write>(
    r: &mut R,
    e: &Entry,
    fek: &[u8; 32],
    aad: &[u8],
    out: W,
) -> Result<()> {
    r.seek(SeekFrom::Start(e.offset))?;
    let mut limited = LimitWriter {
        inner: out,
        remaining: e.size,
    };
    {
        let mut dec = zstd::stream::write::Decoder::new(&mut limited)?;
        let mut stream = DecryptorBE32::from_aead(
            XChaCha20Poly1305::new(Key::from_slice(fek)),
            GenericArray::from_slice(&e.nonce_prefix),
        );
        let full = e.chunk_size as u64 + TAG_LEN;
        let mut buf = vec![0u8; full as usize];
        let mut remaining = e.length;
        loop {
            if remaining > full {
                r.read_exact(&mut buf)?;
                let pt = Zeroizing::new(
                    stream
                        .decrypt_next(Payload { msg: &buf, aad })
                        .map_err(|_| Error::Tampered)?,
                );
                dec.write_all(&pt).map_err(map_write_err)?;
                remaining -= full;
            } else {
                let n = remaining as usize;
                r.read_exact(&mut buf[..n])?;
                let pt = Zeroizing::new(
                    stream
                        .decrypt_last(Payload {
                            msg: &buf[..n],
                            aad,
                        })
                        .map_err(|_| Error::Tampered)?,
                );
                dec.write_all(&pt).map_err(map_write_err)?;
                break;
            }
        }
        dec.flush().map_err(map_write_err)?;
    }
    if limited.remaining != 0 {
        return Err(Error::Tampered);
    }
    limited.inner.flush()?;
    Ok(())
}

/// (source file on disk, path inside the vault)
type SourceFile = (PathBuf, String);

/// Expands inputs into (source file, archive path) pairs. Folders are walked
/// recursively; symlinks and junctions are skipped, never followed.
fn collect_inputs(inputs: &[PathBuf]) -> Result<(Vec<SourceFile>, Vec<PathBuf>)> {
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    for input in inputs {
        let meta = fs::symlink_metadata(input)?;
        if meta.file_type().is_symlink() {
            skipped.push(input.clone());
            continue;
        }
        let base =
            match input.file_name() {
                Some(n) => PathBuf::from(n),
                None => PathBuf::from(input.canonicalize()?.file_name().ok_or_else(|| {
                    Error::InvalidInput(format!("cannot add {}", input.display()))
                })?),
            };
        if meta.is_file() {
            files.push((input.clone(), pathsafe::from_relative(&base)?));
        } else if meta.is_dir() {
            walk(input, &base, &mut files, &mut skipped)?;
        } else {
            skipped.push(input.clone());
        }
    }
    let mut seen = std::collections::HashSet::new();
    for (_, name) in &files {
        if !seen.insert(pathsafe::fold(name)) {
            return Err(Error::InvalidInput(format!(
                "two inputs map to the same name in the vault: {name}"
            )));
        }
    }
    Ok((files, skipped))
}

fn walk(
    dir: &Path,
    rel: &Path,
    files: &mut Vec<(PathBuf, String)>,
    skipped: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut items: Vec<_> = fs::read_dir(dir)?.collect::<io::Result<_>>()?;
    items.sort_by_key(|d| d.file_name());
    for item in items {
        let ft = item.file_type()?;
        let p = item.path();
        let r = rel.join(item.file_name());
        if ft.is_symlink() {
            skipped.push(p);
        } else if ft.is_dir() {
            walk(&p, &r, files, skipped)?;
        } else if ft.is_file() {
            files.push((p, pathsafe::from_relative(&r)?));
        } else {
            skipped.push(p);
        }
    }
    Ok(())
}

/// Formats a Unix timestamp for display (UTC, `YYYY-MM-DD HH:MM`).
pub fn format_time(secs: i64) -> String {
    let s = secs.max(0) as u64;
    let days = (s / 86_400) as i64;
    let rem = s % 86_400;
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60
    )
}
