//! Key file (`.svkey`), DESIGN.md §4.3.
//!
//! ```text
//! 0   8  magic "SVKEY\0\0\1"
//! 8   2  format_version (u16 LE) = 1
//! 10  2  flags (u16 LE) = 0
//! 12  16 key_id
//! 28  4  argon2 m (KiB)  32 4 argon2 t   36 4 argon2 p
//! 40  16 salt
//! 56  24 nonce
//! 80  48 XChaCha20-Poly1305(KEK, nonce, master_key) ; AAD = bytes 0..56
//! ```

use std::fmt;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::kdf::{self, KdfLimits, KdfParams};
use crate::{fsutil, rng, Error, Password, Result};

pub const KEYFILE_LEN: usize = 128;
pub const EXTENSION: &str = "svkey";

const MAGIC: &[u8; 8] = b"SVKEY\0\0\x01";
const VERSION: u16 = 1;
const AAD_LEN: usize = 56;

/// Identifies a key file. Stored in plaintext in key files and vaults so the
/// app can tell which key a vault needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyId(pub [u8; 16]);

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A decrypted master key. Wiped from memory on drop.
pub struct UnlockedKey {
    key_id: KeyId,
    master: Zeroizing<[u8; 32]>,
}

impl UnlockedKey {
    /// Generates a brand-new key (new `key_id` and master key).
    pub fn generate() -> Self {
        UnlockedKey {
            key_id: KeyId(rng::array()),
            master: Zeroizing::new(rng::array()),
        }
    }

    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub(crate) fn master(&self) -> &[u8; 32] {
        &self.master
    }
}

/// Encrypts `key` under `password` and returns key file bytes.
pub fn seal(
    key: &UnlockedKey,
    password: &Password,
    params: KdfParams,
    limits: &KdfLimits,
) -> Result<[u8; KEYFILE_LEN]> {
    limits.check(&params)?;
    let salt: [u8; 16] = rng::array();
    let nonce: [u8; 24] = rng::array();

    let mut out = [0u8; KEYFILE_LEN];
    out[0..8].copy_from_slice(MAGIC);
    out[8..10].copy_from_slice(&VERSION.to_le_bytes());
    out[10..12].copy_from_slice(&0u16.to_le_bytes());
    out[12..28].copy_from_slice(&key.key_id.0);
    out[28..32].copy_from_slice(&params.m_kib.to_le_bytes());
    out[32..36].copy_from_slice(&params.t.to_le_bytes());
    out[36..40].copy_from_slice(&params.p.to_le_bytes());
    out[40..56].copy_from_slice(&salt);
    out[56..80].copy_from_slice(&nonce);

    let kek = kdf::derive(password, &salt, &params)?;
    let ct = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()))
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: key.master.as_ref(),
                aad: &out[..AAD_LEN],
            },
        )
        .map_err(|_| Error::Crypto)?;
    out[80..128].copy_from_slice(&ct);
    Ok(out)
}

/// Reads the key id and KDF parameters without the password.
pub fn inspect(bytes: &[u8]) -> Result<(KeyId, KdfParams)> {
    if bytes.len() != KEYFILE_LEN || &bytes[0..8] != MAGIC {
        return Err(Error::NotKeyFile);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    let flags = u16::from_le_bytes([bytes[10], bytes[11]]);
    if version != VERSION || flags != 0 {
        return Err(Error::Unsupported(format!(
            "key file version {version}, flags {flags:#x}"
        )));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes[12..28]);
    let u32_at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().expect("4 bytes"));
    Ok((
        KeyId(id),
        KdfParams {
            m_kib: u32_at(28),
            t: u32_at(32),
            p: u32_at(36),
        },
    ))
}

/// Decrypts key file bytes with `password`.
pub fn open(bytes: &[u8], password: &Password, limits: &KdfLimits) -> Result<UnlockedKey> {
    let (key_id, params) = inspect(bytes)?;
    limits.check(&params)?;
    let salt: [u8; 16] = bytes[40..56].try_into().expect("16 bytes");
    let kek = kdf::derive(password, &salt, &params)?;
    let pt = Zeroizing::new(
        XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()))
            .decrypt(
                XNonce::from_slice(&bytes[56..80]),
                Payload {
                    msg: &bytes[80..128],
                    aad: &bytes[..AAD_LEN],
                },
            )
            .map_err(|_| Error::WrongPasswordOrCorrupt)?,
    );
    let mut master = Zeroizing::new([0u8; 32]);
    master.copy_from_slice(&pt);
    Ok(UnlockedKey { key_id, master })
}

/// Creates a new key file at `path` (refuses to overwrite).
pub fn create_file(
    path: &Path,
    password: &Password,
    params: KdfParams,
    limits: &KdfLimits,
) -> Result<UnlockedKey> {
    let key = UnlockedKey::generate();
    let bytes = seal(&key, password, params, limits)?;
    fsutil::write_new(path, &bytes)?;
    Ok(key)
}

/// Writes `key` to a new key file at `path` (refuses to overwrite).
pub fn write_file(
    path: &Path,
    key: &UnlockedKey,
    password: &Password,
    params: KdfParams,
    limits: &KdfLimits,
) -> Result<()> {
    let bytes = seal(key, password, params, limits)?;
    fsutil::write_new(path, &bytes)
}

/// Writes an exact copy of key file `bytes` to a new file at `path`
/// (refuses to overwrite) and reads it back to confirm it landed intact.
/// Used for backups: the copy opens with the same password.
pub fn write_copy(path: &Path, bytes: &[u8]) -> Result<()> {
    inspect(bytes)?;
    fsutil::write_new(path, bytes)?;
    if std::fs::read(path)? != bytes {
        return Err(Error::InvalidInput(format!(
            "{} did not read back correctly; the drive may be faulty",
            path.display()
        )));
    }
    Ok(())
}

/// Opens the key file at `path`.
pub fn open_file(path: &Path, password: &Password, limits: &KdfLimits) -> Result<UnlockedKey> {
    let bytes = std::fs::read(path)?;
    open(&bytes, password, limits)
}

/// Changes the password of the key file at `path`, keeping the same master
/// key. DESIGN.md §4.5: this does **not** invalidate old copies of the key
/// file; use rekey for that.
pub fn change_password_file(
    path: &Path,
    old: &Password,
    new: &Password,
    params: KdfParams,
    limits: &KdfLimits,
) -> Result<()> {
    let key = open_file(path, old, limits)?;
    let bytes = seal(&key, new, params, limits)?;
    fsutil::replace_atomic(path, &bytes)
}
