//! Published known-answer vectors (`test-vectors/v1/`, DESIGN.md §10).
//!
//! Two independent checks:
//! 1. the library opens the vectors with production limits, and
//! 2. a minimal reader written only from DESIGN.md §4 (below, `reference`)
//!    decodes them too, using the raw primitives instead of the library.
//!    If the library and the document ever disagree, this test fails.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use sha2::{Digest, Sha256};
use vault_core::{keyfile, KdfLimits, Password, Vault};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/v1")
}

fn vectors() -> Value {
    serde_json::from_str(&fs::read_to_string(dir().join("vectors.json")).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k}"))
}

#[test]
fn files_match_their_published_hashes() {
    let v = vectors();
    for (file, hash) in [
        ("key_file", "key_file_sha256"),
        ("vault_file", "vault_file_sha256"),
    ] {
        let bytes = fs::read(dir().join(s(&v, file))).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&bytes)), s(&v, hash), "{file}");
    }
}

#[test]
fn library_opens_vectors_with_production_limits() {
    let v = vectors();
    let key_bytes = fs::read(dir().join(s(&v, "key_file"))).unwrap();
    let (id, params) = keyfile::inspect(&key_bytes).unwrap();
    assert_eq!(id.to_string(), s(&v, "key_id"));
    assert_eq!(params.m_kib as u64, v["kdf"]["m_kib"].as_u64().unwrap());

    // The password in the vectors is NFD; the library normalises to NFC.
    let pw = Password::new_unchecked(s(&v, "password"));
    assert_eq!(hex::encode(pw.as_bytes()), s(&v, "password_nfc_utf8_hex"));
    let key = keyfile::open(&key_bytes, &pw, &KdfLimits::PRODUCTION).unwrap();

    let vault = Vault::open(&dir().join(s(&v, "vault_file")), &key).unwrap();
    let want = v["entries"].as_array().unwrap();
    assert_eq!(vault.entries().len(), want.len());
    for (e, w) in vault.entries().iter().zip(want) {
        assert_eq!(e.path, s(w, "path"));
        assert_eq!(e.size, w["size"].as_u64().unwrap());
        assert_eq!(e.modified, w["modified"].as_i64().unwrap());
    }

    let out = tempfile::tempdir().unwrap();
    vault.extract(out.path(), &[], false).unwrap();
    for w in want {
        let data = fs::read(out.path().join(s(w, "path"))).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            s(w, "sha256"),
            "{}",
            s(w, "path")
        );
    }

    assert!(keyfile::open(
        &key_bytes,
        &Password::new_unchecked("wrong password, same length"),
        &KdfLimits::PRODUCTION
    )
    .is_err());
}

#[test]
fn reference_reader_decodes_vectors() {
    let v = vectors();
    let key_bytes = fs::read(dir().join(s(&v, "key_file"))).unwrap();
    let vault_bytes = fs::read(dir().join(s(&v, "vault_file"))).unwrap();
    let pw = hex::decode(s(&v, "password_nfc_utf8_hex")).unwrap();

    let (kek, mk) = reference::unlock_key(&key_bytes, &pw);
    assert_eq!(hex::encode(kek), s(&v, "kek_hex"));
    let files = reference::read_vault(&vault_bytes, &mk);

    let want = v["entries"].as_array().unwrap();
    assert_eq!(files.len(), want.len());
    for ((path, modified, data), w) in files.iter().zip(want) {
        assert_eq!(path, s(w, "path"));
        assert_eq!(*modified, w["modified"].as_i64().unwrap());
        assert_eq!(hex::encode(Sha256::digest(data)), s(w, "sha256"), "{path}");
    }
}

/// A deliberately small, independent decoder following DESIGN.md §4.3–4.4.
/// It panics on any error; it is a test oracle, not production code.
mod reference {
    use argon2::{Algorithm, Argon2, Params, Version};
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    fn u16le(b: &[u8], i: usize) -> u16 {
        u16::from_le_bytes(b[i..i + 2].try_into().unwrap())
    }
    fn u32le(b: &[u8], i: usize) -> u32 {
        u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
    }
    fn u64le(b: &[u8], i: usize) -> u64 {
        u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
    }

    fn open(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Vec<u8> {
        XChaCha20Poly1305::new_from_slice(key)
            .unwrap()
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
            .expect("authentication failed")
    }

    /// §4.3: returns (KEK, master key).
    pub fn unlock_key(k: &[u8], password_nfc: &[u8]) -> ([u8; 32], Vec<u8>) {
        assert_eq!(k.len(), 128);
        assert_eq!(&k[0..8], b"SVKEY\0\0\x01");
        assert_eq!((u16le(k, 8), u16le(k, 10)), (1, 0));
        let (m, t, p) = (u32le(k, 28), u32le(k, 32), u32le(k, 36));
        let mut kek = [0u8; 32];
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(m, t, p, Some(32)).unwrap(),
        )
        .hash_password_into(password_nfc, &k[40..56], &mut kek)
        .unwrap();
        let mk = open(&kek, &k[56..80], &k[80..128], &k[..56]);
        assert_eq!(mk.len(), 32);
        (kek, mk)
    }

    /// §4.4: returns (path, modified, contents) per entry, in index order.
    pub fn read_vault(f: &[u8], mk: &[u8]) -> Vec<(String, i64, Vec<u8>)> {
        assert_eq!(&f[0..8], b"SVAULT\0\x01");
        assert_eq!((u16le(f, 8), u16le(f, 10)), (1, 0));
        let fek = open(mk, &f[44..68], &f[68..116], &f[..44]);
        let aad = |domain: &[u8]| [&f[..28], domain].concat();

        let t = f.len() - 24;
        assert_eq!(&f[t + 16..], b"SVEND\0\0\x01");
        let (io, il) = (u64le(f, t) as usize, u64le(f, t + 8) as usize);
        assert_eq!(io + il, t, "index must end where the trailer starts");
        let idx = open(&fek, &f[io..io + 24], &f[io + 24..t], &aad(b"SV-INDEX"));

        let mut out = Vec::new();
        let mut c = 4;
        for _ in 0..u32le(&idx, 0) {
            let n = u16le(&idx, c) as usize;
            let path = String::from_utf8(idx[c + 2..c + 2 + n].to_vec()).unwrap();
            c += 2 + n;
            let size = u64le(&idx, c);
            let compressed = u64le(&idx, c + 8);
            let modified = u64le(&idx, c + 16) as i64;
            let offset = u64le(&idx, c + 24) as usize;
            let length = u64le(&idx, c + 32) as usize;
            let prefix = &idx[c + 40..c + 59];
            let chunk = u32le(&idx, c + 59) as usize;
            c += 63;

            // STREAM (BE32): nonce = prefix[19] || counter u32 BE || last flag.
            let mut z = Vec::new();
            let data = &f[offset..offset + length];
            let full = chunk + 16;
            let chunks = data.len().div_ceil(full).max(1);
            for i in 0..chunks {
                let part = &data[i * full..((i + 1) * full).min(data.len())];
                let mut nonce = prefix.to_vec();
                nonce.extend_from_slice(&(i as u32).to_be_bytes());
                nonce.push(u8::from(i + 1 == chunks));
                z.extend(open(&fek, &nonce, part, &aad(b"SV-ENTRY")));
            }
            assert_eq!(z.len() as u64, compressed);
            let plain = zstd::decode_all(&z[..]).unwrap();
            assert_eq!(plain.len() as u64, size);
            out.push((path, modified, plain));
        }
        assert_eq!(c, idx.len(), "trailing bytes in index");
        out
    }
}
