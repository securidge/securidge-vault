//! Generates the published test vectors in `test-vectors/v1/` (DESIGN.md §10).
//!
//!     cargo run --release -p vault-core --example gen_test_vectors -- test-vectors/v1
//!
//! Nonces and salts are random, so every run produces different (equally
//! valid) files. The committed vectors are the reference; regenerate only
//! when the format version changes.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::json;
use sha2::{Digest, Sha256};
use vault_core::{kdf, keyfile, KdfLimits, KdfParams, Password, Vault};

/// Decomposed "é" (e + U+0301) on purpose: implementations must normalise
/// passwords to NFC before Argon2id.
pub const PASSWORD: &str = "Ve\u{301}ritable test-vector passphrase";
/// Lowest cost the application accepts, so the vectors also check that
/// [`KdfLimits::PRODUCTION`] opens them.
pub const PARAMS: KdfParams = KdfParams {
    m_kib: 256 * 1024,
    t: 3,
    p: 1,
};
const MTIME: u64 = 1_767_225_600; // 2026-01-01 00:00:00 UTC

fn pseudo_random(len: usize) -> Vec<u8> {
    // xorshift64*, fixed seed: incompressible but reproducible.
    let mut x: u64 = 0x5EC0_121D_6E00_0001;
    (0..len)
        .map(|_| {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
        })
        .collect()
}

fn put(root: &Path, rel: &str, data: &[u8]) -> PathBuf {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, data).unwrap();
    File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(MTIME))
        .unwrap();
    p
}

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).expect("output folder"));
    fs::create_dir_all(&out).unwrap();
    let key_path = out.join("key.svkey");
    let vault_path = out.join("vault.svault");
    for p in [&key_path, &vault_path] {
        let _ = fs::remove_file(p);
    }

    let src = tempfile::tempdir().unwrap();
    let s = src.path();
    // > 1 MiB of incompressible data, so its stream has two chunks.
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("hello.txt", b"Hello, Securidge Vault!\n".to_vec()),
        ("empty.bin", Vec::new()),
        (
            "docs/\u{d55c}\u{ae00} \u{d30c}\u{c77c}.txt",
            "UTF-8 file name.\n".repeat(200).into_bytes(),
        ),
        ("big/random.bin", pseudo_random((1 << 20) + 4321)),
    ];
    for (rel, data) in &files {
        put(s, rel, data);
    }
    let inputs = [
        s.join("hello.txt"),
        s.join("empty.bin"),
        s.join("docs"),
        s.join("big"),
    ];

    let pw = Password::new_unchecked(PASSWORD);
    let key = keyfile::create_file(&key_path, &pw, PARAMS, &KdfLimits::PRODUCTION).unwrap();
    let (vault, _) = Vault::create(&vault_path, &key, &inputs).unwrap();

    let kb = fs::read(&key_path).unwrap();
    let salt: [u8; 16] = kb[40..56].try_into().unwrap();
    let kek = kdf::derive(&pw, &salt, &PARAMS).unwrap();

    let entries: Vec<_> = vault
        .entries()
        .iter()
        .map(|e| {
            let data = &files
                .iter()
                .find(|(r, _)| *r == e.path)
                .expect("known file")
                .1;
            json!({
                "path": e.path,
                "size": e.size,
                "compressed_size": e.compressed_size,
                "modified": e.modified,
                "sha256": hex::encode(Sha256::digest(data)),
            })
        })
        .collect();

    let v = json!({
        "description": "Securidge Vault format v1 known-answer vectors. See README.md in this folder.",
        "format_version": 1,
        "password": PASSWORD,
        "password_nfc_utf8_hex": hex::encode(pw.as_bytes()),
        "kdf": { "algorithm": "argon2id", "version": 19, "m_kib": PARAMS.m_kib, "t": PARAMS.t, "p": PARAMS.p },
        "key_file": "key.svkey",
        "key_id": key.key_id().to_string(),
        "salt_hex": hex::encode(salt),
        "kek_hex": hex::encode(kek.as_ref()),
        "vault_file": "vault.svault",
        "key_file_sha256": hex::encode(Sha256::digest(&kb)),
        "vault_file_sha256": hex::encode(Sha256::digest(fs::read(&vault_path).unwrap())),
        "entries": entries,
    });
    fs::write(
        out.join("vectors.json"),
        serde_json::to_string_pretty(&v).unwrap() + "\n",
    )
    .unwrap();
    println!("wrote {}", out.display());
}
