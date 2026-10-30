//! Integration tests: round trips, tampering, key handling, path safety.
//! KDF parameters are tiny here so the suite runs fast; production limits
//! reject such key files (see `production_limits_reject_test_keys`).

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use vault_core::keyfile::{self, KEYFILE_LEN};
use vault_core::{vault, Error, KdfLimits, KdfParams, Password, UnlockedKey, Vault};

const LIMITS: KdfLimits = KdfLimits::INSECURE_FOR_TESTS;
const PARAMS: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};

fn pw(s: &str) -> Password {
    Password::new_unchecked(s)
}

fn key() -> UnlockedKey {
    UnlockedKey::generate()
}

/// Deterministic pseudo-random bytes (incompressible).
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        })
        .collect()
}

/// Builds a small tree with edge-case sizes around the 1 MiB chunk boundary.
fn sample_tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    let files = vec![
        ("docs/empty.txt".to_string(), Vec::new()),
        ("docs/one.txt".to_string(), b"x".to_vec()),
        (
            "docs/한글 메모.txt".to_string(),
            "안녕하세요, 보관함입니다.".repeat(100).into_bytes(),
        ),
        ("docs/sub/exact_chunk.bin".to_string(), noise(1 << 20, 1)),
        ("docs/sub/big.bin".to_string(), noise((5 << 19) + 123, 2)),
        (
            "docs/sub/text.log".to_string(),
            b"line of log text\n".repeat(200_000),
        ),
    ];
    for (p, data) in &files {
        let full = root.join(p);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, data).unwrap();
    }
    files
}

fn assert_tree(root: &Path, files: &[(String, Vec<u8>)]) {
    for (p, data) in files {
        let got = fs::read(root.join(p)).unwrap_or_else(|e| panic!("{p}: {e}"));
        assert!(got == *data, "content mismatch for {p}");
    }
}

#[test]
fn keyfile_round_trip_and_wrong_password() {
    let k = key();
    let bytes = keyfile::seal(&k, &pw("correct password!"), PARAMS, &LIMITS).unwrap();
    let opened = keyfile::open(&bytes, &pw("correct password!"), &LIMITS).unwrap();
    assert_eq!(opened.key_id(), k.key_id());
    assert!(matches!(
        keyfile::open(&bytes, &pw("wrong password!!"), &LIMITS),
        Err(Error::WrongPasswordOrCorrupt)
    ));
}

#[test]
fn keyfile_every_byte_is_protected() {
    let bytes = keyfile::seal(&key(), &pw("correct password!"), PARAMS, &LIMITS).unwrap();
    for i in 0..KEYFILE_LEN {
        let mut b = bytes;
        b[i] ^= 0x01;
        assert!(
            keyfile::open(&b, &pw("correct password!"), &LIMITS).is_err(),
            "flip at byte {i} was accepted"
        );
    }
}

#[test]
fn production_limits_reject_test_keys() {
    let bytes = keyfile::seal(&key(), &pw("correct password!"), PARAMS, &LIMITS).unwrap();
    assert!(matches!(
        keyfile::open(&bytes, &pw("correct password!"), &KdfLimits::PRODUCTION),
        Err(Error::KdfParamsOutOfRange)
    ));
    assert!(keyfile::seal(&key(), &pw("x"), PARAMS, &KdfLimits::PRODUCTION).is_err());
}

#[test]
fn round_trip_list_and_extract() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("src");
    let files = sample_tree(&src);
    let k = key();
    let vpath = dir.path().join("a.svault");

    let (v, skipped) = Vault::create(&vpath, &k, &[src.join("docs")]).unwrap();
    assert!(skipped.is_empty());
    assert_eq!(v.entries().len(), files.len());
    assert!(!vault_core::vault::EXTENSION.is_empty());
    assert!(!dir.path().join("a.svault.tmp").exists());

    // Names are not visible in the vault file.
    let raw = fs::read(&vpath).unwrap();
    assert!(!raw.windows(9).any(|w| w == b"empty.txt"));

    let v = Vault::open(&vpath, &k).unwrap();
    for (p, data) in &files {
        let e = v.entries().iter().find(|e| &e.path == p).expect(p);
        assert_eq!(e.size, data.len() as u64);
    }
    let out = dir.path().join("out");
    v.extract(&out, &[], false).unwrap();
    assert_tree(&out, &files);
}

#[test]
fn extract_single_entry_and_folder() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("src");
    let files = sample_tree(&src);
    let k = key();
    let vpath = dir.path().join("a.svault");
    Vault::create(&vpath, &k, &[src.join("docs")]).unwrap();
    let v = Vault::open(&vpath, &k).unwrap();

    let out = dir.path().join("one");
    let got = v.extract(&out, &["docs/one.txt".into()], false).unwrap();
    assert_eq!(got, vec!["docs/one.txt"]);
    assert!(!out.join("docs/empty.txt").exists());

    let out = dir.path().join("sub");
    let got = v.extract(&out, &["docs/sub".into()], false).unwrap();
    assert_eq!(got.len(), 3);
    assert_tree(&out, &files[3..]);

    assert!(matches!(
        v.extract(&out, &["nope".into()], false),
        Err(Error::EntryNotFound(_))
    ));
}

#[test]
fn extract_refuses_overwrite_unless_asked() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("f.txt");
    fs::write(&src, b"new").unwrap();
    let k = key();
    let vpath = dir.path().join("a.svault");
    Vault::create(&vpath, &k, &[src]).unwrap();
    let out = dir.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("f.txt"), b"old").unwrap();
    let v = Vault::open(&vpath, &k).unwrap();
    assert!(matches!(
        v.extract(&out, &[], false),
        Err(Error::DestinationExists(_))
    ));
    assert_eq!(fs::read(out.join("f.txt")).unwrap(), b"old");
    v.extract(&out, &[], true).unwrap();
    assert_eq!(fs::read(out.join("f.txt")).unwrap(), b"new");
}

#[test]
fn wrong_key_is_rejected() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("f.txt");
    fs::write(&f, b"secret").unwrap();
    let vpath = dir.path().join("a.svault");
    let k = key();
    Vault::create(&vpath, &k, &[f]).unwrap();
    assert!(matches!(
        Vault::open(&vpath, &key()),
        Err(Error::KeyMismatch { .. })
    ));
    assert_eq!(Vault::peek_key_id(&vpath).unwrap(), k.key_id());
}

#[test]
fn every_byte_flip_is_detected() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    fs::write(&a, b"alpha alpha alpha").unwrap();
    fs::write(&b, b"bravo").unwrap();
    let k = key();
    let vpath = dir.path().join("v.svault");
    Vault::create(&vpath, &k, &[a, b]).unwrap();
    let orig = fs::read(&vpath).unwrap();
    let bad = dir.path().join("bad.svault");
    let out = dir.path().join("out");

    for i in 0..orig.len() {
        let mut m = orig.clone();
        m[i] ^= 0x80;
        fs::write(&bad, &m).unwrap();
        let r = Vault::open(&bad, &k).and_then(|v| v.extract(&out, &[], true));
        assert!(
            r.is_err(),
            "flip at byte {i} of {} was not detected",
            orig.len()
        );
    }
}

#[test]
fn every_truncation_is_detected() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.bin");
    fs::write(&a, noise(3000, 7)).unwrap();
    let k = key();
    let vpath = dir.path().join("v.svault");
    Vault::create(&vpath, &k, &[a]).unwrap();
    let orig = fs::read(&vpath).unwrap();
    let bad = dir.path().join("bad.svault");
    let out = dir.path().join("out");
    for len in 0..orig.len() {
        fs::write(&bad, &orig[..len]).unwrap();
        let r = Vault::open(&bad, &k).and_then(|v| v.extract(&out, &[], true));
        assert!(r.is_err(), "truncation to {len} bytes was not detected");
    }
}

#[test]
fn swapped_entry_data_is_detected() {
    // Two equal-length entries: swap their ciphertext in place.
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    fs::write(&a, b"AAAAAAAAAAAAAAAA").unwrap();
    fs::write(&b, b"BBBBBBBBBBBBBBBB").unwrap();
    let k = key();
    let vpath = dir.path().join("v.svault");
    let (v, _) = Vault::create(&vpath, &k, &[a, b]).unwrap();
    let len = v.entries()[0].compressed_size as usize + 16;
    assert_eq!(v.entries()[1].compressed_size as usize + 16, len);
    let mut m = fs::read(&vpath).unwrap();
    let (o1, o2) = (vault::HEADER_LEN, vault::HEADER_LEN + len);
    let first = m[o1..o1 + len].to_vec();
    m.copy_within(o2..o2 + len, o1);
    m[o2..o2 + len].copy_from_slice(&first);
    fs::write(&vpath, &m).unwrap();
    let v = Vault::open(&vpath, &k).unwrap();
    assert!(v.extract(&dir.path().join("out"), &[], true).is_err());
}

#[test]
fn add_replace_remove() {
    let dir = TempDir::new().unwrap();
    let k = key();
    let vpath = dir.path().join("v.svault");
    let one = dir.path().join("one.txt");
    fs::write(&one, b"first").unwrap();
    Vault::create(&vpath, &k, std::slice::from_ref(&one)).unwrap();

    let two = dir.path().join("two.txt");
    fs::write(&two, b"second").unwrap();
    let mut v = Vault::open(&vpath, &k).unwrap();
    v.add(&[two], false).unwrap();
    assert_eq!(v.entries().len(), 2);

    // Clash (case-insensitive, as on Windows) without replace: error, nothing changes.
    let clash_dir = dir.path().join("clash");
    fs::create_dir(&clash_dir).unwrap();
    let upper = clash_dir.join("ONE.txt");
    fs::write(&upper, b"replaced").unwrap();
    assert!(matches!(
        v.add(std::slice::from_ref(&upper), false),
        Err(Error::EntryExists(_))
    ));
    assert_eq!(Vault::open(&vpath, &k).unwrap().entries().len(), 2);

    v.add(&[upper], true).unwrap();
    let v2 = Vault::open(&vpath, &k).unwrap();
    assert_eq!(v2.entries().len(), 2);
    let out = dir.path().join("out");
    v2.extract(&out, &[], false).unwrap();
    assert_eq!(fs::read(out.join("ONE.txt")).unwrap(), b"replaced");
    assert_eq!(fs::read(out.join("two.txt")).unwrap(), b"second");

    let mut v3 = Vault::open(&vpath, &k).unwrap();
    v3.remove(&["two.txt".into()]).unwrap();
    let v4 = Vault::open(&vpath, &k).unwrap();
    assert_eq!(v4.entries().len(), 1);
    assert_eq!(v4.entries()[0].path, "ONE.txt");
    assert!(!dir.path().join("v.svault.tmp").exists());
}

#[test]
fn password_change_keeps_vaults_working() {
    let dir = TempDir::new().unwrap();
    let kpath = dir.path().join("me.svkey");
    let k = keyfile::create_file(&kpath, &pw("first password!!"), PARAMS, &LIMITS).unwrap();
    let f = dir.path().join("f.txt");
    fs::write(&f, b"data").unwrap();
    let vpath = dir.path().join("v.svault");
    Vault::create(&vpath, &k, &[f]).unwrap();

    keyfile::change_password_file(
        &kpath,
        &pw("first password!!"),
        &pw("second password!"),
        PARAMS,
        &LIMITS,
    )
    .unwrap();
    assert!(keyfile::open_file(&kpath, &pw("first password!!"), &LIMITS).is_err());
    let k2 = keyfile::open_file(&kpath, &pw("second password!"), &LIMITS).unwrap();
    assert_eq!(Vault::open(&vpath, &k2).unwrap().entries().len(), 1);
}

#[test]
fn rekey_invalidates_old_key() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("src");
    let files = sample_tree(&src);
    let old = key();
    let vpath = dir.path().join("v.svault");
    Vault::create(&vpath, &old, &[src.join("docs")]).unwrap();
    let before = fs::read(&vpath).unwrap();

    let new = key();
    vault::rekey(&vpath, &old, &new).unwrap();
    let after = fs::read(&vpath).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(
        before[vault::HEADER_LEN..],
        after[vault::HEADER_LEN..],
        "rekey must only touch the header"
    );

    assert!(matches!(
        Vault::open(&vpath, &old),
        Err(Error::KeyMismatch { .. })
    ));
    let out = dir.path().join("out");
    Vault::open(&vpath, &new)
        .unwrap()
        .extract(&out, &[], false)
        .unwrap();
    assert_tree(&out, &files);
}

#[test]
fn create_refuses_to_overwrite() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("f.txt");
    fs::write(&f, b"x").unwrap();
    let vpath = dir.path().join("v.svault");
    fs::write(&vpath, b"precious").unwrap();
    assert!(matches!(
        Vault::create(&vpath, &key(), &[f]),
        Err(Error::DestinationExists(_))
    ));
    assert_eq!(fs::read(&vpath).unwrap(), b"precious");
}

#[cfg(unix)]
#[test]
fn symlinks_are_skipped_and_never_followed() {
    use std::os::unix::fs::symlink;
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("real.txt"), b"real").unwrap();
    let outside = dir.path().join("outside.txt");
    fs::write(&outside, b"must not be archived").unwrap();
    symlink(&outside, src.join("link.txt")).unwrap();

    let k = key();
    let vpath = dir.path().join("v.svault");
    let (v, skipped) = Vault::create(&vpath, &k, std::slice::from_ref(&src)).unwrap();
    assert_eq!(v.entries().len(), 1);
    assert_eq!(skipped, vec![src.join("link.txt")]);

    // A symlinked folder in the destination must not be followed on extract.
    let out = dir.path().join("out");
    fs::create_dir(&out).unwrap();
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    symlink(&elsewhere, out.join("src")).unwrap();
    assert!(matches!(
        v.extract(&out, &[], false),
        Err(Error::UnsafePath(_))
    ));
    assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
}

#[test]
fn format_time_is_sane() {
    assert_eq!(vault::format_time(0), "1970-01-01 00:00");
    assert_eq!(vault::format_time(1_798_675_200), "2026-12-31 00:00");
    let _ = PathBuf::new();
}
