//! Extraction edge cases found in review: long names, Mark-of-the-Web,
//! network destinations.

use std::fs;
use std::path::{Path, PathBuf};

use vault_core::{keyfile, KdfLimits, KdfParams, Password, UnlockedKey, Vault};

const LIMITS: KdfLimits = KdfLimits::INSECURE_FOR_TESTS;
const PARAMS: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};

fn key(dir: &Path) -> UnlockedKey {
    keyfile::create_file(
        &dir.join("k.svkey"),
        &Password::new_unchecked("edge case password"),
        PARAMS,
        &LIMITS,
    )
    .unwrap()
}

fn make_vault(dir: &Path, name: &str) -> (Vault, PathBuf) {
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let f = src.join(name);
    fs::write(&f, b"contents").unwrap();
    let k = key(dir);
    let v = dir.join("v.svault");
    let (vault, _) = Vault::create(&v, &k, &[f]).unwrap();
    (vault, v)
}

/// A 250-character name is valid on every target file system; the temp
/// file used while extracting must not push it over the limit.
#[test]
fn long_entry_name_extracts_and_leaves_nothing_behind() {
    let d = tempfile::tempdir().unwrap();
    let name = format!("{}.txt", "a".repeat(246));
    assert_eq!(name.len(), 250);
    let (vault, _) = make_vault(d.path(), &name);
    let out = d.path().join("out");
    vault.extract(&out, &[], false).unwrap();
    assert_eq!(fs::read(out.join(&name)).unwrap(), b"contents");
    let left: Vec<_> = fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        left.len(),
        1,
        "no temp files or placeholders left: {left:?}"
    );
    // Extracting again without overwrite reports the existing file...
    assert!(vault.extract(&out, &[], false).is_err());
    // ...and with overwrite replaces it.
    vault.extract(&out, &[], true).unwrap();
}

#[cfg(windows)]
#[test]
fn mark_of_the_web_is_inherited() {
    let d = tempfile::tempdir().unwrap();
    let (vault, vpath) = make_vault(d.path(), "doc.txt");
    let zone = b"[ZoneTransfer]\r\nZoneId=3\r\n";
    let mut ads = vpath.as_os_str().to_owned();
    ads.push(":Zone.Identifier");
    fs::write(PathBuf::from(ads), zone).unwrap();
    // Reopen so nothing is cached from before the stream existed.
    drop(vault);
    let k = keyfile::open_file(
        &d.path().join("k.svkey"),
        &Password::new_unchecked("edge case password"),
        &LIMITS,
    )
    .unwrap();
    let vault = Vault::open(&vpath, &k).unwrap();
    let out = d.path().join("out");
    vault.extract(&out, &[], false).unwrap();
    let mut got = out.join("doc.txt").into_os_string();
    got.push(":Zone.Identifier");
    assert_eq!(fs::read(PathBuf::from(got)).unwrap(), zone);
}

/// Extracting to a network path (here the local admin share) must work.
/// Skipped when the share is not reachable (non-admin machines).
#[cfg(windows)]
#[test]
fn extract_to_unc_path() {
    let d = tempfile::tempdir().unwrap();
    let (vault, _) = make_vault(d.path(), "net.txt");
    let local = d.path().join("unc-out");
    fs::create_dir_all(&local).unwrap();
    let s = local.canonicalize().unwrap().to_string_lossy().into_owned();
    let s = s.trim_start_matches(r"\\?\");
    let (drive, rest) = s.split_at(2); // "C:" + "\..."
    let unc = PathBuf::from(format!(r"\\localhost\{}${}", &drive[..1], rest));
    if fs::metadata(&unc).is_err() {
        eprintln!("skipped: {} not reachable", unc.display());
        return;
    }
    vault.extract(&unc.join("sub"), &[], false).unwrap();
    assert_eq!(
        fs::read(local.join("sub").join("net.txt")).unwrap(),
        b"contents"
    );
}
