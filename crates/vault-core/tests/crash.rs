//! Crash tests (DESIGN.md §10): kill a process in the middle of changing a
//! vault or key file and check that what is left always opens and is either
//! the complete old state or the complete new state.
//!
//! The parent re-runs this test binary as a child (`crash_child`, ignored in
//! normal runs) that performs one operation; the parent kills it after a
//! delay spread across the operation's measured duration. On Windows the
//! kill is TerminateProcess, on Unix SIGKILL: no destructors, no cleanup.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vault_core::{keyfile, vault, KdfLimits, KdfParams, Password, UnlockedKey, Vault};

const LIMITS: KdfLimits = KdfLimits::INSECURE_FOR_TESTS;
const PARAMS: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};
const PW: &str = "old password for crash tests";
const PW2: &str = "new password for crash tests";

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

fn open_key(path: &Path, pw: &str) -> Option<UnlockedKey> {
    keyfile::open_file(path, &Password::new_unchecked(pw), &LIMITS).ok()
}

/// The operations a child performs. Each is one library call.
fn run_op(op: &str, d: &Path) {
    let key = open_key(&d.join("old.svkey"), PW).expect("old key");
    let v = d.join("v.svault");
    match op {
        "add" => {
            let mut vt = Vault::open(&v, &key).unwrap();
            vt.add(&[d.join("in").join("new.bin")], false).unwrap();
        }
        "replace" => {
            let mut vt = Vault::open(&v, &key).unwrap();
            vt.add(&[d.join("in2").join("a.bin")], true).unwrap();
        }
        "remove" => {
            let mut vt = Vault::open(&v, &key).unwrap();
            vt.remove(&["a.bin".to_string()]).unwrap();
        }
        "rekey" => {
            let new = open_key(&d.join("new.svkey"), PW).expect("new key");
            vault::rekey(&v, &key, &new).unwrap();
        }
        "passwd" => {
            keyfile::change_password_file(
                &d.join("old.svkey"),
                &Password::new_unchecked(PW),
                &Password::new_unchecked(PW2),
                PARAMS,
                &LIMITS,
            )
            .unwrap();
        }
        other => panic!("unknown op {other}"),
    }
}

#[test]
#[ignore = "child process for crash tests"]
fn crash_child() {
    let (Ok(op), Ok(dir)) = (std::env::var("SV_CRASH_OP"), std::env::var("SV_CRASH_DIR")) else {
        return;
    };
    let dir = PathBuf::from(dir);
    fs::write(dir.join("started"), b"").unwrap();
    run_op(&op, &dir);
    fs::write(dir.join("finished"), b"").unwrap();
}

/// A fresh scenario: a vault with `a.bin` (big) and `b.txt`, the old key,
/// a second key for rekey, and the inputs the operations use.
fn setup(root: &Path) -> PathBuf {
    let d = root.to_path_buf();
    fs::create_dir_all(d.join("src")).unwrap();
    fs::create_dir_all(d.join("in")).unwrap();
    fs::create_dir_all(d.join("in2")).unwrap();
    fs::write(d.join("src").join("a.bin"), noise(3 << 20, 1)).unwrap();
    fs::write(d.join("src").join("b.txt"), b"keep me\n").unwrap();
    fs::write(d.join("in").join("new.bin"), noise(3 << 20, 2)).unwrap();
    fs::write(d.join("in2").join("a.bin"), noise(2 << 20, 3)).unwrap();
    let old = keyfile::create_file(
        &d.join("old.svkey"),
        &Password::new_unchecked(PW),
        PARAMS,
        &LIMITS,
    )
    .unwrap();
    keyfile::create_file(
        &d.join("new.svkey"),
        &Password::new_unchecked(PW),
        PARAMS,
        &LIMITS,
    )
    .unwrap();
    Vault::create(
        &d.join("v.svault"),
        &old,
        &[d.join("src").join("a.bin"), d.join("src").join("b.txt")],
    )
    .unwrap();
    d
}

/// Opens whatever is on disk after the crash and returns its file list,
/// after checking every entry decrypts and authenticates.
fn surviving_state(d: &Path) -> BTreeSet<String> {
    let v = d.join("v.svault");
    let id = Vault::peek_key_id(&v).expect("vault header must be intact");
    let mut key = None;
    for (k, pw) in [("old.svkey", PW), ("old.svkey", PW2), ("new.svkey", PW)] {
        if let Some(u) = open_key(&d.join(k), pw) {
            if u.key_id() == id {
                key = Some(u);
                break;
            }
        }
    }
    let key = key.expect("some key must open the vault");
    let vt = Vault::open(&v, &key).expect("vault must open after a crash");
    let out = d.join(format!("x{}", rand_suffix()));
    vt.extract(&out, &[], false)
        .expect("every entry must authenticate");
    fs::remove_dir_all(&out).unwrap();
    vt.entries()
        .iter()
        .map(|e| format!("{}:{}", e.path, e.size))
        .collect()
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// Starts a child performing `op`; kills it `delay` after it starts unless
/// `delay` is `None`. Returns (finished normally, time from start to exit).
fn crash_run(op: &str, delay: Option<Duration>, d: &Path) -> (bool, Duration) {
    let _ = fs::remove_file(d.join("started"));
    let _ = fs::remove_file(d.join("finished"));
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "crash_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SV_CRASH_OP", op)
        .env("SV_CRASH_DIR", d)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let t0 = Instant::now();
    while !d.join("started").exists() {
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "child did not start"
        );
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let started = Instant::now();
    if let Some(delay) = delay {
        std::thread::sleep(delay);
        let _ = child.kill();
    }
    let _ = child.wait();
    (d.join("finished").exists(), started.elapsed())
}

fn check_op(op: &str, before: &BTreeSet<String>, after: &BTreeSet<String>) {
    let base = tempfile::tempdir().unwrap();
    // How long does the operation take in a child? Spread kills across it.
    let probe = setup(&base.path().join("probe"));
    let (done, full) = crash_run(op, None, &probe);
    assert!(done, "{op} must succeed when not interrupted");
    let full = full.max(Duration::from_millis(20));

    let mut saw_old = false;
    let mut saw_new = false;
    let mut interrupted = 0;
    for i in 0..12u32 {
        let d = setup(&base.path().join(format!("run{i}")));
        let delay = full * i / 10;
        let (finished, _) = crash_run(op, Some(delay), &d);
        if !finished {
            interrupted += 1;
        }
        if op == "passwd" {
            let old = open_key(&d.join("old.svkey"), PW).is_some();
            let new = open_key(&d.join("old.svkey"), PW2).is_some();
            assert!(
                old ^ new,
                "{op} run {i}: key file must open with exactly one password"
            );
            saw_old |= old;
            saw_new |= new;
            continue;
        }
        let state = surviving_state(&d);
        if &state == before {
            saw_old = true;
        } else if &state == after {
            saw_new = true;
        } else {
            panic!("{op} run {i}: unexpected state {state:?}");
        }
        // The vault stays usable: the dead writer's lock is gone.
        let id = Vault::peek_key_id(&d.join("v.svault")).unwrap();
        let key = [("old.svkey", PW), ("new.svkey", PW)]
            .iter()
            .filter_map(|(k, p)| open_key(&d.join(k), p))
            .find(|k| k.key_id() == id)
            .unwrap();
        let mut vt = Vault::open(&d.join("v.svault"), &key).unwrap();
        fs::write(d.join("later.txt"), b"later").unwrap();
        vt.add(&[d.join("later.txt")], false)
            .expect("vault must accept changes after a crash");
    }
    eprintln!("{op}: {interrupted}/12 interrupted, saw old={saw_old} new={saw_new}");
    assert!(saw_old || saw_new);
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn killed_mid_add_leaves_old_or_new_vault() {
    let before = set(&["a.bin:3145728", "b.txt:8"]);
    check_op(
        "add",
        &before,
        &set(&["a.bin:3145728", "b.txt:8", "new.bin:3145728"]),
    );
}

#[test]
fn killed_mid_replace_leaves_old_or_new_vault() {
    let before = set(&["a.bin:3145728", "b.txt:8"]);
    check_op("replace", &before, &set(&["a.bin:2097152", "b.txt:8"]));
}

#[test]
fn killed_mid_remove_leaves_old_or_new_vault() {
    let before = set(&["a.bin:3145728", "b.txt:8"]);
    check_op("remove", &before, &set(&["b.txt:8"]));
}

#[test]
fn killed_mid_rekey_leaves_old_or_new_vault() {
    let s = set(&["a.bin:3145728", "b.txt:8"]);
    check_op("rekey", &s, &s);
}

#[test]
fn killed_mid_password_change_leaves_a_working_key_file() {
    check_op("passwd", &BTreeSet::new(), &BTreeSet::new());
}
