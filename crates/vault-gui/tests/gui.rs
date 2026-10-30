//! Headless GUI tests: drive the real window logic with `egui_kittest`
//! (no screen or GPU needed). File dialogs cannot be driven, so tests fill
//! paths into the screen state directly and click the buttons.

use std::path::Path;
use std::time::{Duration, Instant};

use eframe::egui;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use vault_core::{KdfLimits, KdfParams};
use vault_gui::app::{App, Backup, Config, NoticeKind, Screen};
use zeroize::Zeroizing;

const CFG: Config = Config {
    limits: KdfLimits::INSECURE_FOR_TESTS,
    params: KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    },
};
const PW: &str = "maple river lantern quietly";

fn harness() -> Harness<'static, App> {
    Harness::builder()
        .with_size(egui::vec2(1000.0, 900.0))
        .build_eframe(|cc| App::new(cc, CFG))
}

/// Steps the UI until the background job has finished and been applied.
fn wait(h: &mut Harness<'_, App>) {
    let start = Instant::now();
    h.step();
    while h.state().busy() {
        assert!(start.elapsed() < Duration::from_secs(60), "job timed out");
        std::thread::sleep(Duration::from_millis(10));
        h.step();
    }
    h.run_steps(2);
}

fn notice(h: &Harness<'_, App>) -> (NoticeKind, String) {
    let n = h.state().notice().expect("a notice");
    (n.kind, n.text.clone())
}

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn screen(h: &Harness<'_, App>) -> &'static str {
    h.state().screen().name()
}

/// Creates a key file through the GUI and finishes the backup flow.
fn make_key(h: &mut Harness<'_, App>, dir: &Path) -> std::path::PathBuf {
    h.get_by_label("Create a key file").click();
    h.run_steps(2);
    assert_eq!(screen(h), "new-key");
    let out = dir.join("k").join("me.svkey");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    if let Screen::NewKey(s) = h.state_mut().screen_mut() {
        s.out = Some(out.clone());
        s.pw1 = pw(PW);
        s.pw2 = pw(PW);
    }
    h.run_steps(2);
    h.get_by_label("Create key file").click();
    wait(h);
    assert_eq!(screen(h), "backup", "{:?}", h.state().notice());

    // Backups: same folder as the original is refused.
    let b1 = dir.join("usb1").join("me.svkey");
    let b2 = dir.join("usb2").join("me.svkey");
    std::fs::create_dir_all(b1.parent().unwrap()).unwrap();
    std::fs::create_dir_all(b2.parent().unwrap()).unwrap();
    if let Screen::Backup(b) = h.state_mut().screen_mut() {
        b.write_copy(0, dir.join("k").join("copy.svkey"));
        assert!(b.copies[0].is_none(), "same folder must be refused");
        b.write_copy(0, b1.clone());
        b.write_copy(1, b1.parent().unwrap().join("again.svkey"));
        assert!(
            b.copies[1].is_none(),
            "two backups in one folder must be refused"
        );
        b.write_copy(1, b2.clone());
        assert!(b.copies.iter().all(Option::is_some));
        b.pw = pw("wrong password entirely");
    }
    h.run_steps(2);
    h.get_by_label("Verify all copies").click();
    wait(h);
    assert_eq!(notice(h).0, NoticeKind::Error);

    if let Screen::Backup(b) = h.state_mut().screen_mut() {
        b.pw = pw(PW);
    }
    h.run_steps(2);
    h.get_by_label("Verify all copies").click();
    wait(h);
    assert_eq!(notice(h).0, NoticeKind::Success, "{:?}", notice(h));
    h.get_by_label("Done").click();
    h.run_steps(2);
    assert_eq!(screen(h), "home");
    assert_eq!(std::fs::read(&b1).unwrap(), std::fs::read(&out).unwrap());
    out
}

#[test]
fn key_backup_vault_roundtrip_and_rekey() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = harness();
    h.run_steps(2);
    let key = make_key(&mut h, dir.path());

    // Create a vault.
    let src = dir.path().join("docs");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("sub").join("b.txt"), b"beta").unwrap();
    let vpath = dir.path().join("v").join("docs.svault");
    std::fs::create_dir_all(vpath.parent().unwrap()).unwrap();

    h.get_by_label("Create a vault").click();
    h.run_steps(2);
    if let Screen::CreateVault(s) = h.state_mut().screen_mut() {
        s.inputs.push(src.clone());
        s.out = Some(vpath.clone());
        s.key.set(key.clone());
        s.pw = pw(PW);
    }
    h.run_steps(2);
    h.get_by_label("Create vault").click();
    wait(&mut h);
    assert_eq!(screen(&h), "opened", "{:?}", h.state().notice());
    if let Screen::Opened(o) = h.state().screen() {
        let names: Vec<_> = o
            .vault()
            .unwrap()
            .entries()
            .iter()
            .map(|e| e.path.clone())
            .collect();
        assert_eq!(names, ["docs/a.txt", "docs/sub/b.txt"]);
    }
    h.get_by_label("🔒 Lock").click();
    h.run_steps(2);
    assert_eq!(screen(&h), "home");

    // Wrong password fails cleanly; right one opens.
    h.get_by_label("Open a vault").click();
    h.run_steps(2);
    if let Screen::OpenVault(s) = h.state_mut().screen_mut() {
        s.vault.set(vpath.clone());
        s.key.set(key.clone());
        s.pw = pw("not the right password");
    }
    h.run_steps(2);
    h.get_by_label("Open").click();
    wait(&mut h);
    assert_eq!(screen(&h), "open-vault");
    assert_eq!(notice(&h).0, NoticeKind::Error);
    if let Screen::OpenVault(s) = h.state_mut().screen_mut() {
        s.pw = pw(PW);
    }
    h.run_steps(2);
    h.get_by_label("Open").click();
    wait(&mut h);
    assert_eq!(screen(&h), "opened", "{:?}", h.state().notice());

    // Remove one entry through the confirmation dialog.
    if let Screen::Opened(o) = h.state_mut().screen_mut() {
        o.selected.insert("docs/a.txt".into());
    }
    h.run_steps(2);
    h.get_by_label("Remove selected (1)").click();
    h.run_steps(2);
    h.get_by_label("Remove").click();
    wait(&mut h);
    if let Screen::Opened(o) = h.state().screen() {
        assert_eq!(o.vault().unwrap().entries().len(), 1);
        assert!(o.selected.is_empty());
    }
    h.get_by_label("🔒 Lock").click();
    h.run_steps(2);

    // Rekey to a new key file, which leads straight into the backup flow.
    let new_key = dir.path().join("k2").join("new.svkey");
    std::fs::create_dir_all(new_key.parent().unwrap()).unwrap();
    h.get_by_label("Rekey vaults").click();
    h.run_steps(2);
    if let Screen::Rekey(s) = h.state_mut().screen_mut() {
        s.key.set(key.clone());
        s.pw = pw(PW);
        s.add_vault(vpath.clone());
        s.new_key = Some(new_key.clone());
        s.pw1 = pw("another long passphrase here");
        s.pw2 = pw("another long passphrase here");
    }
    h.run_steps(2);
    h.get_by_label("Rekey").click();
    wait(&mut h);
    assert_eq!(screen(&h), "backup", "{:?}", h.state().notice());
    assert_eq!(notice(&h).0, NoticeKind::Success);

    // The old key no longer opens the vault; the new one does.
    let lim = CFG.limits;
    let old = vault_core::keyfile::open_file(&key, &vault_core::Password::new_unchecked(PW), &lim)
        .unwrap();
    assert!(vault_core::Vault::open(&vpath, &old).is_err());
    let new = vault_core::keyfile::open_file(
        &new_key,
        &vault_core::Password::new_unchecked("another long passphrase here"),
        &lim,
    )
    .unwrap();
    assert_eq!(
        vault_core::Vault::open(&vpath, &new)
            .unwrap()
            .entries()
            .len(),
        1
    );
}

#[test]
fn backup_cannot_be_skipped_without_accepting_the_risk() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = harness();
    h.run_steps(2);
    let key = dir.path().join("only.svkey");
    vault_core::keyfile::create_file(
        &key,
        &vault_core::Password::new_unchecked(PW),
        CFG.params,
        &CFG.limits,
    )
    .unwrap();
    let bytes = std::fs::read(&key).unwrap();
    *h.state_mut().screen_mut() = Screen::Backup(Backup::new(key, bytes));
    h.run_steps(2);

    h.get_by_label("Skip backups").click();
    h.run_steps(2);
    assert_eq!(
        screen(&h),
        "backup",
        "skip must be disabled until the risk is accepted"
    );

    h.get_by_label(
        "I accept that if I lose this key file or forget the password, my data is gone.",
    )
    .click();
    h.run_steps(2);
    h.get_by_label("Skip backups").click();
    h.run_steps(2);
    assert_eq!(screen(&h), "home");
    assert_eq!(notice(&h).0, NoticeKind::Info);
}

#[test]
fn weak_password_keeps_create_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = harness();
    h.run_steps(2);
    h.get_by_label("Create a key file").click();
    h.run_steps(2);
    let out = dir.path().join("weak.svkey");
    if let Screen::NewKey(s) = h.state_mut().screen_mut() {
        s.out = Some(out.clone());
        s.pw1 = pw("short");
        s.pw2 = pw("short");
    }
    h.run_steps(2);
    h.get_by_label("Create key file").click();
    h.run_steps(3);
    assert!(!h.state().busy());
    assert!(!out.exists());
    assert_eq!(screen(&h), "new-key");
}

#[test]
fn change_password_then_verify() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.svkey");
    vault_core::keyfile::create_file(
        &key,
        &vault_core::Password::new_unchecked(PW),
        CFG.params,
        &CFG.limits,
    )
    .unwrap();
    let new_pw = "seven blue harbors at dawn";
    let mut h = harness();
    h.run_steps(2);

    h.get_by_label("Change password").click();
    h.run_steps(2);
    if let Screen::Passwd(s) = h.state_mut().screen_mut() {
        s.key.set(key.clone());
        s.old = pw(PW);
        s.pw1 = pw(new_pw);
        s.pw2 = pw(new_pw);
    }
    h.run_steps(2);
    h.get_by_label("Save new password").click();
    wait(&mut h);
    // Straight into making fresh backups.
    assert_eq!(screen(&h), "backup", "{:?}", h.state().notice());

    // Home is not offered until backups are done or the risk is accepted.
    assert!(h.query_by_label("⬅ Home").is_none());
    assert!(h.state().backup_pending());
    h.get_by_label(
        "I accept that if I lose this key file or forget the password, my data is gone.",
    )
    .click();
    h.run_steps(2);
    h.get_by_label("Skip backups").click();
    h.run_steps(2);
    assert_eq!(screen(&h), "home");
    h.get_by_label("Verify a backup").click();
    h.run_steps(2);
    if let Screen::Verify(s) = h.state_mut().screen_mut() {
        s.key.set(key.clone());
        s.pw = pw(PW);
    }
    h.run_steps(2);
    h.get_by_label("Verify").click();
    wait(&mut h);
    assert_eq!(notice(&h).0, NoticeKind::Error, "old password must fail");
    if let Screen::Verify(s) = h.state_mut().screen_mut() {
        s.pw = pw(new_pw);
    }
    h.run_steps(2);
    h.get_by_label("Verify").click();
    wait(&mut h);
    assert_eq!(notice(&h).0, NoticeKind::Success, "{:?}", notice(&h));
}
