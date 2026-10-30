//! The Korean interface. Kept in its own test binary because the language
//! is process-wide.

use std::time::{Duration, Instant};

use eframe::egui;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use vault_core::{KdfLimits, KdfParams};
use vault_gui::app::{App, Config, NoticeKind, Screen};
use vault_gui::i18n::{self, Lang};
use zeroize::Zeroizing;

const CFG: Config = Config {
    limits: KdfLimits::INSECURE_FOR_TESTS,
    params: KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    },
    save_settings: false,
};

fn wait(h: &mut Harness<'_, App>) {
    let start = Instant::now();
    h.step();
    while h.state().busy() {
        assert!(start.elapsed() < Duration::from_secs(60));
        std::thread::sleep(Duration::from_millis(10));
        h.step();
    }
    h.run_steps(2);
}

#[test]
fn switch_to_korean_and_create_a_key() {
    i18n::set_lang(Lang::En);
    let mut h = Harness::builder()
        .with_size(egui::vec2(1000.0, 900.0))
        .build_eframe(|cc| App::new(cc, CFG));
    // CI machines may lack Korean fonts; layout and labels are what we test.
    h.ctx
        .set_missing_glyph_policy(egui::epaint::text::MissingGlyphPolicy::Tofu);
    h.run_steps(2);

    // Choose Korean in the language menu.
    h.get_by_label("🌐 Language / 언어").click();
    h.run_steps(2);
    h.get_by_label("한국어").click();
    h.run_steps(3);
    assert_eq!(i18n::lang(), Lang::Ko);
    h.get_by_label("보관함 열기");
    h.get_by_label("키 파일 만들기").click();
    h.run_steps(2);
    assert_eq!(h.state().screen().name(), "new-key");

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("me.svkey");
    if let Screen::NewKey(s) = h.state_mut().screen_mut() {
        s.out = Some(out.clone());
        s.pw1 = Zeroizing::new("short".into());
        s.pw2 = Zeroizing::new("short".into());
    }
    h.run_steps(2);
    // Policy feedback is in Korean.
    h.get_by_label(
        "15자 이상이어야 합니다 (지금 5자). 관련 없는 단어 몇 개를 이어 쓰는 방법을 권합니다.",
    );

    if let Screen::NewKey(s) = h.state_mut().screen_mut() {
        s.pw1 = Zeroizing::new("maple river lantern quietly".into());
        s.pw2 = Zeroizing::new("maple river lantern quietly".into());
    }
    h.run_steps(2);
    h.get_by_label("키 파일 생성").click();
    wait(&mut h);
    assert_eq!(h.state().screen().name(), "backup");
    let n = h.state().notice().unwrap();
    assert_eq!(n.kind, NoticeKind::Success);
    assert!(n.text.contains("백업 2개"), "{}", n.text);
    h.get_by_label("2/3단계: 백업 사본 2개 만들기");

    // A copy that cannot be written leaves the slot empty.
    if let Screen::Backup(b) = h.state_mut().screen_mut() {
        b.write_copy(0, dir.path().join("a").join("me.svkey"));
        assert!(b.copies[0].is_none());
    }
    i18n::set_lang(Lang::En);
}
