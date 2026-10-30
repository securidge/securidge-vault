//! Developer preview: opens the window on a chosen screen with throwaway
//! data, for checking layout. Not part of the shipped app.
//!
//! cargo run -p vault-gui --example preview -- home|newkey|create|opened|backup|rekey [ko]

use eframe::egui;
use vault_core::{keyfile, KdfLimits, KdfParams, Password, Vault};
use vault_gui::app::{Backup, CreateVault, Opened, Screen};
use vault_gui::{App, Config};

const CFG: Config = Config {
    limits: KdfLimits::INSECURE_FOR_TESTS,
    params: KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    },
    save_settings: false,
};

fn main() -> eframe::Result {
    let which = std::env::args().nth(1).unwrap_or_else(|| "opened".into());
    if std::env::args().nth(2).as_deref() == Some("ko") {
        vault_gui::i18n::set_lang(vault_gui::i18n::Lang::Ko);
    }
    let dir = std::env::temp_dir().join(format!("svault-preview-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("photos/2026")).unwrap();
    for (n, s) in [
        ("photos/2026/trip.jpg", 3_400_000),
        ("photos/2026/여행.png", 820_000),
        ("photos/notes.txt", 1200),
    ] {
        std::fs::write(dir.join(n), vec![7u8; s]).unwrap();
    }
    let key = dir.join("me.svkey");
    let pw = Password::new_unchecked("maple river lantern quietly");
    let k = keyfile::create_file(&key, &pw, CFG.params, &CFG.limits).unwrap();
    let screen = match which.as_str() {
        "backup" => {
            let mut b = Backup::new(key.clone(), std::fs::read(&key).unwrap());
            std::fs::create_dir_all(dir.join("usb1")).unwrap();
            b.write_copy(0, dir.join("usb1/me.svkey"));
            Screen::Backup(b)
        }
        "home" => Screen::Home,
        "newkey" => Screen::NewKey(Default::default()),
        "rekey" => Screen::Rekey(Default::default()),
        "create" => {
            let mut c = CreateVault::default();
            c.inputs.push(dir.join("photos"));
            c.key.set(key.clone());
            c.out = Some(dir.join("photos.svault"));
            Screen::CreateVault(c)
        }
        _ => {
            let (v, _) =
                Vault::create(&dir.join("photos.svault"), &k, &[dir.join("photos")]).unwrap();
            let mut o = Opened::new(v);
            o.selected.insert("photos/notes.txt".into());
            Screen::Opened(o)
        }
    };
    let mut screen = Some(screen);
    eframe::run_native(
        "Securidge Vault (preview)",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([940.0, 680.0]),
            ..Default::default()
        },
        Box::new(move |cc| {
            let mut app = App::new(cc, CFG);
            *app.screen_mut() = screen.take().unwrap();
            Ok(Box::new(app))
        }),
    )
}
