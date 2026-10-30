// No console window behind the app in release builds on Windows.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use eframe::egui;
use vault_gui::{App, Config};

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Securidge Vault")
            .with_inner_size([940.0, 680.0])
            .with_min_inner_size([640.0, 480.0])
            .with_drag_and_drop(true),
        // Portable app: do not write window state anywhere.
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        "Securidge Vault",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc, Config::PRODUCTION)))),
    )
}
