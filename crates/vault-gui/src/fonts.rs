//! egui's bundled fonts have no Hangul or CJK glyphs. File names often do,
//! so on Windows we add the system's Malgun Gothic (Korean) and Microsoft
//! YaHei (Chinese/Japanese) as fallbacks when they are present. Nothing is
//! downloaded and nothing is required: missing fonts are simply skipped.

use eframe::egui::{self, FontData, FontFamily};
use eframe::epaint::text::{FontInsert, FontPriority, InsertFontFamily};

pub fn install(ctx: &egui::Context) {
    for path in candidates() {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        ctx.add_font(FontInsert::new(
            &name,
            FontData::from_owned(bytes),
            vec![
                InsertFontFamily {
                    family: FontFamily::Proportional,
                    priority: FontPriority::Lowest,
                },
                InsertFontFamily {
                    family: FontFamily::Monospace,
                    priority: FontPriority::Lowest,
                },
            ],
        ));
    }
}

fn candidates() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if cfg!(windows) {
        let windir = std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into());
        let fonts = std::path::PathBuf::from(windir).join("Fonts");
        for f in ["malgun.ttf", "msyh.ttc"] {
            out.push(fonts.join(f));
        }
    } else {
        for f in [
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
        ] {
            out.push(f.into());
        }
    }
    out
}
