//! Portable settings (DESIGN.md §8.3): `settings.toml` next to the
//! executable, holding only the interface language. Never contains secrets.
//! If the folder is read-only the setting simply is not remembered.

use std::path::PathBuf;

use crate::i18n::Lang;

fn path() -> Option<PathBuf> {
    Some(
        std::env::current_exe()
            .ok()?
            .parent()?
            .join("settings.toml"),
    )
}

/// The saved language, if any.
pub fn load_lang() -> Option<Lang> {
    let text = std::fs::read_to_string(path()?).ok()?;
    text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == "language")
            .then(|| Lang::from_code(v.trim().trim_matches('"')))
            .flatten()
    })
}

/// Remembers the language. Best effort.
pub fn save_lang(l: Lang) {
    if let Some(p) = path() {
        let _ = std::fs::write(
            p,
            format!(
                "# Securidge Vault settings (no secrets are stored here)\nlanguage = \"{}\"\n",
                l.code()
            ),
        );
    }
}
