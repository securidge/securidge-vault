//! Archive path rules (DESIGN.md §7.1).
//!
//! Paths inside a vault are relative, use `/` as separator, and are checked
//! both when stored and again when extracted, so a vault can never write
//! outside the folder the user chose.

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::{Error, Result};

pub const MAX_PATH_BYTES: usize = 4096;

const RESERVED: [&str; 32] = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
];

/// True for names that look like Windows 8.3 short names (`LONGNA~1`),
/// which can alias a different long name on the same disk.
fn looks_like_short_name(stem: &str) -> bool {
    match stem.rsplit_once('~') {
        Some((left, digits)) => {
            let n = left.chars().count();
            (1..=6).contains(&n) && !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

/// Validates a path as stored inside a vault.
pub fn validate(path: &str) -> Result<()> {
    let bad = |why: &str| Err(Error::UnsafePath(format!("{path:?}: {why}")));
    if path.is_empty() {
        return bad("empty");
    }
    if path.len() > MAX_PATH_BYTES {
        return bad("too long");
    }
    if path.starts_with('/') {
        return bad("absolute path");
    }
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return bad("empty, '.' or '..' component");
        }
        if comp
            .chars()
            .any(|c| c < ' ' || matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
        {
            return bad("character not allowed on Windows");
        }
        if comp.ends_with('.') || comp.ends_with(' ') {
            return bad("component ends with '.' or space");
        }
        let stem = comp
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end()
            .to_ascii_uppercase();
        if RESERVED.contains(&stem.as_str()) {
            return bad("reserved Windows device name");
        }
        if looks_like_short_name(&stem) {
            return bad("looks like a Windows short (8.3) name");
        }
    }
    Ok(())
}

/// Converts a relative filesystem path into an archive path.
pub fn from_relative(rel: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_str().ok_or_else(|| {
                Error::InvalidInput(format!("file name is not valid Unicode: {}", rel.display()))
            })?),
            _ => return Err(Error::UnsafePath(rel.display().to_string())),
        }
    }
    let joined = parts.join("/");
    validate(&joined)?;
    Ok(joined)
}

/// Case-folded key used to detect paths that would collide on Windows.
pub fn fold(path: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    path.nfc().collect::<String>().to_lowercase()
}

/// Resolves where `archive_path` should be written under `root`, creating
/// parent folders as needed and refusing to pass through symlinks or
/// junctions.
///
/// `root` must already exist and be canonical.
pub fn prepare_target(root: &Path, archive_path: &str) -> Result<PathBuf> {
    validate(archive_path)?;
    let comps: Vec<&str> = archive_path.split('/').collect();
    let (last, parents) = comps.split_last().expect("validated path is non-empty");
    let mut cur = root.to_path_buf();
    for comp in parents {
        cur.push(comp);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(Error::UnsafePath(format!(
                    "{} is a link; refusing to follow it",
                    cur.display()
                )))
            }
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                return Err(Error::UnsafePath(format!(
                    "{} exists and is not a folder",
                    cur.display()
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&cur)?,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(cur.join(last))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_normalises_unicode() {
        assert_eq!(fold("Cafe\u{0301}.txt"), fold("caf\u{00e9}.TXT"));
    }

    #[test]
    fn rejects_unsafe() {
        for p in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a/./b",
            "a//b",
            "a/",
            "C:x",
            "C:/x",
            "a\\b",
            "con",
            "CON.txt",
            "nul.tar.gz",
            "Com1",
            "a/lpt9.log",
            "trailing.",
            "trailing ",
            "a\u{0}b",
            "a:stream",
            "what?",
            "COM0",
            "lpt\u{b9}.txt",
            "conin$",
            "PROGRA~1",
            "docs/LONGNA~12.TXT",
        ] {
            assert!(validate(p).is_err(), "should reject {p:?}");
        }
    }

    #[test]
    fn accepts_normal() {
        for p in [
            "a.txt",
            "folder/sub/file.bin",
            "한글 파일.docx",
            "console.log",
            "com10.txt",
            ".hidden",
            "backup~old.txt",
            "verylongname~1.txt",
            "~1.txt",
        ] {
            assert!(validate(p).is_ok(), "should accept {p:?}");
        }
    }
}
