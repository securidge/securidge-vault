//! Storage warnings for key files (DESIGN.md §5.2). Warnings inform; they
//! never block. Shared by the CLI and the GUI so both say the same thing.

use std::path::{Component, Path, PathBuf};

/// One storage warning about where a key file lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyWarning {
    /// The key file is in the same folder as the vault.
    SameFolderAsVault,
    /// The key file is in a folder synced by a cloud service.
    CloudSynced,
    /// The key file is on the Windows system drive.
    SystemDrive,
}

impl KeyWarning {
    pub fn message(self) -> &'static str {
        match self {
            KeyWarning::SameFolderAsVault => {
                "The key file is in the same folder as the vault. Anyone who copies the folder gets both."
            }
            KeyWarning::CloudSynced => {
                "The key file is in a cloud-synced folder. A copy may be stored online."
            }
            KeyWarning::SystemDrive => {
                "The key file is on the system drive. Malware that steals files can find it; prefer a USB drive."
            }
        }
    }
}

/// Best-effort absolute form of `p` (the file itself need not exist).
pub fn absolute(p: &Path) -> PathBuf {
    let parent = p
        .parent()
        .filter(|x| !x.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    parent
        .canonicalize()
        .map(|d| d.join(p.file_name().unwrap_or_default()))
        .or_else(|_| std::path::absolute(p))
        .unwrap_or_else(|_| p.to_path_buf())
}

/// Warnings for a key file at `key`, optionally used with the vault at `vault`.
pub fn key_location(key: &Path, vault: Option<&Path>) -> Vec<KeyWarning> {
    let mut out = Vec::new();
    let key_abs = absolute(key);
    let lower = key_abs.to_string_lossy().to_lowercase();

    if let Some(v) = vault {
        if absolute(v).parent() == key_abs.parent() {
            out.push(KeyWarning::SameFolderAsVault);
        }
    }
    const CLOUD: [&str; 5] = [
        "onedrive",
        "dropbox",
        "google drive",
        "googledrive",
        "icloud",
    ];
    if CLOUD.iter().any(|s| lower.contains(s)) {
        out.push(KeyWarning::CloudSynced);
    }
    if cfg!(windows) {
        let sys = std::env::var("SystemDrive")
            .unwrap_or_else(|_| "C:".into())
            .to_lowercase();
        let path = lower.trim_start_matches(r"\\?\");
        if path.starts_with(&sys) {
            out.push(KeyWarning::SystemDrive);
        }
    }
    out
}

/// The volume a path is on: the drive or UNC share on Windows, `None`
/// where that cannot be told from the path (Unix). Used to suggest that
/// backups go to different drives.
pub fn volume(p: &Path) -> Option<String> {
    match absolute(p).components().next() {
        Some(Component::Prefix(pre)) => Some(pre.as_os_str().to_string_lossy().to_lowercase()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_folder_and_cloud() {
        let d = std::env::temp_dir();
        let w = key_location(&d.join("k.svkey"), Some(&d.join("v.svault")));
        assert!(w.contains(&KeyWarning::SameFolderAsVault));
        let w = key_location(&d.join("OneDrive").join("k.svkey"), None);
        assert!(w.contains(&KeyWarning::CloudSynced));
        let w = key_location(&d.join("a").join("k.svkey"), Some(&d.join("v.svault")));
        assert!(!w.contains(&KeyWarning::SameFolderAsVault));
    }
}
