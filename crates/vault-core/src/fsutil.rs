use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// `<path>.tmp`, used for crash-safe replacement.
pub fn tmp_path(path: &Path) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Writes a new file, refusing to overwrite an existing one, and syncs it.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => Error::DestinationExists(path.to_path_buf()),
            _ => Error::Io(e),
        })?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Replaces `path` atomically: writes `<path>.tmp`, syncs, then renames.
/// A crash leaves either the old or the new file, never a mix.
pub fn replace_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_path(path);
    let result = (|| -> Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            fs::rename(&tmp, path)?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}
