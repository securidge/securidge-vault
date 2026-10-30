//! Crash-safe and race-resistant file helpers.
//!
//! Temporary files get a random name and are created with `create_new`
//! (which never follows an existing link), so a planted symlink cannot
//! redirect our writes and two processes never share a temp file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::{rng, Error, Result};

/// Creates a new, uniquely named temp file next to `path`.
pub fn create_tmp(path: &Path) -> Result<(PathBuf, File)> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    for _ in 0..8 {
        let suffix: [u8; 8] = rng::array();
        let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
        // Short fixed-length name: a long target name must not push the
        // temp name over the file system's 255-character limit.
        let tmp = dir.join(format!(".svtmp-{hex}"));
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::Io(io::Error::other(
        "could not create a temporary file",
    )))
}

/// Creates an empty placeholder at `path`, failing if anything (including a
/// link) already exists there. Renaming a temp file over the placeholder
/// later gives "create, but never overwrite" semantics without races.
pub fn reserve_new(path: &Path) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map(drop)
        .map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => Error::DestinationExists(path.to_path_buf()),
            _ => Error::Io(e),
        })
}

/// Removes a placeholder created by [`reserve_new`] if it is still an empty
/// regular file (so we never delete something another process put there).
pub fn remove_placeholder(path: &Path) {
    if let Ok(m) = fs::symlink_metadata(path) {
        if m.is_file() && m.len() == 0 {
            let _ = fs::remove_file(path);
        }
    }
}

/// Renames `tmp` over `target` and makes the rename durable.
pub fn commit(tmp: &Path, target: &Path) -> Result<()> {
    fs::rename(tmp, target)?;
    sync_parent(target);
    Ok(())
}

/// On Unix, a rename is only durable once the folder is synced.
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Writes a new file, refusing to overwrite an existing one, and syncs it.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    reserve_new(path)?;
    if let Err(e) = replace_atomic(path, bytes) {
        remove_placeholder(path);
        return Err(e);
    }
    Ok(())
}

/// Replaces `path` atomically: writes a temp file, syncs, then renames.
/// A crash leaves either the old or the new file, never a mix.
pub fn replace_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let (tmp, mut f) = create_tmp(path)?;
    let result = (|| -> Result<()> {
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    })();
    drop(f);
    match result.and_then(|()| commit(&tmp, path)) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Opens an input file without following a final symlink or junction, and
/// confirms through the open handle that it is a regular file.
pub fn open_regular_nofollow(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let f = opts.open(path).map_err(|e| {
        if e.raw_os_error() == loop_errno() {
            Error::UnsafePath(format!("{} is a link", path.display()))
        } else {
            Error::Io(e)
        }
    })?;
    if !f.metadata()?.file_type().is_file() {
        return Err(Error::UnsafePath(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(f)
}

fn loop_errno() -> Option<i32> {
    #[cfg(unix)]
    return Some(libc::ELOOP);
    #[cfg(not(unix))]
    return None;
}
