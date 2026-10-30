//! Extraction target folder, accessed only through directory handles
//! (DESIGN.md §7.1).
//!
//! Every file operation during extraction is relative to an open handle of
//! the destination folder (via `cap-std`), never a path string resolved from
//! the root again. `cap-std` refuses any lookup that would leave the folder,
//! including through a symlink or junction that is swapped in while we work,
//! so a local attacker racing folder creation can no longer redirect a write
//! outside the destination. On top of that, existing links in parent
//! components are refused outright, so archives never write through links.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};

use crate::{pathsafe, rng, Error, Result};

pub struct DestDir {
    root: Dir,
    root_path: PathBuf,
}

/// The folder an entry goes into, plus the entry's file name.
pub struct Slot {
    pub dir: Dir,
    pub name: String,
    /// For messages only; never used to open anything.
    pub display: PathBuf,
}

fn map_escape(e: io::Error, what: &Path) -> Error {
    // cap-std reports an attempted escape as PermissionDenied.
    if e.kind() == io::ErrorKind::PermissionDenied {
        Error::UnsafePath(format!(
            "{} leads outside the destination folder",
            what.display()
        ))
    } else {
        Error::Io(e)
    }
}

impl DestDir {
    /// Opens (creating if needed) the destination folder.
    pub fn open(dest: &Path) -> Result<DestDir> {
        std::fs::create_dir_all(dest)?;
        Ok(DestDir {
            root: Dir::open_ambient_dir(dest, ambient_authority())?,
            root_path: dest.to_path_buf(),
        })
    }

    /// Opens the parent folder of `archive_path`, creating missing folders.
    /// Refuses existing links and anything that is not a folder.
    pub fn slot(&self, archive_path: &str) -> Result<Slot> {
        pathsafe::validate(archive_path)?;
        let comps: Vec<&str> = archive_path.split('/').collect();
        let (last, parents) = comps.split_last().expect("validated path is non-empty");
        let mut dir = self.root.try_clone()?;
        let mut shown = self.root_path.clone();
        for comp in parents {
            shown.push(comp);
            match dir.symlink_metadata(comp) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(Error::UnsafePath(format!(
                        "{} is a link; refusing to follow it",
                        shown.display()
                    )))
                }
                Ok(m) if m.is_dir() => {}
                Ok(_) => {
                    return Err(Error::UnsafePath(format!(
                        "{} exists and is not a folder",
                        shown.display()
                    )))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => match dir.create_dir(comp) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(map_escape(e, &shown)),
                },
                Err(e) => return Err(map_escape(e, &shown)),
            }
            // Even if `comp` was swapped for a link since the check above,
            // cap-std will not let the open leave the destination.
            dir = dir.open_dir(comp).map_err(|e| map_escape(e, &shown))?;
        }
        shown.push(last);
        Ok(Slot {
            dir,
            name: (*last).to_owned(),
            display: shown,
        })
    }
}

impl Slot {
    /// Whether something already exists at the target, and if it is a folder.
    pub fn existing(&self) -> Result<Option<bool>> {
        match self.dir.symlink_metadata(&self.name) {
            Ok(m) => Ok(Some(m.is_dir())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(map_escape(e, &self.display)),
        }
    }

    /// Creates an empty placeholder, failing if anything exists there.
    pub fn reserve(&self) -> Result<()> {
        self.dir
            .open_with(&self.name, OpenOptions::new().write(true).create_new(true))
            .map(drop)
            .map_err(|e| match e.kind() {
                io::ErrorKind::AlreadyExists => Error::DestinationExists(self.display.clone()),
                _ => map_escape(e, &self.display),
            })
    }

    /// Removes our placeholder if it is still an empty regular file.
    pub fn remove_placeholder(&self) {
        if let Ok(m) = self.dir.symlink_metadata(&self.name) {
            if m.is_file() && m.len() == 0 {
                let _ = self.dir.remove_file(&self.name);
            }
        }
    }

    /// Creates a fresh, uniquely named temp file next to the target.
    pub fn create_tmp(&self) -> Result<(String, File)> {
        for _ in 0..8 {
            let suffix: [u8; 8] = rng::array();
            let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
            let tmp = format!(".{}.{hex}.svtmp", self.name);
            match self
                .dir
                .open_with(&tmp, OpenOptions::new().write(true).create_new(true))
            {
                Ok(f) => return Ok((tmp, f.into_std())),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(map_escape(e, &self.display)),
            }
        }
        Err(Error::Io(io::Error::other(
            "could not create a temporary file",
        )))
    }

    /// Renames the temp file over the target (replacing a file or link
    /// there, never writing through it) and makes the rename durable.
    pub fn commit(&self, tmp: &str) -> Result<()> {
        self.dir
            .rename(tmp, &self.dir, &self.name)
            .map_err(|e| map_escape(e, &self.display))?;
        #[cfg(unix)]
        if let Ok(d) = self.dir.try_clone() {
            let _ = d.into_std_file().sync_all();
        }
        Ok(())
    }

    pub fn remove_tmp(&self, tmp: &str) {
        let _ = self.dir.remove_file(tmp);
    }
}
