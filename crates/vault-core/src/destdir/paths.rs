//! Windows: path-based extraction target (see `destdir.rs` for why).
//! Also compiled into the Unix test build so it is exercised everywhere.
#![cfg_attr(not(windows), allow(dead_code))]

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::{pathsafe, rng, Error, Result};

pub struct DestDir {
    /// Canonical form, used for the inside-the-destination checks.
    canon: PathBuf,
    /// As the user gave it, used for messages.
    root_path: PathBuf,
}

/// The folder an entry goes into, plus the entry's file name.
pub struct Slot {
    canon_root: PathBuf,
    parent: PathBuf,
    pub name: String,
    pub display: PathBuf,
}

impl DestDir {
    pub fn open(dest: &Path) -> Result<DestDir> {
        fs::create_dir_all(dest)?;
        Ok(DestDir {
            canon: dest.canonicalize()?,
            root_path: dest.to_path_buf(),
        })
    }

    /// Resolves the parent folder of `archive_path`, creating missing
    /// folders and refusing links and non-folders on the way.
    pub fn slot(&self, archive_path: &str) -> Result<Slot> {
        pathsafe::validate(archive_path)?;
        let comps: Vec<&str> = archive_path.split('/').collect();
        let (last, parents) = comps.split_last().expect("validated path is non-empty");
        let mut cur = self.canon.clone();
        let mut shown = self.root_path.clone();
        for comp in parents {
            cur.push(comp);
            shown.push(comp);
            match fs::symlink_metadata(&cur) {
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
                Err(e) if e.kind() == io::ErrorKind::NotFound => match fs::create_dir(&cur) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                },
                Err(e) => return Err(e.into()),
            }
        }
        shown.push(last);
        let slot = Slot {
            canon_root: self.canon.clone(),
            parent: cur,
            name: (*last).to_owned(),
            display: shown,
        };
        slot.check_inside()?;
        Ok(slot)
    }
}

impl Slot {
    fn target(&self) -> PathBuf {
        self.parent.join(&self.name)
    }

    /// The parent folder, resolved now, must still be inside the destination.
    fn check_inside(&self) -> Result<()> {
        let real = self.parent.canonicalize()?;
        if real.starts_with(&self.canon_root) {
            Ok(())
        } else {
            Err(Error::UnsafePath(format!(
                "{} leads outside the destination folder",
                self.display.display()
            )))
        }
    }

    pub fn existing(&self) -> Result<Option<bool>> {
        match fs::symlink_metadata(self.target()) {
            Ok(m) => Ok(Some(m.is_dir())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn reserve(&self) -> Result<()> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.target())
            .map(drop)
            .map_err(|e| match e.kind() {
                io::ErrorKind::AlreadyExists => Error::DestinationExists(self.display.clone()),
                _ => Error::Io(e),
            })
    }

    pub fn remove_placeholder(&self) {
        let t = self.target();
        if let Ok(m) = fs::symlink_metadata(&t) {
            if m.is_file() && m.len() == 0 {
                let _ = fs::remove_file(&t);
            }
        }
    }

    pub fn create_tmp(&self) -> Result<(String, File)> {
        self.check_inside()?;
        for _ in 0..8 {
            let suffix: [u8; 8] = rng::array();
            let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
            let tmp = format!(".svtmp-{hex}");
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.parent.join(&tmp))
            {
                Ok(f) => return Ok((tmp, f)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::Io(io::Error::other(
            "could not create a temporary file",
        )))
    }

    /// Renames the temp file over the target, then re-checks that the
    /// folder is still inside the destination; if a folder was swapped for
    /// a link meanwhile, the file is removed and an error returned.
    pub fn commit(&self, tmp: &str) -> Result<()> {
        let t = self.target();
        fs::rename(self.parent.join(tmp), &t)?;
        if let Err(e) = self.check_inside() {
            let _ = fs::remove_file(&t);
            return Err(e);
        }
        Ok(())
    }

    pub fn remove_tmp(&self, tmp: &str) {
        let _ = fs::remove_file(self.parent.join(tmp));
    }

    /// Path of a temp file, for the Mark-of-the-Web stream.
    pub fn tmp_display(&self, tmp: &str) -> PathBuf {
        self.parent.join(tmp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn writes_inside_and_refuses_links() {
        let d = tempfile::tempdir().unwrap();
        let dest = DestDir::open(&d.path().join("out")).unwrap();
        let s = dest.slot("a/b/c.txt").unwrap();
        assert_eq!(s.existing().unwrap(), None);
        s.reserve().unwrap();
        assert!(s.reserve().is_err());
        let (tmp, mut f) = s.create_tmp().unwrap();
        f.write_all(b"x").unwrap();
        drop(f);
        s.commit(&tmp).unwrap();
        assert_eq!(fs::read(d.path().join("out/a/b/c.txt")).unwrap(), b"x");
        assert!(dest.slot("../x").is_err());

        #[cfg(unix)]
        {
            let outside = d.path().join("outside");
            fs::create_dir(&outside).unwrap();
            std::os::unix::fs::symlink(&outside, d.path().join("out/link")).unwrap();
            assert!(matches!(dest.slot("link/x.txt"), Err(Error::UnsafePath(_))));
        }
    }
}
