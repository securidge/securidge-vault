//! Where extracted files are written (DESIGN.md §7.1).
//!
//! - **Unix:** every operation goes through directory handles (`cap-std`,
//!   `handles.rs`), so a folder swapped for a link mid-extraction cannot
//!   redirect a write outside the destination.
//! - **Windows:** `cap-std` rebuilds paths from handles there and breaks on
//!   network paths (`\\server\share`, mapped drives), so `paths.rs` works
//!   with paths: links in parent folders are refused before use, and after
//!   each rename the file's folder is re-checked to be inside the
//!   destination (removing the file if not). A narrow race remains for a
//!   local attacker who can write into the destination folder.
//!
//! Both expose the same `DestDir` / `Slot` interface.

#[cfg(unix)]
mod handles;
#[cfg(unix)]
pub use handles::DestDir;

#[cfg(any(windows, test))]
mod paths;
#[cfg(windows)]
pub use paths::DestDir;
