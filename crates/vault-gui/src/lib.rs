//! Securidge Vault desktop app (Windows first; also builds on Linux).
//!
//! The binary is in `main.rs`; the window logic lives here so it can be
//! tested headlessly with `egui_kittest`.

#![forbid(unsafe_code)]

pub mod app;
pub mod fonts;
pub mod i18n;
pub mod settings;

pub use app::{App, Config};
