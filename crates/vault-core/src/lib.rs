//! Core library for Securidge Vault.
//!
//! The format and cryptographic design are specified in `docs/DESIGN.md`.
//! In short:
//!
//! ```text
//! password --Argon2id--> KEK --XChaCha20-Poly1305--> master key (in .svkey)
//! master key --XChaCha20-Poly1305--> per-vault FEK (in .svault header)
//! FEK --XChaCha20-Poly1305 STREAM--> index and entries
//! ```
//!
//! Opening a vault therefore always needs both the key file and its password.

#![forbid(unsafe_code)]

mod error;
mod fsutil;
mod index;
pub mod kdf;
pub mod keyfile;
pub mod password;
pub mod pathsafe;
mod rng;
pub mod vault;

pub use error::{Error, Result};
pub use kdf::{KdfLimits, KdfParams};
pub use keyfile::{KeyId, UnlockedKey};
pub use password::Password;
pub use vault::{Entry, Vault};
