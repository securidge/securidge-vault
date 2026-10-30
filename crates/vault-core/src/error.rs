use std::path::PathBuf;

/// Errors returned by the core library.
///
/// Authentication failures are deliberately coarse: the library never tells
/// an attacker *which* check failed beyond what is needed for a usable UI.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not a Securidge Vault key file")]
    NotKeyFile,

    #[error("not a Securidge Vault vault file")]
    NotVault,

    #[error("unsupported format version or flags ({0})")]
    Unsupported(String),

    #[error("wrong password, or the key file is corrupted")]
    WrongPasswordOrCorrupt,

    #[error(
        "this vault belongs to a different key file (vault needs key {expected}, got {actual})"
    )]
    KeyMismatch { expected: String, actual: String },

    #[error("vault failed authentication: it is corrupted or has been tampered with")]
    Tampered,

    #[error("key derivation parameters are outside the accepted range")]
    KdfParamsOutOfRange,

    #[error("password rejected: {0}")]
    WeakPassword(String),

    #[error("unsafe path: {0}")]
    UnsafePath(String),

    #[error("limit exceeded: {0}")]
    LimitExceeded(&'static str),

    #[error("no entry matches '{0}'")]
    EntryNotFound(String),

    #[error("entry already exists in the vault: {0} (use replace to overwrite)")]
    EntryExists(String),

    #[error("destination already exists: {}", .0.display())]
    DestinationExists(PathBuf),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("internal cryptographic error")]
    Crypto,
}

pub type Result<T> = std::result::Result<T, Error>;
