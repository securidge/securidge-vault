//! Password-based key derivation with Argon2id (RFC 9106).

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::{Error, Password, Result};

/// Argon2id cost parameters. Stored in every key file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// Default for new key files: 1 GiB, 3 iterations, 4 lanes.
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 1024 * 1024,
        t: 3,
        p: 4,
    };
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Accepted range of KDF parameters.
///
/// The minimum stops weak key files from being created or accepted; the
/// maximum stops a crafted key file from exhausting memory or CPU.
#[derive(Clone, Copy, Debug)]
pub struct KdfLimits {
    pub min_m_kib: u32,
    pub min_t: u32,
    pub max_m_kib: u32,
    pub max_t: u32,
    pub max_p: u32,
}

impl KdfLimits {
    /// Limits used by the application. See DESIGN.md §4.2.
    pub const PRODUCTION: KdfLimits = KdfLimits {
        min_m_kib: 256 * 1024,
        min_t: 3,
        max_m_kib: 4 * 1024 * 1024,
        max_t: 10,
        max_p: 16,
    };

    /// Tiny limits so the test suite runs in seconds.
    ///
    /// **Never use outside tests.** Key files created with these
    /// parameters are rejected by [`KdfLimits::PRODUCTION`].
    #[doc(hidden)]
    pub const INSECURE_FOR_TESTS: KdfLimits = KdfLimits {
        min_m_kib: 8,
        min_t: 1,
        max_m_kib: 4 * 1024 * 1024,
        max_t: 10,
        max_p: 16,
    };

    pub fn check(&self, p: &KdfParams) -> Result<()> {
        let ok = p.m_kib >= self.min_m_kib
            && p.m_kib <= self.max_m_kib
            && p.t >= self.min_t
            && p.t <= self.max_t
            && p.p >= 1
            && p.p <= self.max_p
            && p.m_kib >= 8 * p.p;
        if ok {
            Ok(())
        } else {
            Err(Error::KdfParamsOutOfRange)
        }
    }
}

/// Derives a 32-byte key-encryption key from a password.
pub fn derive(
    password: &Password,
    salt: &[u8; 16],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| Error::KdfParamsOutOfRange)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}
