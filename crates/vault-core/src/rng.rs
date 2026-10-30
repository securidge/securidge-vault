//! Randomness comes only from the operating system CSPRNG
//! (`BCryptGenRandom` on Windows). Never from time or hardware identifiers.

/// Returns `N` random bytes.
///
/// # Panics
/// Panics if the OS random number generator fails. Continuing without
/// randomness would be unsafe, so aborting is the correct behaviour.
pub fn array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("operating system random number generator failed");
    buf
}
