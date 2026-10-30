//! Key file parsing and unlocking with attacker-chosen bytes. Limits are
//! tiny so Argon2id cost stays small; the parameter checks are under test.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_core::{keyfile, KdfLimits, Password};

const LIMITS: KdfLimits = KdfLimits {
    min_m_kib: 8,
    min_t: 1,
    max_m_kib: 64,
    max_t: 1,
    max_p: 1,
};

fuzz_target!(|data: &[u8]| {
    let _ = keyfile::inspect(data);
    let _ = keyfile::open(data, &Password::new_unchecked("fuzz password 123"), &LIMITS);
});
