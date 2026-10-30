//! Opening an arbitrary file as a vault with a known key must fail cleanly.
#![no_main]
use std::io::Write;

use libfuzzer_sys::fuzz_target;
use vault_core::{UnlockedKey, Vault};

fuzz_target!(|data: &[u8]| {
    let key = UnlockedKey::generate();
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    let _ = Vault::peek_key_id(f.path());
    let _ = Vault::open(f.path(), &key);
});
