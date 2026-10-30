//! The decrypted index is authenticated, but a bug elsewhere (or a
//! malicious writer holding the key) could still produce any bytes here.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let (end, buf) = data.split_at(8);
    let data_end = u64::from_le_bytes(end.try_into().unwrap());
    vault_core::fuzzing::index_decode(buf, data_end);
});
