//! Path rules (DESIGN.md §7.1): never panic, and anything accepted must be
//! a plain relative path that stays inside the destination.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_core::pathsafe;

fuzz_target!(|s: &str| {
    if pathsafe::validate(s).is_ok() {
        assert!(!s.starts_with('/'));
        assert!(!s.split('/').any(|c| c.is_empty() || c == "." || c == ".."));
        assert!(!s.chars().any(|c| c < ' ' || c == '\\' || c == ':'));
        let _ = pathsafe::fold(s);
    }
});
