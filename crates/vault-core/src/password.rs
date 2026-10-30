//! Password handling and policy (DESIGN.md §6, based on NIST SP 800-63B Rev. 4).
//!
//! - minimum 15 characters, maximum 256
//! - no composition rules
//! - Unicode normalised to NFC before hashing, so the same password typed on
//!   different keyboards or systems produces the same key
//! - passwords found in a bundled offline list of breached passwords
//!   (`data/breached-15plus.txt`, see `data/README.md`) are rejected, as are
//!   a few well-known phrases and repetition patterns. No network lookup.

use std::collections::HashSet;
use std::sync::OnceLock;

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const MIN_CHARS: usize = 15;
pub const MAX_CHARS: usize = 256;

/// A password, NFC-normalised, wiped from memory on drop.
pub struct Password(Zeroizing<String>);

impl Password {
    /// For setting a **new** password: applies the policy.
    pub fn new_checked(raw: &str) -> Result<Self> {
        let pw = Self::new_unchecked(raw);
        check_policy(&pw.0)?;
        Ok(pw)
    }

    /// For unlocking an **existing** key file: no policy check, only
    /// normalisation, so a policy change never locks anyone out.
    pub fn new_unchecked(raw: &str) -> Self {
        Password(Zeroizing::new(raw.nfc().collect()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Why a new password was rejected. Lets user interfaces explain it in
/// their own words and language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Weakness {
    /// Fewer than [`MIN_CHARS`] characters; carries the actual count.
    TooShort(usize),
    /// More than [`MAX_CHARS`] characters.
    TooLong,
    /// Fewer than five different characters.
    Repetitive,
    /// Found in the breached-password list or a known common pattern.
    Common,
}

impl std::fmt::Display for Weakness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Weakness::TooShort(n) => write!(
                f,
                "use at least {MIN_CHARS} characters (yours has {n}); a few random words work well"
            ),
            Weakness::TooLong => write!(f, "use at most {MAX_CHARS} characters"),
            Weakness::Repetitive => f.write_str("too repetitive"),
            Weakness::Common => f.write_str("it appears in lists of breached or common passwords"),
        }
    }
}

/// Checks a candidate **new** password against the policy (after NFC).
pub fn weakness(raw: &str) -> Option<Weakness> {
    let pw: String = raw.nfc().collect();
    let chars = pw.chars().count();
    if chars < MIN_CHARS {
        return Some(Weakness::TooShort(chars));
    }
    if chars > MAX_CHARS {
        return Some(Weakness::TooLong);
    }
    let distinct: HashSet<char> = pw.chars().collect();
    if distinct.len() < 5 {
        return Some(Weakness::Repetitive);
    }
    let lower = pw.to_lowercase();
    if COMMON.iter().any(|c| *c == lower) || is_repeated_common(&lower) || is_breached(&lower) {
        return Some(Weakness::Common);
    }
    None
}

fn check_policy(pw: &str) -> Result<()> {
    match weakness(pw) {
        Some(w) => Err(Error::WeakPassword(w.to_string())),
        None => Ok(()),
    }
}

/// Breached passwords of 15+ characters, sorted by bytes (one per line).
static BREACHED_RAW: &str = include_str!("../data/breached-15plus.txt");

fn breached() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| BREACHED_RAW.lines().collect())
}

/// `lower` must already be NFC-normalised and lower-cased.
pub fn is_breached(lower: &str) -> bool {
    breached().binary_search(&lower).is_ok()
}

/// Number of entries in the bundled breached-password list.
pub fn breached_list_len() -> usize {
    breached().len()
}

/// Catches things like "passwordpassword1" or "qwertyqwertyqwerty".
fn is_repeated_common(lower: &str) -> bool {
    const STEMS: [&str; 8] = [
        "password", "qwerty", "123456", "iloveyou", "abc123", "letmein", "admin", "welcome",
    ];
    let stripped: String = lower.chars().filter(|c| c.is_alphanumeric()).collect();
    STEMS.iter().any(|s| {
        let mut rest = stripped.as_str();
        let mut count = 0;
        while let Some(r) = rest.strip_prefix(s) {
            rest = r;
            count += 1;
        }
        count >= 2 && rest.chars().all(|c| c.is_ascii_digit())
    })
}

const COMMON: &[&str] = &[
    "123456789012345",
    "1234567890123456",
    "qwertyuiopasdfgh",
    "qwertyuiopasdfghjkl",
    "1q2w3e4r5t6y7u8i",
    "passwordpassword",
    "iloveyouiloveyou",
    "abcdefghijklmnop",
    "correcthorsebatterystaple",
    "correct horse battery staple",
    "thequickbrownfox",
    "letmeinletmein1",
    "trustno1trustno1",
    "administrator123",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy() {
        assert!(Password::new_checked("short").is_err());
        assert!(Password::new_checked("aaaaaaaaaaaaaaaaaaaa").is_err());
        assert!(Password::new_checked("passwordpassword").is_err());
        assert!(Password::new_checked("PasswordPassword2024").is_err());
        assert!(Password::new_checked("Correct Horse Battery Staple").is_err());
        assert!(Password::new_checked("maple river lantern quietly").is_ok());
        // Length counts characters, not bytes.
        assert!(Password::new_checked("가나다라마바사아자차카타파하").is_err()); // 14 chars
        assert!(Password::new_checked("가나다라마바사아자차카타파하거").is_ok());
        // 15 chars
    }

    #[test]
    fn breached_list() {
        let list = breached();
        assert!(list.len() > 100_000);
        assert!(
            list.windows(2).all(|w| w[0] < w[1]),
            "must be sorted and unique"
        );
        assert!(list.iter().all(|p| p.chars().count() >= MIN_CHARS));
        // Real entries from the corpus, in any case.
        for p in ["1qaz2wsx3edc4rfv", "123456789qwerty", "QAZWSXEDCRFVTGB"] {
            assert!(Password::new_checked(p).is_err(), "{p} should be rejected");
        }
        assert!(!is_breached("maple river lantern quietly"));
    }

    #[test]
    fn nfc_normalisation() {
        // "é" precomposed vs "e" + combining acute accent.
        let a = Password::new_unchecked("caf\u{00e9}");
        let b = Password::new_unchecked("cafe\u{0301}");
        assert_eq!(a.as_bytes(), b.as_bytes());
    }
}
