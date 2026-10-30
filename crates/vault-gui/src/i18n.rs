//! User-interface language (English by default, Korean optional).
//!
//! Every text shown in the window goes through [`t`] (fixed text) or [`tf`]
//! (text with `{0}`, `{1}`… placeholders). The English text is the key; the
//! Korean table below translates it. A unit test scans `app.rs` and fails if
//! any key has no Korean entry or the placeholders differ.

use std::fmt::Display;
use std::sync::atomic::{AtomicU8, Ordering};

use vault_core::advice::KeyWarning;
use vault_core::password::Weakness;
use vault_core::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Ko,
}

impl Lang {
    pub const ALL: [Lang; 2] = [Lang::En, Lang::Ko];

    /// The language's own name, shown in the language menu.
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Ko => "한국어",
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Ko => "ko",
        }
    }

    pub fn from_code(c: &str) -> Option<Lang> {
        match c.trim() {
            "en" => Some(Lang::En),
            "ko" => Some(Lang::Ko),
            _ => None,
        }
    }
}

static LANG: AtomicU8 = AtomicU8::new(0);

pub fn set_lang(l: Lang) {
    LANG.store(l as u8, Ordering::Relaxed);
}

pub fn lang() -> Lang {
    match LANG.load(Ordering::Relaxed) {
        1 => Lang::Ko,
        _ => Lang::En,
    }
}

/// Fixed text in the current language.
pub fn t(en: &'static str) -> &'static str {
    match lang() {
        Lang::En => en,
        Lang::Ko => ko(en).unwrap_or(en),
    }
}

/// Text with `{0}`, `{1}`… placeholders, filled in the current language.
pub fn tf(en: &'static str, args: &[&dyn Display]) -> String {
    let mut s = t(en).to_owned();
    for (i, a) in args.iter().enumerate() {
        s = s.replace(&format!("{{{i}}}"), &a.to_string());
    }
    s
}

/// A library error, explained in the current language.
pub fn err(e: &Error) -> String {
    if lang() == Lang::En {
        return e.to_string();
    }
    match e {
        Error::Io(io) => format!("파일을 읽거나 쓰는 중 문제가 생겼습니다: {io}"),
        Error::NotKeyFile => "Securidge Vault 키 파일이 아닙니다. 올바른 .svkey 파일을 선택하세요.".into(),
        Error::NotVault => "Securidge Vault 보관함 파일이 아닙니다. 올바른 .svault 파일을 선택하세요.".into(),
        Error::Unsupported(s) => format!(
            "이 버전에서 지원하지 않는 파일 형식입니다 ({s}). 프로그램을 최신 버전으로 업데이트해 보세요."
        ),
        Error::WrongPasswordOrCorrupt => {
            "비밀번호가 틀렸거나 키 파일이 손상되었습니다. 비밀번호를 다시 확인하세요.".into()
        }
        Error::KeyMismatch { expected, actual } => format!(
            "이 보관함은 다른 키 파일로 잠겨 있습니다 (필요한 키 ID {expected}, 선택한 키 ID {actual})."
        ),
        Error::Tampered => "보관함 검증에 실패했습니다. 파일이 손상되었거나 누군가 내용을 바꿨습니다. 아무것도 풀지 않았습니다.".into(),
        Error::KdfParamsOutOfRange => {
            "키 파일의 보안 설정 값이 허용 범위를 벗어났습니다. 손상되었거나 조작된 키 파일일 수 있습니다.".into()
        }
        Error::WeakPassword(_) => "사용할 수 없는 비밀번호입니다.".into(),
        Error::UnsafePath(s) => format!("안전하지 않은 경로라서 중단했습니다: {s}"),
        Error::LimitExceeded(s) => format!("허용 한도를 넘었습니다: {s}"),
        Error::EntryNotFound(s) => format!("보관함에 '{s}' 항목이 없습니다."),
        Error::EntryExists(s) => format!(
            "같은 이름의 파일이 이미 보관함에 있습니다: {s}\n('같은 이름 파일 바꾸기'를 켜면 새 파일로 바꿉니다.)"
        ),
        Error::DestinationExists(p) => format!(
            "같은 이름의 파일이 이미 있습니다: {}\n('기존 파일 덮어쓰기'를 켜면 덮어씁니다.)",
            p.display()
        ),
        Error::InvalidInput(s) => format!("입력이 올바르지 않습니다: {s}"),
        Error::Crypto => "내부 암호화 오류가 발생했습니다.".into(),
    }
}

/// Why a new password is not accepted, in the current language.
pub fn weakness(w: Weakness) -> String {
    match w {
        Weakness::TooShort(n) => tf(
            "Use at least 15 characters (yours has {0}). A few random words work well.",
            &[&n],
        ),
        Weakness::TooLong => t("Use at most 256 characters.").into(),
        Weakness::Repetitive => t("Too repetitive: use more different characters.").into(),
        Weakness::Common => {
            t("This password appears in lists of leaked or common passwords. Choose another.")
                .into()
        }
    }
}

pub fn key_warning(w: KeyWarning) -> &'static str {
    match w {
        KeyWarning::SameFolderAsVault => t("The key file is in the same folder as the vault. Anyone who copies the folder gets both."),
        KeyWarning::CloudSynced => t("The key file is in a cloud-synced folder. A copy may be stored online."),
        KeyWarning::SystemDrive => t("The key file is on the system drive. Malware that steals files can find it; prefer a USB drive."),
    }
}

/// Korean translations, keyed by the English text.
fn ko(en: &str) -> Option<&'static str> {
    Some(match en {
        // --- frame
        "Home" => "홈",
        "Language" => "언어",
        "Dismiss" => "닫기",
        "pre-alpha" => "시험판(프리알파)",
        "{0}… {1}s" => "{0}… {1}초",
        "The operation stopped unexpectedly." => "작업이 예기치 않게 멈췄습니다.",
        "Please wait until the current operation finishes." => "진행 중인 작업이 끝날 때까지 잠시 기다려 주세요.",
        "Your key file has no verified backups yet. Finish the backups, or close again to quit anyway." =>
            "키 파일 백업이 아직 확인되지 않았습니다. 백업을 마무리하시거나, 그래도 종료하려면 창을 한 번 더 닫으세요.",

        // --- common widgets
        "New password" => "새 비밀번호",
        "Repeat password" => "새 비밀번호 확인",
        "At least 15 characters. A few random words work well." =>
            "15자 이상 입력하세요. 서로 관련 없는 단어 몇 개를 띄어 쓰면 기억하기 쉽고 안전합니다.",
        "The passwords do not match." => "두 비밀번호가 서로 다릅니다.",
        "Use at least 15 characters (yours has {0}). A few random words work well." =>
            "15자 이상이어야 합니다 (지금 {0}자). 관련 없는 단어 몇 개를 이어 쓰는 방법을 권합니다.",
        "Use at most 256 characters." => "256자 이하로 입력하세요.",
        "Too repetitive: use more different characters." => "같은 글자가 너무 많이 반복됩니다. 더 다양한 글자를 쓰세요.",
        "This password appears in lists of leaked or common passwords. Choose another." =>
            "유출되었거나 흔히 쓰이는 비밀번호 목록에 있는 비밀번호입니다. 다른 비밀번호를 정하세요.",
        "Securidge key file" => "Securidge 키 파일",
        "Securidge vault" => "Securidge 보관함",
        "Browse…" => "찾아보기…",
        "not chosen" => "선택 안 함",
        "Key id {0}" => "키 ID {0}",
        "Vault" => "보관함",
        "Needs the key file with key id {0}" => "키 ID {0}인 키 파일이 있어야 열립니다",
        "Password" => "비밀번호",
        "Key" => "키",
        "Key file" => "키 파일",
        "That file already exists. Choose a new name." => "같은 이름의 파일이 이미 있습니다. 다른 이름을 정하세요.",
        "The key file is in the same folder as the vault. Anyone who copies the folder gets both." =>
            "키 파일이 보관함과 같은 폴더에 있습니다. 폴더째 복사해 가면 자물쇠와 열쇠를 함께 가져가는 셈입니다.",
        "The key file is in a cloud-synced folder. A copy may be stored online." =>
            "키 파일이 클라우드 동기화 폴더(OneDrive 등)에 있습니다. 온라인에 사본이 저장될 수 있습니다.",
        "The key file is on the system drive. Malware that steals files can find it; prefer a USB drive." =>
            "키 파일이 시스템 드라이브(C:)에 있습니다. 파일을 훔치는 악성코드가 찾을 수 있으니 USB 드라이브를 권합니다.",

        // --- home
        "Encrypted archives that open only with both your key file and your password. There is no recovery: lose either one and the data is gone." =>
            "키 파일과 비밀번호가 둘 다 있어야만 열리는 암호화 보관함입니다. 복구 방법은 없습니다. 둘 중 하나라도 잃어버리면 데이터를 되찾을 수 없습니다.",
        "Vaults" => "보관함",
        "Open a vault" => "보관함 열기",
        "List, extract, add or remove files." => "파일 목록 보기, 꺼내기, 추가, 삭제를 할 수 있습니다.",
        "Create a vault" => "보관함 만들기",
        "Pack files and folders into a new .svault." => "파일과 폴더를 암호화해 새 보관함(.svault)에 담습니다.",
        "Tip: drop files or a .svault here." => "팁: 파일이나 .svault 파일을 이 창에 끌어다 놓아도 됩니다.",
        "Key files" => "키 파일",
        "Create a key file" => "키 파일 만들기",
        "Start here. Includes making two backups." => "처음이라면 여기서 시작하세요. 백업 2개 만들기까지 안내합니다.",
        "Verify a backup" => "백업 확인하기",
        "Check that a key file copy still opens." => "보관해 둔 키 파일 사본이 지금도 잘 열리는지 확인합니다.",
        "Change password" => "비밀번호 바꾸기",
        "Same key, new password." => "키는 그대로 두고 비밀번호만 바꿉니다.",
        "Rekey vaults" => "키 교체하기",
        "Move vaults to a brand-new key file." => "보관함을 완전히 새로운 키 파일로 옮겨 잠급니다.",
        "Pre-alpha software, not independently audited. Keep other copies of anything you cannot afford to lose." =>
            "시험판 소프트웨어이며 외부 보안 감사를 받지 않았습니다. 잃으면 안 되는 파일은 다른 곳에도 꼭 사본을 두세요.",

        // --- new key
        "Step 1 of 3: choose a password and where to save the key file. Steps 2 and 3 make and check two backups." =>
            "1/3단계: 비밀번호와 키 파일 저장 위치를 정합니다. 2·3단계에서 백업 2개를 만들고 확인합니다.",
        "Location" => "저장 위치",
        "Save key file to" => "키 파일 저장 위치",
        "Create key file" => "키 파일 생성",
        "Creating key file" => "키 파일 만드는 중",
        "Created {0} (key id {1}). Now make two backups." => "{0} 파일을 만들었습니다 (키 ID {1}). 이제 백업 2개를 만드세요.",
        "Could not create the key file: {0}" => "키 파일을 만들지 못했습니다: {0}",

        // --- backup
        "{0} is in the same folder as another copy. Use a different drive or folder." =>
            "{0} 위치는 다른 사본과 같은 폴더입니다. 다른 드라이브나 폴더를 고르세요.",
        "{0} already exists." => "{0} 파일이 이미 있습니다.",
        "Back up your key file" => "키 파일 백업",
        "All copies verified." => "모든 사본을 확인했습니다.",
        "Original: {0}" => "원본: {0}",
        "Backup: {0}" => "백업: {0}",
        "Keep the copies in separate places. Verify a backup now and then (Home > Verify a backup)." =>
            "사본은 서로 다른 장소에 보관하세요. 가끔 '홈 > 백업 확인하기'로 잘 열리는지 점검하세요.",
        "Done" => "완료",
        "There is no recovery. If you lose every copy of this key file, or forget the password, every vault made with it is lost for good. Save two backups now, ideally on two different USB drives." =>
            "복구 방법은 없습니다. 이 키 파일의 사본을 모두 잃거나 비밀번호를 잊으면, 이 키로 만든 보관함은 영영 열 수 없습니다. 지금 백업 2개를 저장하세요. 서로 다른 USB 드라이브 2개에 저장하는 것이 가장 좋습니다.",
        "Step 2 of 3: two backup copies" => "2/3단계: 백업 사본 2개 만들기",
        "Backup {0}" => "백업 {0}",
        "Same drive as the original: if that drive fails, both copies are lost." =>
            "원본과 같은 드라이브입니다. 그 드라이브가 고장 나면 두 사본을 함께 잃습니다.",
        "Step 3 of 3: check the copies" => "3/3단계: 사본 확인하기",
        "Type the password once more. This reads every copy back and confirms the password opens it." =>
            "비밀번호를 한 번 더 입력하세요. 모든 사본을 다시 읽어 원본과 같은지, 비밀번호로 열리는지 확인합니다.",
        "Verify all copies" => "모든 사본 확인",
        "Verifying copies" => "사본 확인하는 중",
        "All {0} copies match and open (key id {1})." => "사본 {0}개가 모두 원본과 같고 정상적으로 열립니다 (키 ID {1}).",
        "I accept that if I lose this key file or forget the password, my data is gone." =>
            "이 키 파일을 잃거나 비밀번호를 잊으면 데이터를 영영 잃는다는 점을 이해하고 받아들입니다.",
        "Skip backups" => "백업 건너뛰기",
        "Backups skipped. Only one copy exists: {0}" => "백업을 건너뛰었습니다. 사본은 이것 하나뿐입니다: {0}",
        "Cannot read {0}: {1}" => "{0} 파일을 읽을 수 없습니다: {1}",
        "{0} differs from the original key file." => "{0} 파일이 원본 키 파일과 다릅니다.",

        // --- create vault
        "Files and folders" => "담을 파일과 폴더",
        "Add files…" => "파일 추가…",
        "Add folder…" => "폴더 추가…",
        "or drop them on this window" => "또는 이 창에 끌어다 놓으세요",
        "Remove from list" => "목록에서 빼기",
        "Save as" => "저장할 파일",
        "Vault file" => "보관함 파일",
        "Create vault" => "보관함 생성",
        "Unlocking key and encrypting" => "키를 열고 암호화하는 중",
        "Created {0} with {1} file(s)." => "{0} 보관함을 만들었습니다 (파일 {1}개).",
        " Skipped {0} link(s) or special file(s)." => " 바로가기·특수 파일 {0}개는 건너뛰었습니다.",

        // --- open vault
        "This key file does not belong to this vault." => "이 키 파일로는 이 보관함을 열 수 없습니다. 맞는 키 파일을 고르세요.",
        "Open" => "열기",
        "Unlocking key file" => "키 파일 여는 중 (몇 초 걸립니다)",

        // --- opened vault
        "Adding" => "추가하는 중",
        "Vault now holds {0} file(s) (was {1})." => "보관함의 파일이 {1}개에서 {0}개가 되었습니다.",
        "Extract to folder" => "꺼낼 폴더 선택",
        "Extracting" => "꺼내는 중",
        "Extracted {0} file(s) to {1}." => "파일 {0}개를 {1} 폴더에 꺼냈습니다.",
        "Working…" => "작업 중…",
        "{0} file(s), {1} · key id {2}" => "파일 {0}개, {1} · 키 ID {2}",
        "Extract all…" => "모두 꺼내기…",
        "Extract selected ({0})…" => "선택한 파일 꺼내기 ({0})…",
        "Overwrite existing files" => "기존 파일 덮어쓰기",
        "Replace files with the same name" => "같은 이름 파일 바꾸기",
        "Remove selected ({0})" => "선택한 파일 삭제 ({0})",
        "Lock" => "잠그기",
        "Close the vault and wipe its key from memory" => "보관함을 닫고 메모리에서 키를 지웁니다",
        "Remove {0} file(s) from the vault?" => "보관함에서 파일 {0}개를 삭제할까요?",
        "This cannot be undone." => "삭제하면 되돌릴 수 없습니다.",
        "Remove" => "삭제",
        "Cancel" => "취소",
        "Removing" => "삭제하는 중",
        "Removed {0} file(s)." => "파일 {0}개를 삭제했습니다.",
        "Filter" => "검색",
        "Select shown" => "보이는 항목 모두 선택",
        "Clear selection" => "선택 해제",
        "Path" => "경로",
        "Size" => "크기",
        "Modified (UTC)" => "수정 시각 (UTC)",

        // --- change password
        "The key stays the same, so your vaults keep working. Older copies of this key file (your backups) still open with the OLD password until you replace them. If someone may know the old password, use Rekey instead." =>
            "키는 그대로이므로 기존 보관함은 계속 열립니다. 단, 예전에 만든 키 파일 사본(백업)은 바꾸기 전까지 예전 비밀번호로 계속 열립니다. 누군가 예전 비밀번호를 알 수도 있다면 '키 교체하기'를 쓰세요.",
        "Current password" => "현재 비밀번호",
        "Save new password" => "새 비밀번호 저장",
        "Re-encrypting key file" => "키 파일 다시 암호화하는 중",
        "Password changed. Make fresh backups now; your old backups still use the old password." =>
            "비밀번호를 바꿨습니다. 지금 새로 백업하세요. 예전 백업은 여전히 예전 비밀번호로 열립니다.",

        // --- verify
        "Checks that a key file copy is intact and that your password opens it. Nothing is changed." =>
            "키 파일 사본이 손상되지 않았는지, 비밀번호로 열리는지 확인합니다. 파일은 전혀 바뀌지 않습니다.",
        "Verify" => "확인",
        "OK: {0} opens correctly (key id {1})." => "정상: {0} 파일이 올바르게 열립니다 (키 ID {1}).",

        // --- rekey
        "Creates a brand-new key file and re-encrypts the listed vaults for it. Afterwards the old key file (and every copy of it) can no longer open them. Use this if a key file copy or the password may have leaked." =>
            "완전히 새로운 키 파일을 만들고, 목록의 보관함을 새 키로 다시 암호화합니다. 그 뒤로는 예전 키 파일(과 모든 사본)로 열 수 없습니다. 키 파일 사본이나 비밀번호가 유출되었을 수 있을 때 쓰세요.",
        "Current key" => "현재 키",
        "Current key file" => "현재 키 파일",
        "Vaults to move" => "새 키로 옮길 보관함",
        "Add vaults…" => "보관함 추가…",
        "{0}: belongs to a different key file" => "{0}: 다른 키 파일의 보관함입니다",
        "{0}: not a readable vault" => "{0}: 읽을 수 있는 보관함이 아닙니다",
        "Vaults you do not list keep needing the OLD key file." => "목록에 넣지 않은 보관함은 계속 예전 키 파일로 열어야 합니다.",
        "New key file" => "새 키 파일",
        "Save new key file to" => "새 키 파일 저장 위치",
        "Rekey" => "키 교체 실행",
        "Rekeying" => "키 교체하는 중",
        "Rekeyed {0} vault(s). Back up the new key file now, then destroy every copy of the old one." =>
            "보관함 {0}개의 키를 교체했습니다. 지금 새 키 파일을 백업한 뒤, 예전 키 파일은 사본까지 모두 지우세요.",
        "Rekeyed {0} vault(s), then stopped: {1}. Vaults not yet rekeyed still need the OLD key file. Back up the new key file now." =>
            "보관함 {0}개를 교체한 뒤 멈췄습니다: {1}. 아직 교체하지 못한 보관함은 예전 키 파일이 있어야 열립니다. 지금 새 키 파일을 백업하세요.",
        "{0}: {1}" => "{0}: {1}",
        "{0} does not belong to this key file; nothing was changed" => "{0} 보관함은 이 키 파일의 것이 아닙니다. 아무것도 바꾸지 않았습니다",
        "Could not create the new key: {0}" => "새 키를 만들지 못했습니다: {0}",
        "Could not write the new key file: {0}" => "새 키 파일을 저장하지 못했습니다: {0}",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `t("…")` / `tf("…"` key used in the app has a Korean entry with
    /// the same placeholders.
    #[test]
    fn every_ui_text_has_a_korean_translation() {
        let mut keys = Vec::new();
        for file in [include_str!("app.rs"), include_str!("i18n.rs")] {
            // Ignore comment lines; join the rest so keys split across
            // lines by rustfmt (call on one line, literal on the next) match.
            let code: Vec<&str> = file
                .lines()
                .map(str::trim)
                .filter(|l| !l.starts_with("//"))
                .collect();
            let joined = code.join("");
            let src = joined.as_str();
            for marker in ["t(\"", "tf(\"", "spawn(\"", "run(rt, \""] {
                let mut rest = src;
                while let Some(i) = rest.find(marker) {
                    let before = rest[..i].chars().last();
                    rest = &rest[i + marker.len()..];
                    // Skip identifiers that merely end in "t(" (e.g. "set(").
                    if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                        continue;
                    }
                    let end = rest.find('"').expect("closing quote");
                    keys.push(rest[..end].to_owned());
                }
            }
        }
        assert!(keys.len() > 100, "found only {} keys", keys.len());
        let mut missing = Vec::new();
        for k in &keys {
            match ko(k) {
                None => missing.push(k.clone()),
                Some(v) => {
                    for i in 0..4 {
                        let p = format!("{{{i}}}");
                        assert_eq!(k.contains(&p), v.contains(&p), "placeholder {p} in {k:?}");
                    }
                }
            }
        }
        assert!(missing.is_empty(), "no Korean text for: {missing:#?}");
    }

    #[test]
    fn placeholders_fill_in_order() {
        set_lang(Lang::En);
        assert_eq!(tf("{0}: {1}", &[&"a", &2]), "a: 2");
    }
}
