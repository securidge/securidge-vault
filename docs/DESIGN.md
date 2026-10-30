# Securidge Vault — Design Document

| | |
|---|---|
| Status | Draft v0.3 — format v1 implemented; GUI (M2) and test hardening (M3) done; release pipeline (M4) in place |
| Last updated | 2026-10-30 |
| Scope | Windows desktop, single-user, offline |

This document defines what Securidge Vault is, what it protects against, and exactly how it encrypts data. It is the reference for implementation, review, and any future security audit. If the code and this document disagree, that is a bug in one of them.

---

## 1. Overview

Securidge Vault is a free, portable, open-source encrypted archiver for Windows. It compresses files into a vault (`.svault`) that can only be opened with **both**:

1. a **key file** (`.svkey`) that the user carries (e.g., on a USB drive), and
2. the **password** that protects that key file.

There is no recovery path. Neither the author nor anyone else can open a vault without the key file and its password. This is the core promise of the product, not a limitation to be fixed later.

### 1.1 Goals

- **G1. Two factors, always.** Every vault requires a key file *and* a password. No password-only or key-file-only mode exists.
- **G2. No backdoor, no recovery service.** No server, no escrow, no telemetry, no network access at all.
- **G3. Portable.** One executable, no installer, no admin rights, no registry writes by default.
- **G4. Archive, not just encryption.** List contents, extract a single file, and add or replace files without decrypting the whole vault.
- **G5. Cheap password change.** Changing the password re-encrypts only the key file, not every vault.
- **G6. Hard to misuse.** Weak passwords are rejected; risky key-file storage is warned about; backup is part of setup, not an afterthought.
- **G7. Standard cryptography only.** Well-reviewed primitives from maintained libraries. No custom ciphers, no "stronger than AES" claims.

### 1.2 Non-goals (v1)

- Sharing vaults with other people (public-key recipients)
- Cloud sync, accounts, or any online feature
- macOS, Linux, mobile
- Plausible deniability / hidden volumes
- Error-correction coding (Reed–Solomon)
- Protecting data on a machine that is already compromised while the vault is open (see §2.3)

---

## 2. Threat model

### 2.1 Assets

- Plaintext contents of vaults, including file names, folder structure, and file sizes where feasible.
- The vault master key (MK) inside each key file.

### 2.2 Attackers we defend against

| Attacker has | Outcome we guarantee |
|---|---|
| Vault file only | Cannot read anything. MK is 256 random bits; brute force is infeasible. |
| Vault + password | Cannot read anything. Key file is still required. |
| Vault + copy of key file | Must brute-force the password through Argon2id (§4.2). Security then depends on password strength, which is why §6 enforces a strong policy. |
| Modified / truncated vault | Detected and rejected. All data is authenticated (AEAD); chunk reordering and truncation are detected (§4.4). |
| Malicious vault crafted to attack the extractor | Paths outside the destination folder are refused (§7.1); parsers enforce size limits. |
| Future quantum computer | Only symmetric cryptography is used. 256-bit keys keep ~128-bit security against Grover's algorithm. |

### 2.3 Out of scope (stated honestly)

- **Malware running on the user's PC while a vault is open.** A keylogger can capture the password; memory scrapers can read decrypted data. No file-encryption tool can fully defend against this.
- **Attacker who has the key file *and* the password.** That is, by definition, the legitimate user.
- **Swapped executable.** If someone replaces `SecuridgeVault.exe` on the user's USB drive with a trojaned build, the next password entry is compromised. Mitigated (not solved) by code signing and published checksums (§9).
- **Lost key file and/or forgotten password.** Data is permanently unrecoverable. Mitigated only by the backup flow (§5.3).

---

## 3. Terminology

| Term | Meaning |
|---|---|
| **Key file** (`.svkey`) | Small file holding the encrypted master key. Called "certificate" in early planning; it is *not* an X.509 certificate. |
| **MK** | Master key. 32 random bytes, stored only inside the key file, encrypted. |
| **KEK** | Key-encryption key. Derived from the password with Argon2id; encrypts MK. Never stored. |
| **Vault** (`.svault`) | The encrypted archive. |
| **FEK** | File-encryption key. 32 random bytes per vault; encrypts vault contents. Stored in the vault header, wrapped by MK. |
| **Entry** | One file stored inside a vault. |

---

## 4. Cryptographic design

### 4.1 Primitives

| Purpose | Choice | Notes |
|---|---|---|
| Authenticated encryption | XChaCha20-Poly1305 | 192-bit nonce makes random nonces safe; no hardware dependency. |
| Password hashing | Argon2id (RFC 9106) | Memory-hard; parameters stored per key file. |
| Randomness | OS CSPRNG (`BCryptGenRandom` via `getrandom`) | Used for MK, FEK, salts, nonces. Never time or hardware serials. |
| Compression | Zstandard | Applied *before* encryption. |
| Memory hygiene | Zeroize secrets after use | Keys, passwords, decrypted index, Argon2 memory. Best effort: I/O buffers and compressor state are not wiped. |

Key hierarchy:

```
password ──Argon2id(salt, params)──▶ KEK
KEK ──XChaCha20-Poly1305──▶ decrypts MK          (inside .svkey)
MK  ──XChaCha20-Poly1305──▶ decrypts FEK         (inside each .svault header)
FEK ──XChaCha20-Poly1305 (STREAM)──▶ decrypts index and entries
```

### 4.2 Key derivation (password → KEK)

- Salt: 16 random bytes per key file.
- Default parameters: **memory 1 GiB, iterations 3, parallelism 4**, output 32 bytes.
- Target: 1–3 seconds on a mid-range 2024 laptop.
- Measured (M1, release build, 2-vCPU cloud VM): 2.6–3.1 s per unlock; first run in a process up to 5.7 s while 1 GiB is allocated. Re-measure on typical Windows laptops before v1.0.
- Floor (refuse weaker): memory 256 MiB, iterations 3.
- Ceiling when *reading* a key file (anti-DoS): memory 4 GiB, iterations 10. Files outside these bounds are rejected.
- Parameters are stored in the key file header so they can be raised in future versions without breaking old files.

### 4.3 Key file (`.svkey`)

```
Offset  Size  Field
0       8     magic            "SVKEY\0\0\1"
8       2     format_version   u16 LE = 1
10      2     flags            u16 LE = 0 (reserved)
12      16    key_id           random; lets the app match vaults to key files
28      4     argon2_m_kib     u32 LE
32      4     argon2_t         u32 LE
36      4     argon2_p         u32 LE
40      16    salt
56      24    nonce
80      48    ciphertext       XChaCha20-Poly1305(KEK, nonce, MK[32]) + tag[16]
                               AAD = bytes 0..56 (whole header before nonce)
128           end
```

- Binding the header as AAD means tampering with KDF parameters or `key_id` makes decryption fail instead of silently weakening security.
- `key_id` is stored in plaintext so the app can say "this vault needs key file X". Accepted trade-off: someone holding both files can tell they belong together.

### 4.4 Vault (`.svault`)

```
[Header]       fixed size, plaintext
[Entry data]   entry streams, appended over time
[Index block]  encrypted file list (latest one is authoritative)
[Trailer]      points to the latest index block
```

**Header**

```
Offset  Size  Field
0       8     magic            "SVAULT\0\1"
8       2     format_version   u16 LE = 1
10      2     flags            u16 LE = 0 (reserved; non-zero is rejected)
12      16    vault_id         random; never changes, including on rekey
28      16    key_id           must equal the key file's key_id
44      24    fek_nonce
68      48    fek_wrapped      XChaCha20-Poly1305(MK, fek_nonce, FEK[32]) + tag
                               AAD = bytes 0..44
116           end
```

`vault_id` exists so that index and entry data can be bound to *this* vault (via AAD) without being bound to `key_id`, which changes on rekey.

**Entry streams.** Each entry is zstd-compressed (level 6), then encrypted with FEK in fixed 1 MiB chunks using the STREAM construction (`EncryptorBE32`: chunk counter and a last-chunk flag are bound into each chunk's nonce). This detects reordered, duplicated, dropped, or truncated chunks. Each entry gets its own random 19-byte nonce prefix, recorded in the index, so swapping two entries' data is also detected. AAD = header bytes 0..28 ‖ `"SV-ENTRY"`.

Ciphertext length of an entry is `compressed_size + 16 × max(1, ⌈compressed_size / 1 MiB⌉)`; the decoder rejects any index entry that does not match.

**Index block.** `nonce[24] ‖ XChaCha20-Poly1305(FEK, nonce, index)`, AAD = header bytes 0..28 ‖ `"SV-INDEX"`. A fresh random nonce is used every time the index is written. Per entry:

- normalized relative path (UTF-8, validated per §7.1, unique case-insensitively)
- original size, compressed size, modification time
- offset and length of its stream, nonce prefix, chunk size

File names, folder structure, and per-file sizes are therefore hidden. The **total vault size** is visible; we accept this leak in v1.

**Trailer.** `index_offset` (u64) + `index_length` (u64) + magic `"SVEND\0\0\1"`. The index must end exactly where the trailer starts. Authenticity of the index comes from its AEAD tag, not the trailer.

**Add / replace / remove.** Every change writes a complete new vault: header, the kept entries copied verbatim as ciphertext (not re-encrypted), new entries, a new index, a new trailer. There is no dead space and no old index left in the file, so an attacker with write access cannot roll the file list back to an earlier version stored in the same file. Cost: each change rewrites the whole file (I/O only). No separate Compact command is needed.

**Crash safety and concurrency.** Writes go to a uniquely named temp file next to the vault (`.svtmp-<random>`, created with `create_new`, so a planted file or link at a predictable name is never followed), are synced, then renamed over the original; on Unix the folder is synced too. A crash leaves the previous vault intact, and a leftover `.svtmp` file contains only ciphertext. While a vault is being changed it holds an advisory exclusive lock; a second writer is refused. Creating a vault first reserves the name with `create_new`, so a file that appears in the meantime is never replaced.

**Limitations of format v1.**
- An attacker who can replace the whole file can substitute an *older copy of the same vault* (e.g., from a backup). Detecting this would require state outside the file.
- Empty folders are not stored.
- If extraction fails part-way (e.g., tampering detected in the third file), the failing file is deleted but files already extracted remain. They are authentic, because every chunk is authenticated before it is written.

### 4.5 Password change vs. rekey

These are different operations, and the UI must not blur them.

- **Change password.** Decrypt MK with the old KEK, re-encrypt it with a new KEK (new salt). Only the key file changes; takes seconds. **Limitation:** any *old copy* of the key file still opens with the *old* password. If the old password may be compromised, password change alone is not enough.
- **Rekey (compromise response).** Generate a new MK and `key_id` and write the new key file first. Then, for every selected vault, generate a **new FEK and new `vault_id`** and re-encrypt every entry chunk from the old FEK to the new one (no decompression or recompression, so chunk and file sizes stay the same). Afterwards the old key cannot read anything in the rekeyed vault, and splicing an old header onto the new file fails because both the FEK and the AAD (`vault_id`) changed. The user must then destroy old key file copies and back up the new one.
- **Limitation:** older *copies of the vault* (e.g., backups made before the rekey) are still encrypted under the old key. Rekey protects the current file, not copies that already exist elsewhere.
- *History:* the first M1 implementation rewrapped only the header and kept the FEK and `vault_id`. An internal review showed that splicing the pre-rekey header onto the post-rekey file let the old key read data added after the rekey. Fixed before any release.

### 4.6 What we deliberately do not do

- No cipher cascades in v1. XChaCha20 alone is not the weak link; extra layers add code and bug surface.
- No "secure delete" of original files. Overwriting is unreliable on SSDs and journaling file systems; promising it would be false. Deleting originals after archiving is an opt-in action with a clear warning.
- No hardware-ID binding. Hardware serials are readable and often blank; they add no secret.

---

## 5. Key file lifecycle

### 5.1 Creation

1. User chooses a password (validated per §6).
2. App generates MK and `key_id` from the OS CSPRNG.
3. App writes the key file to a location the user picks.
4. App immediately starts the backup flow (§5.3). It cannot be skipped silently; skipping requires an explicit "I accept that losing this file loses my data" confirmation.

### 5.2 Storage warnings

- Key file on the system drive (`C:`) → warn: malware that steals files will find it.
- Key file in the same folder as a vault → warn: the lock and key are stored together.
- Key file in a cloud-synced folder (OneDrive, Dropbox, Google Drive paths) → warn.

Warnings inform; they do not block.

### 5.3 Backup and verification

- Setup asks for **two** backup locations (e.g., two USB drives).
- **Verify backup** command: opens a backup key file with the password and confirms it decrypts to the same `key_id`. Users are reminded to run it periodically (local reminder only; no network).

---

## 6. Password policy

Based on NIST SP 800-63B Rev. 4.

- Minimum **15 characters**. Maximum 256.
- **No composition rules** (no forced uppercase / digit / symbol).
- All Unicode accepted, including spaces; normalized with NFC before hashing.
- Rejected if found in a **bundled offline list of common and breached passwords** (no network lookup). Since shorter passwords are already refused, only breached passwords of 15–256 characters are bundled: 140,899 entries (2.5 MB uncompressed) from the SecLists `xato-net-10-million-passwords` list (MIT), NFC-normalised, lower-cased and binary-searched. Source and rebuild script: `crates/vault-core/data/README.md`, `scripts/build_password_list.py`. Repetition patterns and a few well-known phrases are also refused.
- Planned, not yet implemented: a strength meter and a passphrase generator (random words). The GUI currently shows the policy result live while typing.

---

## 7. Extraction and file-system safety

### 7.1 Path safety

On extraction, every entry path is normalized and rejected if it:

- is absolute, has a drive letter, or is a UNC path
- contains `..` that escapes the destination
- uses reserved Windows names (`CON`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9`, superscript variants, `CONIN$`, `CONOUT$`) or alternate data streams (`:`)
- looks like an 8.3 short name (`LONGNA~1`), which could alias another file
- collides with another entry after Unicode NFC normalisation and case folding
- resolves through a symlink or junction outside the destination

Each file is decrypted into a fresh temp file in its destination folder and then renamed into place. This means:

- an existing file or link at the target is *replaced*, never written through (hard links included);
- a failed or tampered entry never touches the user's existing file;
- without `overwrite`, the name is reserved with `create_new` first, so nothing that appears meanwhile is replaced.

All of this happens through directory handles, not path strings: the destination is opened once, and every lookup, folder creation, temp file and rename is relative to an open handle of the entry's folder (`cap-std`, `vault-core/src/destdir.rs`). A lookup that would leave the destination — including through a folder that a local attacker swaps for a link or junction mid-extraction — fails. Existing links in parent folders are refused outright. (Before M3 this was a path-based re-check with a small race window.)

When adding files, inputs are opened without following a final link (`O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`) and checked to be regular files through the open handle.

### 7.2 Plaintext hygiene

- Decrypted data is streamed into a temp file in the user-chosen destination folder, then renamed. It never goes to a system temp folder.
- "Preview" (open a file without extracting) is **not** in v1, because it requires a temp file that the app cannot reliably wipe.
- Mark-of-the-Web: if the vault itself carries a Zone.Identifier, extracted files inherit it.

### 7.3 Resource limits

- Index size, entry count, path length, and per-entry decompressed size are bounded to prevent decompression bombs. Exceeding a limit aborts extraction with a clear error.

---

## 8. Application

### 8.1 Platform and stack

- **Windows 10/11, x64.** Single executable, no runtime install.
- **Language: Rust.** Memory safety matters more than usual in a tool that parses untrusted files and holds keys.
- **GUI toolkit:** egui/eframe (OpenGL via glow), statically linked, no WebView runtime dependency. Crate `vault-gui`, binary `SecuridgeVault.exe`. Needs Rust 1.95+ (the core library and CLI keep 1.89).
- **Core library is separate from the GUI** (`vault-core` crate), with a CLI for testing and scripting.

### 8.2 Main flows

- **Create key file** → password → save → backup ×2 → verify.
- **Create vault** → drag files/folders in → select key file → password → save `.svault`.
- **Open vault** → select key file → password → file list → extract all / extract selected / add / replace / remove.
- **Change password**, **Rekey**, **Verify backup**.

The GUI implements all of these. Its key-file flow cannot be finished without two backup copies (in folders different from the original and from each other; same-drive copies are flagged) and a verification step that reads every copy back and unlocks it with the password; skipping requires ticking "I accept that if I lose this key file or forget the password, my data is gone." Change password and rekey both lead straight into the same backup flow for the resulting key file. Slow work runs on a worker thread; closing the window while a vault is being rewritten is refused.

The CLI implements the same operations as commands (`keygen`, `create`, `list`, `extract`, `add`, `remove`, `passwd`, `rekey`, `verify-key`, `info`). It cannot enforce the two-copy backup step; it prints instructions instead.

GUI limitations today: no auto-lock timer (use Lock), no right-click menu integration, and password text may linger briefly in egui's internal buffers (undo history, text layout caches) even though the app's own copies are wiped.

### 8.3 Portability

- No registry writes by default. Settings (if any) live next to the executable in `settings.toml`, and contain no secrets.
- Optional, user-triggered "Add to right-click menu" writes only to `HKCU` and has a matching "Remove" action.

---

## 9. Distribution and trust

- Source code licensed under **MIT OR Apache-2.0** (the Rust ecosystem convention; Apache-2.0 adds an explicit patent grant).
- Release binaries **code-signed**; SHA-256 checksums published with each release. **M4 status:** `.github/workflows/release.yml` builds on a tag, signs with Authenticode when a certificate is configured as a repository secret (otherwise it marks the release *unsigned*), publishes `SHA256SUMS.txt` and GitHub build-provenance attestations, and stages a **draft** release for a person to publish. No certificate is configured yet. See `docs/RELEASING.md`.
- Reproducible builds are a goal for v1.x so others can verify the binary matches the source. Release builds already strip build-machine paths (`--remap-path-prefix`) and use a deterministic PE header (`/Brepro`); bit-for-bit reproducibility has not been verified.
- Planned, not yet implemented: a self-integrity check at startup that warns if the app's signature is missing or invalid (needs signed releases first).
- An **independent security audit** is planned before v1.0 is recommended for real data. Until then, the README must state that the software is unaudited.

---

## 10. Testing

- **Known-answer tests** for every format operation, published as test vectors so other implementations can check compatibility.
- **Round-trip tests**: random file trees in → vault → extract → byte-for-byte equal.
- **Tamper tests**: flip, drop, reorder, and truncate bytes in every region; all must fail closed.
- **Fuzzing** of key-file and vault parsers (`cargo-fuzz`), run in CI.
- **Path-traversal suite** for §7.1.
- **Crash tests**: kill the process mid-write; the previous vault must still open.

Status (M3): all of the above are in place and run in CI on Windows and Linux.

- `crates/vault-core/tests/vault.rs` — round-trip, every-byte-flip, every-truncation, entry-swap, key-mismatch, rekey, password-change, overwrite-refusal, symlink and path rules.
- `test-vectors/v1/` + `tests/vectors.rs` — published known-answer vectors, checked by the library *and* by a small reference reader written only from §4 of this document.
- `fuzz/` — `cargo-fuzz` targets for the index decoder, key file parser, vault opener and path rules; `.github/workflows/fuzz.yml` runs each for 2 minutes per push and 30 minutes weekly.
- `tests/crash.rs` — kills a child process (SIGKILL / TerminateProcess) at 12 points across add, replace, remove, rekey and password change; the survivor must open, authenticate, equal the complete old or new state, and accept further changes. Not covered: power loss (the OS may reorder writes the process already issued) and creating a brand-new vault, where a crash can leave an empty placeholder file at the target name.
- `crates/vault-gui/tests/gui.rs` — headless GUI tests (egui_kittest) of the full key, backup, vault, rekey and password flows.

---

## 11. Milestones

| Milestone | Deliverable |
|---|---|
| **M0** | This design reviewed and frozen as format v1 — *done* |
| **M1** | `vault-core` + CLI: key file, vault create/list/extract/add/remove, rekey, storage warnings, tests, KDF calibration — *done* |
| **M2** | GUI for the main flows (§8.2), including enforced backup flow — *done* |
| **M3** | Test vectors, fuzzing, crash tests, full breached-password list, handle-relative extraction — *done* |
| **M4** | Code signing, release pipeline, checksums — *pipeline done; needs a signing certificate* |
| **M5** | External security audit → v1.0 |

---

## 12. Open questions

1. ~~License~~ — decided: MIT OR Apache-2.0.
2. **Crypto library:** M1 uses the RustCrypto crates (`chacha20poly1305` 0.10, `argon2` 0.5) — pure Rust, no C toolchain needed. Their audit history must be checked and recorded here before v1.0; switching to libsodium remains possible because the file format does not depend on the library.
3. ~~GUI toolkit~~ — decided: egui/eframe (§8.1).
4. ~~Breached-password list~~ — decided: SecLists xato-net 10M, 15+ characters only (§6).
7. **Code-signing certificate:** SignPath Foundation (free for open source), Azure Trusted Signing, or an OV certificate (§9, `docs/RELEASING.md`).
5. **Hiding total vault size:** optional padding to size buckets — worth the overhead?
6. **Key file on hardware tokens** (FIDO2 / smart card) as a v2 option.

---

## Appendix A. Differences from similar tools

| | Securidge Vault | Typical password-encrypted archiver |
|---|---|---|
| Factors | Key file + password, always | Password, optional key file |
| Password change | Re-encrypts key file only | Re-encrypts every archive |
| Compromise response | Rekey re-encrypts chunks without recompressing (§4.5) | Re-encrypt everything |
| Archive operations | List / extract one / add / replace without full decrypt | Often decrypt whole volume |
| Weak password | Rejected | Allowed |
