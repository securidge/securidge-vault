# Securidge Vault — Design Document

| | |
|---|---|
| Status | Draft v0.2 — format v1 implemented in `vault-core` (M1) |
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
| Memory hygiene | Zeroize secrets after use | Keys, passwords, decrypted index. |

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

**Crash safety.** Writes go to `<name>.svault.tmp`, are synced, then renamed over the original. A crash leaves the previous vault intact. A leftover `.tmp` file contains only ciphertext.

**Limitations of format v1.**
- An attacker who can replace the whole file can substitute an *older copy of the same vault* (e.g., from a backup). Detecting this would require state outside the file.
- Empty folders are not stored.
- If extraction fails part-way (e.g., tampering detected in the third file), the failing file is deleted but files already extracted remain. They are authentic, because every chunk is authenticated before it is written.

### 4.5 Password change vs. rekey

These are different operations, and the UI must not blur them.

- **Change password.** Decrypt MK with the old KEK, re-encrypt it with a new KEK (new salt). Only the key file changes; takes seconds. **Limitation:** any *old copy* of the key file still opens with the *old* password. If the old password may be compromised, password change alone is not enough.
- **Rekey (compromise response).** Generate a new MK and `key_id`, write the new key file first, then rewrite `key_id`, `fek_nonce` and `fek_wrapped` of every selected vault. Each vault is fully verified (index decrypted) before its header is replaced. Only headers change; vault data is not re-encrypted, so this is still fast. Old key file copies become useless for rekeyed vaults. The user must then destroy old key file copies and back up the new one.
- **Limitation:** rekey does not change the FEK. Someone who already extracted a vault's FEK (which requires the old key file *and* old password) and keeps a copy of the vault can still read that copy. Rekey protects against future use of a leaked key, not against data already taken.

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
- Rejected if found in a **bundled offline list of common and breached passwords** (no network lookup). Target list size ≤ 5 MB compressed. **M1 status:** only a small built-in list plus repetition checks; the full list is still open (§12, question 4).
- A strength meter and a passphrase generator (random words) are provided.

---

## 7. Extraction and file-system safety

### 7.1 Path safety

On extraction, every entry path is normalized and rejected if it:

- is absolute, has a drive letter, or is a UNC path
- contains `..` that escapes the destination
- uses reserved Windows names (`CON`, `NUL`, `COM1`, …) or alternate data streams (`:`)
- resolves through a symlink or junction outside the destination

### 7.2 Plaintext hygiene

- Decrypted data is streamed directly to the user-chosen destination. No plaintext temp files.
- "Preview" (open a file without extracting) is **not** in v1, because it requires a temp file that the app cannot reliably wipe.
- Mark-of-the-Web: if the vault itself carries a Zone.Identifier, extracted files inherit it.

### 7.3 Resource limits

- Index size, entry count, path length, and per-entry decompressed size are bounded to prevent decompression bombs. Exceeding a limit aborts extraction with a clear error.

---

## 8. Application

### 8.1 Platform and stack

- **Windows 10/11, x64.** Single executable, no runtime install.
- **Language: Rust.** Memory safety matters more than usual in a tool that parses untrusted files and holds keys.
- **GUI toolkit:** to be decided in M2 (candidates: egui, Slint). Requirement: statically linked, no WebView runtime dependency.
- **Core library is separate from the GUI** (`vault-core` crate), with a CLI for testing and scripting.

### 8.2 Main flows

- **Create key file** → password → save → backup ×2 → verify.
- **Create vault** → drag files/folders in → select key file → password → save `.svault`.
- **Open vault** → select key file → password → file list → extract all / extract selected / add / replace / remove.
- **Change password**, **Rekey**, **Verify backup**.

The M1 CLI implements all of these as commands (`keygen`, `create`, `list`, `extract`, `add`, `remove`, `passwd`, `rekey`, `verify-key`, `info`). The CLI cannot enforce the two-copy backup step; it prints instructions instead. The GUI (M2) will enforce it.

### 8.3 Portability

- No registry writes by default. Settings (if any) live next to the executable in `settings.toml`, and contain no secrets.
- Optional, user-triggered "Add to right-click menu" writes only to `HKCU` and has a matching "Remove" action.

---

## 9. Distribution and trust

- Source code licensed under **MIT OR Apache-2.0** (the Rust ecosystem convention; Apache-2.0 adds an explicit patent grant).
- Release binaries **code-signed**; SHA-256 checksums published with each release.
- Reproducible builds are a goal for v1.x so others can verify the binary matches the source.
- The app performs a self-integrity check at startup and warns if its signature is missing or invalid.
- An **independent security audit** is planned before v1.0 is recommended for real data. Until then, the README must state that the software is unaudited.

---

## 10. Testing

- **Known-answer tests** for every format operation, published as test vectors so other implementations can check compatibility.
- **Round-trip tests**: random file trees in → vault → extract → byte-for-byte equal.
- **Tamper tests**: flip, drop, reorder, and truncate bytes in every region; all must fail closed.
- **Fuzzing** of key-file and vault parsers (`cargo-fuzz`), run in CI.
- **Path-traversal suite** for §7.1.
- **Crash tests**: kill the process mid-write; the previous vault must still open.

M1 status: round-trip, every-byte-flip, every-truncation, entry-swap, key-mismatch, rekey, password-change, overwrite-refusal, symlink and path-rule tests are in `crates/vault-core/tests/` and run in CI on Windows and Linux. Not yet done: published test vectors, `cargo-fuzz` targets (only a basic random-input test for the index decoder exists), kill-mid-write crash tests.

---

## 11. Milestones

| Milestone | Deliverable |
|---|---|
| **M0** | This design reviewed and frozen as format v1 — *done* |
| **M1** | `vault-core` + CLI: key file, vault create/list/extract/add/remove, rekey, storage warnings, tests, KDF calibration — *done* |
| **M2** | GUI for the main flows (§8.2), including enforced backup flow |
| **M3** | Test vectors, fuzzing, crash tests, full breached-password list |
| **M4** | Code signing, release pipeline, checksums |
| **M5** | External security audit → v1.0 |

---

## 12. Open questions

1. ~~License~~ — decided: MIT OR Apache-2.0.
2. **Crypto library:** M1 uses the RustCrypto crates (`chacha20poly1305` 0.10, `argon2` 0.5) — pure Rust, no C toolchain needed. Their audit history must be checked and recorded here before v1.0; switching to libsodium remains possible because the file format does not depend on the library.
3. **GUI toolkit:** egui vs. Slint (§8.1).
4. **Breached-password list:** source, licensing, and size (§6).
5. **Hiding total vault size:** optional padding to size buckets — worth the overhead?
6. **Key file on hardware tokens** (FIDO2 / smart card) as a v2 option.

---

## Appendix A. Differences from similar tools

| | Securidge Vault | Typical password-encrypted archiver |
|---|---|---|
| Factors | Key file + password, always | Password, optional key file |
| Password change | Re-encrypts key file only | Re-encrypts every archive |
| Compromise response | Rekey rewrites headers only (see §4.5 limitation) | Re-encrypt everything |
| Archive operations | List / extract one / add / replace without full decrypt | Often decrypt whole volume |
| Weak password | Rejected | Allowed |
