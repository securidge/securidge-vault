# Securidge Vault

**A portable, open-source encrypted archiver for Windows that needs two keys: a key file you carry and a password you remember.**

> ⚠️ **Status: pre-alpha (M1 — command-line core).** No official release yet, and the software has **not** been independently audited. Do not use it for data you cannot afford to lose.

## What it does

- Compresses files into an encrypted vault (`.svault`).
- Opens only with **both** your key file (`.svkey`) **and** your password.
- Hides file names and folder structure, not just contents.
- Runs from a single `.exe` — no installer, no admin rights.
- Lets you list, extract one file, add, replace, or remove files.
- Changes your password in seconds, without re-encrypting every vault.

## What it does not do

- **There is no recovery.** Lose the key file or forget the password, and the data is gone. Nobody — including the author — can open it. Keep at least two backups of your key file.
- It cannot protect you from malware already running on your PC while a vault is open.
- No cloud, no accounts, no telemetry, no network access.

## Quick start (command line)

```text
securidge-vault keygen --out E:\me.svkey                  # E: = a USB drive
securidge-vault verify-key --key F:\backup\me.svkey       # check each backup copy

securidge-vault create  photos.svault --key E:\me.svkey  C:\Users\me\Pictures\2026
securidge-vault list    photos.svault --key E:\me.svkey
securidge-vault extract photos.svault --key E:\me.svkey --dest C:\restore
securidge-vault extract photos.svault --key E:\me.svkey --dest C:\restore 2026/trip.jpg

securidge-vault add     photos.svault --key E:\me.svkey  new.jpg
securidge-vault add     photos.svault --key E:\me.svkey  --replace new.jpg
securidge-vault remove  photos.svault --key E:\me.svkey  2026/old.jpg

securidge-vault passwd  --key E:\me.svkey                 # new password, same key
securidge-vault rekey   --key E:\me.svkey --new-key E:\me2.svkey photos.svault
securidge-vault info    photos.svault                     # which key it needs
```

Passwords must be at least 15 characters; a few random words work well. Unlocking a key file takes a few seconds on purpose — that is what makes guessing passwords expensive.

**Change password vs. rekey:** `passwd` only re-encrypts the key file, so *old copies* of the key file still open with the *old* password. If you think the old password or a key file copy leaked, use `rekey`.

## How it works (short version)

```
password ─Argon2id (1 GiB)─▶ unlocks key file ─▶ master key ─▶ unlocks vault
```

XChaCha20-Poly1305 for all encryption, Argon2id for the password, Zstandard compression. Full details, threat model, and byte-level file formats: [docs/DESIGN.md](docs/DESIGN.md).

## Building

Requires Rust 1.80+.

```text
cargo test
cargo build --release -p vault-cli      # -> target/release/securidge-vault(.exe)
```

Every push is built and tested on Windows and Linux by GitHub Actions; the unsigned Windows binary is available as a workflow artifact.

## Project layout

| Path | What |
|---|---|
| `crates/vault-core` | Library: key files, vault format, cryptography, path safety |
| `crates/vault-cli` | `securidge-vault` command-line tool |
| `docs/DESIGN.md` | Design, threat model, file formats |

## Roadmap

| Milestone | Status |
|---|---|
| M0 Design | Done |
| M1 Core library + CLI | Done |
| M2 GUI | Next |
| M3 Test vectors, fuzzing, crash tests | Planned |
| M4 Signed releases | Planned |
| M5 External audit → v1.0 | Planned |

## Security

Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.

## About

Part of [Securidge](https://github.com/securidge), an independent cybersecurity education project.
