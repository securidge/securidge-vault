# Securidge Vault

**A portable, open-source encrypted archiver for Windows that needs two keys: a key file you carry and a password you remember.**

> ⚠️ **Status: pre-alpha, design stage.** No release exists yet. The software has **not** been independently audited. Do not use it for data you cannot afford to lose.

## What it does

- Compresses files into an encrypted vault (`.svault`).
- Opens only with **both** your key file (`.svkey`) **and** your password.
- Hides file names and folder structure, not just contents.
- Runs from a single `.exe` — no installer, no admin rights.
- Lets you list, extract one file, or add files without decrypting the whole vault.
- Changes your password in seconds, without re-encrypting every vault.

## What it does not do

- **There is no recovery.** Lose the key file or forget the password, and the data is gone. Nobody — including the author — can open it. Keep at least two backups of your key file.
- It cannot protect you from malware already running on your PC while a vault is open.
- No cloud, no accounts, no telemetry, no network access.

## How it works (short version)

```
password ─Argon2id─▶ unlocks key file ─▶ master key ─▶ unlocks vault
```

Standard, well-reviewed cryptography only: XChaCha20-Poly1305 and Argon2id. Full details, threat model, and file formats are in [docs/DESIGN.md](docs/DESIGN.md).

## Roadmap

| Milestone | Status |
|---|---|
| M0 Design | In review |
| M1 Core library + CLI | Not started |
| M2 GUI | Not started |
| M3 Vault management features | Not started |
| M4 Signed releases | Not started |
| M5 External audit → v1.0 | Not started |

## Security

Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md).

## About

Part of [Securidge](https://github.com/securidge), an independent cybersecurity education project.

License: to be decided.
