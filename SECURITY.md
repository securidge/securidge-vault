# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately through GitHub: go to the **Security** tab of this repository and choose **Report a vulnerability**.

Please include:

- what you found and why it matters
- steps to reproduce, or a proof of concept
- the version or commit you tested

We aim to acknowledge reports within 7 days and to agree on a disclosure timeline with you. Credit is given in release notes unless you prefer otherwise.

## Scope

In scope:

- The cryptographic design in [docs/DESIGN.md](docs/DESIGN.md)
- The key file and vault formats and their parsers
- Anything that lets an attacker read, modify, or forge vault contents without both the key file and the password
- Extraction writing outside the chosen folder, or leaving plaintext behind

Out of scope (see the threat model in DESIGN.md §2.3):

- Attacks that require malware already running on the user's machine
- Loss of data caused by losing the key file or forgetting the password (this is by design)

## Supported versions

No release exists yet. Once releases begin, only the latest release will receive security fixes.

## Audit status

This project has **not** been independently audited. An external audit is planned before v1.0.
