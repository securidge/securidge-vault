# Test vectors — format v1

Known-answer vectors for the key file (`.svkey`) and vault (`.svault`)
formats in [DESIGN.md §4](../../docs/DESIGN.md). Another implementation is
compatible if it can open `vault.svault` with `key.svkey` and the password,
and get files whose SHA-256 match `vectors.json`.

| File | What |
|---|---|
| `key.svkey` | Key file. Argon2id m = 256 MiB, t = 3, p = 1 (the lowest cost the app accepts). |
| `vault.svault` | Vault with four entries: a short text file, an empty file, a file with a Korean name, and a 1 MiB + 4321 byte incompressible file whose stream has two chunks. |
| `vectors.json` | Password, intermediate values (salt, KEK), per-entry size, compressed size, modification time and SHA-256. |

Notes for implementers:

- `password` is given in **NFD** form (`e` + U+0301). Normalise it to NFC
  before Argon2id; `password_nfc_utf8_hex` is the exact byte string to hash.
- `kek_hex` is the Argon2id output. The master key is
  XChaCha20-Poly1305-open(KEK, key bytes 56..80, key bytes 80..128,
  AAD = key bytes 0..56).
- Entry streams use the STREAM construction with big-endian 32-bit counters:
  nonce = 19-byte prefix ‖ counter (u32 BE) ‖ last-chunk flag (1 byte).
- `crates/vault-core/tests/vectors.rs` contains a ~100-line reference reader
  written from the design document alone; CI runs it against these files.

Salts and nonces are random, so regenerating
(`cargo run --release -p vault-core --example gen_test_vectors -- test-vectors/v1`)
produces different but equally valid files. The committed files are the
reference and change only with a new format version.
