#!/usr/bin/env python3
"""Builds crates/vault-core/data/breached-15plus.txt (DESIGN.md §6).

Input: SecLists Passwords/Common-Credentials/xato-net-10-million-passwords.txt
(https://github.com/danielmiessler/SecLists, MIT licence; the underlying
data set was published by Mark Burnett).

Only passwords our policy would otherwise accept matter (15 to 256
characters), so shorter ones are dropped. Entries are NFC-normalised and
lower-cased exactly as vault_core::password compares them, de-duplicated,
and sorted by UTF-8 bytes so the library can binary-search them.

Usage: python3 -I scripts/build_password_list.py <xato-net-10-million-passwords.txt>
"""
import sys
import unicodedata

MIN, MAX = 15, 256
OUT = "crates/vault-core/data/breached-15plus.txt"

seen = set()
with open(sys.argv[1], "rb") as f:
    for raw in f:
        try:
            s = raw.rstrip(b"\r\n").decode("utf-8")
        except UnicodeDecodeError:
            continue
        s = unicodedata.normalize("NFC", s).lower()
        if MIN <= len(s) <= MAX and not any(ord(c) < 32 or ord(c) == 127 for c in s):
            seen.add(s)

lines = sorted(seen, key=lambda s: s.encode("utf-8"))
with open(OUT, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(lines) + "\n")
print(f"{len(lines)} entries -> {OUT}")
