# Bundled data

## `breached-15plus.txt`

Passwords of 15 to 256 characters that appear in a public breach corpus,
NFC-normalised, lower-cased and sorted. New passwords that match an entry
are rejected (DESIGN.md §6). Regenerate with `scripts/build_password_list.py`.

- Source: `Passwords/Common-Credentials/xato-net-10-million-passwords.txt`
  from [SecLists](https://github.com/danielmiessler/SecLists)
  (MIT License, Copyright (c) 2018 Daniel Miessler).
- The underlying data set of ten million passwords was compiled and
  published by Mark Burnett (2015).

The list contains no user names or other personal data, only password strings.
