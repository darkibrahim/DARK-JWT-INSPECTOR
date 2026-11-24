# DARK-JWT-INSPECTOR v1.0.0

**JWT decoder, analyzer and signature verifier - offline, portable, no root.**

```
Developer : DARK IBRAHIM
Title     : Bug Bounty Hunter & Cyber Security Expert
Facebook  : https://www.facebook.com/profile.php?id=61580661413217
GitHub    : https://github.com/darkibrahim
Telegram  : @Hunter_1B4H14
```

Category: Cybersecurity / Application Security · License: MIT · Python 3.8+

## Features

1. JWT token decoder (strict Base64URL, duplicate-key detection)
2. Header analyzer (`jku`, `jwk`, `x5u`, `kid`, `crit` checks)
3. Payload analyzer (registered/custom claims, audiences)
4. Expiration checker (`exp`, `nbf`, optional clock-skew leeway)
5. Issued-at analysis (`iat`, token age, lifetime)
6. Algorithm inspector
7. Signature verification: HS256/HS384/HS512 (built in); RS/PS/ES 256/384/512 (needs optional `cryptography`)
8. Security configuration warnings with severity levels
9. Redacted JSON report export (only with your consent)
10. Interactive and command-line modes

## Security design

- **Decoding is not verification.** Every screen says so until a signature is verified.
- `alg: none` is **never** accepted as valid, in any capitalisation.
- Algorithm confusion is blocked: PEM keys cannot be used as HMAC secrets, and RSA/ECDSA algorithms refuse plain secrets. Pin algorithms with `--alg`.
- No secret guessing, no brute force, no network access. Tokens never leave your device.
- Nothing is written to disk unless you pass `--output` (or answer `y` in interactive mode).
- Reports contain no raw token and no signature; sensitive claims (password, email, phone, ...) are redacted.
- Prefer `--secret-env`, `--key-file` or `--prompt-secret` over typing secrets in a command (shell history).

## Installation

Requires Python 3.8+. The core needs **only the standard library**. No root is needed to run the tool.

After any install: `sh run.sh --check-env` shows what your device supports.

### A. Kali Linux
```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
sudo apt install -y python3-cryptography      # optional: RSA/ECDSA
sh install.sh
sh run.sh -i
```

### B. Kali NetHunter Rootless
Run inside the NetHunter terminal (this is not Android root).
```bash
apt update && apt install -y python3 python3-venv python3-pip git
apt install -y python3-cryptography           # optional: RSA/ECDSA
sh install.sh
sh run.sh -i
```
If `apt` reports permission errors, Python 3 is usually already present: just run `sh install.sh`.

### C. Arch Linux
```bash
sudo pacman -S --needed python python-pip git
sudo pacman -S --needed python-cryptography   # optional: RSA/ECDSA
sh install.sh
sh run.sh -i
```

### D. Termux (no sudo)
```bash
pkg update && pkg install python git
pkg install python-cryptography               # optional: RSA/ECDSA (pip would need to compile it)
sh install.sh
sh run.sh -i
```

`install.sh` creates `.venv` (with system packages visible), installs the optional dependency when possible, and runs the self-test. If something fails it prints how to recover; the tool still works with the standard library alone.

## Usage

```bash
sh run.sh -i                                   # interactive menu
sh run.sh <token>                              # decode + analyse offline
sh run.sh --token-file token.txt --secret-env JWT_SECRET --alg HS256
sh run.sh - --key-file public.pem --alg RS256 < token.txt
sh run.sh <token> --output reports/report.json # save redacted report
sh run.sh <token> --json                       # redacted JSON to stdout
sh run.sh --check-env                          # platform + dependency status
sh run.sh --selftest                           # run automated tests
```

Exit codes: `0` ok · `1` bad input · `2` verification failed/rejected (or key given but not verified).

## Testing

```bash
python3 -m unittest discover -s tests -t .
```
Covers: decoding, malformed/invalid tokens, signature verification (HS, RS, PS, ES), expired tokens, unsafe algorithms, algorithm confusion, JSON export and redaction, consent for saving, CLI exit codes, branding, platform detection. Test tokens are generated locally; no real secrets are used. RSA/ECDSA tests are skipped automatically when `cryptography` is missing.

### Platform testing status

| Environment | Status |
|---|---|
| Linux x86_64, Python 3.12 (developer sandbox) | Automated tests executed |
| Kali Linux, Kali NetHunter Rootless, Arch Linux, Termux, ARM64 | **Not yet tested on real devices** - detection logic is unit-tested with simulated inputs only |

Please report problems from your device through GitHub issues.

## Known limitations

- JWE (encrypted tokens) are detected but not decoded; only signed JWS tokens are supported.
- EdDSA / ES256K verification is not supported in v1.0.0.
- NetHunter detection is heuristic.
- RSA/ECDSA verification requires the optional `cryptography` package.

## Project structure

```
main.py  config.py  install.sh  run.sh  requirements.txt
modules/  decoder.py verifier.py analyzer.py security.py reporter.py
core/     platform_detect.py dependency_check.py
tests/    test_decoder.py test_verifier.py test_analyzer.py test_reporter.py test_platform.py
reports/  (generated reports; ignored by git)
```

Use this tool only on tokens you own or are authorised to test.

---
**DARK-JWT-INSPECTOR v1.0.0 - DEVELOPED BY DARK IBRAHIM**
