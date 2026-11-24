#!/usr/bin/env sh
# DARK-JWT-INSPECTOR installer
# Developer: DARK IBRAHIM | No root and no sudo are used by this script.
# The tool itself needs only Python 3.8+. 'cryptography' is optional (RSA/ECDSA).
set -u
cd "$(dirname "$0")" || exit 1

echo "== DARK-JWT-INSPECTOR installer (by DARK IBRAHIM) =="

TERMUX=0
case "${PREFIX:-}" in *com.termux*) TERMUX=1 ;; esac

PY=""
for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
    echo "[!] Python 3 was not found. Install it, then run this script again:"
    if [ "$TERMUX" = 1 ]; then echo "      pkg install python"
    elif command -v pacman >/dev/null 2>&1; then echo "      sudo pacman -S --needed python"
    else echo "      sudo apt install -y python3 python3-venv python3-pip   (inside NetHunter rootless: without sudo)"; fi
    exit 1
fi
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'; then
    echo "[!] Python 3.8 or newer is required. Found: $("$PY" --version 2>&1)"
    exit 1
fi
echo "[+] Python OK: $("$PY" --version 2>&1)"

# --system-site-packages lets the venv see 'cryptography' installed by pkg/apt/pacman.
if [ ! -x .venv/bin/python ]; then
    if "$PY" -m venv --system-site-packages .venv >/dev/null 2>&1; then
        echo "[+] Virtual environment created in .venv"
    else
        rm -rf .venv
        echo "[!] Could not create a virtual environment (python3-venv missing?)."
        echo "    Recovery: Kali/NetHunter -> apt install python3-venv   |   Arch -> pacman -S python"
        echo "    The tool still works without it:  $PY main.py --help"
    fi
fi
if [ -x .venv/bin/python ]; then VPY=.venv/bin/python; else VPY="$PY"; fi

if "$VPY" -c "import cryptography" >/dev/null 2>&1; then
    echo "[+] Optional 'cryptography' found: RSA/ECDSA verification enabled."
elif [ "$TERMUX" = 1 ]; then
    echo "[i] Optional RSA/ECDSA support: run  pkg install python-cryptography  then re-run this script."
elif [ "$VPY" = ".venv/bin/python" ] && "$VPY" -m pip install --disable-pip-version-check -q -r requirements.txt; then
    echo "[+] Installed optional 'cryptography' into .venv"
else
    echo "[i] 'cryptography' not installed (offline, no pip, or build failed)."
    echo "    HS256/HS384/HS512 and all decoding features still work. See README for RSA/ECDSA."
fi

echo "[+] Running self-test..."
if "$VPY" main.py --selftest >/dev/null 2>&1; then
    echo "[+] Self-test passed."
else
    echo "[!] Self-test reported problems. Run:  $VPY main.py --selftest   to see details."
fi

chmod +x run.sh install.sh 2>/dev/null || true
echo
echo "Done. Start with:  sh run.sh -i      (interactive)"
echo "                   sh run.sh --help"
