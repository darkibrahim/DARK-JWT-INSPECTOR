"""Central configuration and branding for DARK-JWT-INSPECTOR."""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "DARK-JWT-INSPECTOR"
VERSION = "1.0.0"
DEVELOPER = "DARK IBRAHIM"
TITLE = "Bug Bounty Hunter & Cyber Security Expert"
FACEBOOK = "https://www.facebook.com/profile.php?id=61580661413217"
GITHUB = "https://github.com/darkibrahim"
TELEGRAM = "@Hunter_1B4H14"

MIN_PYTHON = (3, 8)
MAX_TOKEN_LENGTH = 65536
MAX_RECOMMENDED_LIFETIME_DAYS = 30

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"

HMAC_ALGORITHMS = ("HS256", "HS384", "HS512")
RSA_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")
ECDSA_ALGORITHMS = ("ES256", "ES384", "ES512")
UNSUPPORTED_KNOWN_ALGORITHMS = ("EdDSA", "ES256K")

# --------------------------------------------------------------------------
# Terminal colours (plain ANSI, no third-party dependency)
# --------------------------------------------------------------------------
_color_enabled = False


def use_color(force=None):
    """Enable/disable colours. force=None -> auto-detect from the terminal."""
    global _color_enabled
    if force is not None:
        _color_enabled = bool(force)
    else:
        _color_enabled = bool(
            sys.stdout.isatty()
            and "NO_COLOR" not in os.environ
            and os.environ.get("TERM", "") != "dumb"
        )
    return _color_enabled


def _wrap(code):
    def paint(text):
        text = str(text)
        return "\033[%sm%s\033[0m" % (code, text) if _color_enabled else text

    return paint


cyan = _wrap("36")
blue = _wrap("94")
green = _wrap("32")
red = _wrap("31")
yellow = _wrap("33")
dim = _wrap("2")
bold = _wrap("1")


def identity_block():
    """Developer identity shown in banner, about screen and help."""
    return "\n".join(
        [
            "  Developer : %s" % DEVELOPER,
            "  Title     : %s" % TITLE,
            "  Facebook  : %s" % FACEBOOK,
            "  GitHub    : %s" % GITHUB,
            "  Telegram  : %s" % TELEGRAM,
        ]
    )


def banner():
    line = "=" * 64
    return "\n".join(
        [
            cyan(line),
            bold(cyan("  %s  v%s" % (APP_NAME, VERSION))),
            blue("  JWT decoder / analyzer / signature verifier"),
            green("  Offline. No root. No tokens leave this device."),
            cyan(line),
            green(identity_block()),
            cyan(line),
        ]
    )
