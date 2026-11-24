"""Header, payload, algorithm and time-claim analysis (offline, read-only)."""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, Optional

REGISTERED_CLAIMS = {
    "iss": "Issuer",
    "sub": "Subject",
    "aud": "Audience",
    "exp": "Expiration time",
    "nbf": "Not before",
    "iat": "Issued at",
    "jti": "JWT ID",
}

_ALGORITHMS = {
    "HS256": ("HMAC (symmetric)", "SHA-256", "Shared secret; whoever can verify can also forge."),
    "HS384": ("HMAC (symmetric)", "SHA-384", "Shared secret; whoever can verify can also forge."),
    "HS512": ("HMAC (symmetric)", "SHA-512", "Shared secret; whoever can verify can also forge."),
    "RS256": ("RSA PKCS#1 v1.5 (asymmetric)", "SHA-256", "Verify with the issuer's public key."),
    "RS384": ("RSA PKCS#1 v1.5 (asymmetric)", "SHA-384", "Verify with the issuer's public key."),
    "RS512": ("RSA PKCS#1 v1.5 (asymmetric)", "SHA-512", "Verify with the issuer's public key."),
    "PS256": ("RSA-PSS (asymmetric)", "SHA-256", "Verify with the issuer's public key."),
    "PS384": ("RSA-PSS (asymmetric)", "SHA-384", "Verify with the issuer's public key."),
    "PS512": ("RSA-PSS (asymmetric)", "SHA-512", "Verify with the issuer's public key."),
    "ES256": ("ECDSA P-256 (asymmetric)", "SHA-256", "Verify with the issuer's public key."),
    "ES384": ("ECDSA P-384 (asymmetric)", "SHA-384", "Verify with the issuer's public key."),
    "ES512": ("ECDSA P-521 (asymmetric)", "SHA-512", "Verify with the issuer's public key."),
}

_UNUSUAL_HEADERS = ("jku", "jwk", "x5u", "x5c", "x5t", "crit", "zip", "cty")


def _is_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _to_dt(value: float) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def humanize_seconds(seconds: float) -> str:
    total = int(abs(seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append("%dd" % days)
    if hours:
        parts.append("%dh" % hours)
    if minutes:
        parts.append("%dm" % minutes)
    if secs or not parts:
        parts.append("%ds" % secs)
    return " ".join(parts[:3])


def inspect_algorithm(alg: Any) -> Dict[str, Any]:
    """Describe the algorithm named in the header."""
    if not isinstance(alg, str) or not alg:
        return {"algorithm": alg, "known": False, "family": "missing", "safe": False,
                "note": "Header has no 'alg' value."}
    if alg.strip().lower() == "none":
        return {"algorithm": alg, "known": True, "family": "none (unsigned)", "safe": False,
                "note": "No signature at all. Must never be accepted."}
    if alg in _ALGORITHMS:
        family, digest, note = _ALGORITHMS[alg]
        return {"algorithm": alg, "known": True, "family": family, "hash": digest,
                "safe": True, "note": note}
    return {"algorithm": alg, "known": False, "family": "unknown", "safe": False,
            "note": "Unrecognised algorithm; treat with suspicion."}


def analyze_header(header: Dict[str, Any]) -> Dict[str, Any]:
    unusual = {k: header[k] for k in _UNUSUAL_HEADERS if k in header}
    return {
        "algorithm": inspect_algorithm(header.get("alg")),
        "type": header.get("typ"),
        "key_id": header.get("kid"),
        "unusual_fields": unusual,
        "all_fields": sorted(header.keys()),
    }


def analyze_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    registered = {}
    for name, label in REGISTERED_CLAIMS.items():
        if name in payload:
            registered[name] = {"label": label, "value": payload[name]}
    custom = sorted(k for k in payload if k not in REGISTERED_CLAIMS)
    aud = payload.get("aud")
    audiences = aud if isinstance(aud, list) else ([aud] if aud is not None else [])
    return {
        "registered_claims": registered,
        "missing_registered": [k for k in ("iss", "aud", "exp", "iat") if k not in payload],
        "custom_claims": custom,
        "audiences": audiences,
        "claim_count": len(payload),
    }


def _claim(payload: Dict[str, Any], name: str, now_ts: float) -> Dict[str, Any]:
    if name not in payload:
        return {"present": False}
    value = payload[name]
    if not _is_number(value):
        return {"present": True, "valid": False, "raw": value,
                "problem": "must be a number (seconds since epoch)"}
    dt = _to_dt(value)
    if dt is None:
        return {"present": True, "valid": False, "raw": value, "problem": "timestamp out of range"}
    delta = value - now_ts
    relative = ("in " if delta > 0 else "") + humanize_seconds(delta) + ("" if delta > 0 else " ago")
    return {"present": True, "valid": True, "raw": value, "iso": dt.isoformat(),
            "delta_seconds": int(delta), "relative": relative}


def analyze_time(payload: Dict[str, Any], now: Optional[datetime] = None,
                 leeway: int = 0) -> Dict[str, Any]:
    """Check exp / nbf / iat. State is one of: expired, not_yet_valid, valid, no_expiration, invalid."""
    now = now or datetime.now(timezone.utc)
    now_ts = now.timestamp()
    exp = _claim(payload, "exp", now_ts)
    nbf = _claim(payload, "nbf", now_ts)
    iat = _claim(payload, "iat", now_ts)

    state = "valid"
    if any(c.get("present") and not c.get("valid") for c in (exp, nbf, iat)):
        state = "invalid"
    elif exp.get("present") and now_ts - leeway >= exp["raw"]:
        state = "expired"
    elif nbf.get("present") and now_ts + leeway < nbf["raw"]:
        state = "not_yet_valid"
    elif not exp.get("present"):
        state = "no_expiration"

    lifetime = None
    if exp.get("valid") and iat.get("valid"):
        lifetime = int(exp["raw"] - iat["raw"])
    age = int(now_ts - iat["raw"]) if iat.get("valid") else None
    return {
        "now": now.isoformat(),
        "leeway_seconds": leeway,
        "exp": exp, "nbf": nbf, "iat": iat,
        "state": state,
        "lifetime_seconds": lifetime,
        "age_seconds": age,
    }
