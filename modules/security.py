"""Security configuration warnings for a decoded JWT."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from config import MAX_RECOMMENDED_LIFETIME_DAYS
from modules import verifier
from modules.decoder import DecodedJWT

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

STANDARD_CLAIMS = {
    "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "auth_time", "nonce", "acr",
    "amr", "azp", "scope", "typ", "alg", "kid", "cty",
}

_WORD_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")
_SENSITIVE_WORDS = {
    "pass", "password", "passwd", "pwd", "secret", "token", "private", "credential",
    "credentials", "ssn", "card", "cvv", "otp", "email", "mail", "phone", "mobile",
    "address", "birth", "birthdate", "birthday", "dob",
}
# compounds written without separators, e.g. "accesstoken", "apikey"
_SENSITIVE_COMPOUNDS = ("apikey", "secretkey", "privatekey", "accesskey", "accesstoken",
                        "refreshtoken", "password")

_SUSPICIOUS_KID_RE = re.compile(
    r"(\.\./|\.\.\\|[\"';|`$\x00]|--|\bunion\b|\bselect\b)", re.IGNORECASE
)


def is_sensitive_key(name: str) -> bool:
    """True for claim names that look like secrets/PII. Matches whole words, not substrings."""
    if name.lower() in STANDARD_CLAIMS:
        return False
    words = [w.lower() for w in _WORD_SPLIT_RE.split(name) if w]
    if any(w in _SENSITIVE_WORDS for w in words):
        return True
    compact = "".join(words)
    return any(c in compact for c in _SENSITIVE_COMPOUNDS)


def _f(severity: str, code: str, message: str, recommendation: str = "") -> Dict[str, str]:
    return {"severity": severity, "code": code, "message": message,
            "recommendation": recommendation}


def evaluate(
    decoded: DecodedJWT,
    header_info: Dict[str, Any],
    time_info: Dict[str, Any],
    verification: Optional[verifier.VerificationResult] = None,
) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    header, payload = decoded.header, decoded.payload
    alg = header.get("alg")

    # --- algorithm -------------------------------------------------------
    if not isinstance(alg, str) or not alg:
        findings.append(_f("HIGH", "ALG_MISSING", "Header has no 'alg' value.",
                           "Reject tokens without an explicit algorithm."))
    elif alg.strip().lower() == "none":
        findings.append(_f("CRITICAL", "ALG_NONE",
                           "Algorithm is 'none': the token is unsigned and anyone can forge it.",
                           "Servers must reject 'none' and pin the expected algorithm."))
    elif not header_info["algorithm"]["known"]:
        findings.append(_f("HIGH", "ALG_UNKNOWN", "Unrecognised algorithm '%s'." % alg,
                           "Only accept a fixed allow-list of algorithms."))
    elif alg.startswith("HS"):
        findings.append(_f("INFO", "ALG_SYMMETRIC",
                           "Symmetric HMAC algorithm: verifier and issuer share one secret.",
                           "Use a long random secret and pin the algorithm to avoid algorithm confusion."))
    if isinstance(alg, str) and alg.strip().lower() != "none" and not decoded.signature:
        findings.append(_f("HIGH", "SIGNATURE_EMPTY",
                           "Signature segment is empty although alg is '%s'." % alg,
                           "Reject unsigned tokens."))

    # --- risky header fields ----------------------------------------------
    for name in ("jku", "x5u", "jwk", "x5c"):
        if name in header:
            findings.append(_f("HIGH", "HEADER_KEY_SOURCE_%s" % name.upper(),
                               "Header carries '%s': a key source chosen by the token itself." % name,
                               "Never trust keys supplied by the token; use a server-side key allow-list."))
    kid = header.get("kid")
    if isinstance(kid, str) and _SUSPICIOUS_KID_RE.search(kid):
        findings.append(_f("HIGH", "KID_SUSPICIOUS",
                           "'kid' contains characters typical of path-traversal or injection attempts.",
                           "Treat kid as untrusted input; look it up in a fixed key map, never in files/SQL."))
    if "crit" in header:
        findings.append(_f("INFO", "HEADER_CRIT",
                           "Header has 'crit' (critical extensions).",
                           "Reject the token if you do not understand every listed extension."))
    if decoded.duplicate_keys:
        findings.append(_f("MEDIUM", "DUPLICATE_KEYS",
                           "Duplicate JSON keys found: %s." % ", ".join(decoded.duplicate_keys),
                           "Different parsers may read different values; reject such tokens."))

    # --- time claims -------------------------------------------------------
    state = time_info["state"]
    exp, iat, nbf = time_info["exp"], time_info["iat"], time_info["nbf"]
    for label, claim in (("exp", exp), ("nbf", nbf), ("iat", iat)):
        if claim.get("present") and not claim.get("valid"):
            findings.append(_f("MEDIUM", "CLAIM_%s_INVALID" % label.upper(),
                               "Claim '%s' is not a valid timestamp (%s)." % (label, claim["problem"]),
                               "Reject tokens with malformed time claims."))
    if not exp.get("present"):
        findings.append(_f("MEDIUM", "NO_EXPIRATION", "Token has no 'exp' claim; it never expires.",
                           "Issue short-lived tokens with an expiration."))
    if state == "expired":
        findings.append(_f("INFO", "EXPIRED", "Token is expired (%s)." % exp.get("relative", ""),
                           "Servers must reject expired tokens."))
    if state == "not_yet_valid":
        findings.append(_f("INFO", "NOT_YET_VALID", "Token is not valid yet (nbf in the future)."))
    if iat.get("valid") and iat["delta_seconds"] > 300:
        findings.append(_f("MEDIUM", "IAT_FUTURE", "'iat' is in the future; clocks differ or token is forged."))
    lifetime = time_info.get("lifetime_seconds")
    if lifetime is not None:
        if lifetime < 0:
            findings.append(_f("MEDIUM", "EXP_BEFORE_IAT", "'exp' is earlier than 'iat'."))
        elif lifetime > MAX_RECOMMENDED_LIFETIME_DAYS * 86400:
            findings.append(_f("LOW", "LONG_LIFETIME",
                               "Token lifetime is %d days (more than %d)."
                               % (lifetime // 86400, MAX_RECOMMENDED_LIFETIME_DAYS),
                               "Use short access tokens plus refresh tokens."))

    # --- payload hygiene ---------------------------------------------------
    for name in ("iss", "aud"):
        if name not in payload:
            findings.append(_f("LOW", "NO_%s" % name.upper(),
                               "Token has no '%s' claim." % name,
                               "Validate issuer and audience to prevent token substitution."))
    sensitive = sorted(k for k in payload if is_sensitive_key(str(k)))
    if sensitive:
        findings.append(_f("HIGH", "SENSITIVE_PAYLOAD",
                           "Payload has possibly sensitive fields: %s." % ", ".join(sensitive),
                           "JWT payloads are only encoded, not encrypted. Do not store secrets in them."))

    # --- verification state --------------------------------------------------
    if verification is not None:
        if verification.status == verifier.NOT_VERIFIED:
            findings.append(_f("INFO", "NOT_VERIFIED",
                               "Signature was not verified: claims are UNTRUSTED.",
                               "Supply the secret or public key to verify."))
        elif verification.status == verifier.REJECTED:
            findings.append(_f("HIGH", "VERIFY_REJECTED", verification.message))
        elif verification.status == verifier.FAILED:
            findings.append(_f("HIGH", "VERIFY_FAILED", verification.message))
        if verification.key_length_bytes is not None and verification.verified:
            for d in verification.details:
                findings.append(_f("MEDIUM", "WEAK_KEY", d))
        elif verification.verified:
            for d in verification.details:
                findings.append(_f("LOW", "KEY_NOTE", d))

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    return findings
