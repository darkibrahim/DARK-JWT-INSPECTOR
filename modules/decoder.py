"""JWT decoding. Decoding is NOT verification: nothing here proves authenticity."""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from config import MAX_TOKEN_LENGTH

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class JWTDecodeError(ValueError):
    """Raised when a token is malformed and cannot be decoded."""


@dataclass
class DecodedJWT:
    token: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: bytes
    signing_input: bytes
    header_b64: str
    payload_b64: str
    signature_b64: str
    duplicate_keys: List[str] = field(default_factory=list)


def b64url_decode(segment: str, what: str = "segment") -> bytes:
    """Strict Base64URL decoder (padding optional)."""
    if not isinstance(segment, str):
        raise JWTDecodeError("%s must be text." % what)
    segment = segment.rstrip("=")
    if not _B64URL_RE.match(segment):
        raise JWTDecodeError("%s contains characters that are not valid Base64URL." % what)
    if len(segment) % 4 == 1:
        raise JWTDecodeError("%s has an invalid Base64URL length." % what)
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise JWTDecodeError("%s is not valid Base64URL: %s" % (what, exc))


def _parse_json_object(raw: bytes, what: str) -> Tuple[Dict[str, Any], List[str]]:
    duplicates: List[str] = []

    def hook(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                duplicates.append(key)
            result[key] = value
        return result

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise JWTDecodeError("%s is not valid UTF-8." % what)
    try:
        obj = json.loads(text, object_pairs_hook=hook)
    except (ValueError, RecursionError):
        raise JWTDecodeError("%s is not valid JSON." % what)
    if not isinstance(obj, dict):
        raise JWTDecodeError("%s must be a JSON object." % what)
    return obj, duplicates


def decode_token(token: str) -> DecodedJWT:
    """Decode a compact JWS token (header.payload.signature) without trusting it."""
    if not isinstance(token, str):
        raise JWTDecodeError("Token must be text.")
    text = token.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    if text.lower().startswith("bearer "):
        text = text[7:].strip()
    if not text:
        raise JWTDecodeError("Token is empty.")
    if len(text) > MAX_TOKEN_LENGTH:
        raise JWTDecodeError("Token is larger than %d characters." % MAX_TOKEN_LENGTH)
    if any(ch.isspace() for ch in text):
        raise JWTDecodeError("Token contains whitespace; paste it as one single line.")

    parts = text.split(".")
    if len(parts) == 5:
        raise JWTDecodeError(
            "This looks like an encrypted JWE token (5 segments). "
            "Only signed JWS tokens (3 segments) can be decoded."
        )
    if len(parts) != 3:
        raise JWTDecodeError(
            "A JWT must have exactly 3 dot-separated segments; found %d." % len(parts)
        )
    header_b64, payload_b64, signature_b64 = parts
    if not header_b64 or not payload_b64:
        raise JWTDecodeError("Header and payload segments must not be empty.")

    header, dup_h = _parse_json_object(b64url_decode(header_b64, "Header"), "Header")
    payload, dup_p = _parse_json_object(b64url_decode(payload_b64, "Payload"), "Payload")
    signature = b64url_decode(signature_b64, "Signature") if signature_b64 else b""

    return DecodedJWT(
        token=text,
        header=header,
        payload=payload,
        signature=signature,
        signing_input=("%s.%s" % (header_b64, payload_b64)).encode("ascii"),
        header_b64=header_b64,
        payload_b64=payload_b64,
        signature_b64=signature_b64,
        duplicate_keys=sorted(set(dup_h + dup_p)),
    )
