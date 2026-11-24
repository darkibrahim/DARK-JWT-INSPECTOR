"""Signature verification.

Safety rules enforced here:
* alg "none" is never accepted as a valid verification.
* The key type must match the algorithm family (blocks algorithm confusion,
  e.g. an HS256 token "verified" with an RSA public key used as an HMAC secret).
* No secret guessing or brute forcing is performed. Only the key you supply is used.
* Nothing is sent over the network.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from config import (
    ECDSA_ALGORITHMS,
    HMAC_ALGORITHMS,
    RSA_ALGORITHMS,
    UNSUPPORTED_KNOWN_ALGORITHMS,
)
from modules.decoder import DecodedJWT

VERIFIED = "verified"
FAILED = "failed"
REJECTED = "rejected"
NOT_VERIFIED = "not_verified"

_HASHES = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}
_EC_CURVES = {"ES256": "secp256r1", "ES384": "secp384r1", "ES512": "secp521r1"}
_EC_SIG_LEN = {"ES256": 64, "ES384": 96, "ES512": 132}


@dataclass
class VerificationResult:
    status: str
    algorithm: Optional[str]
    message: str
    details: List[str] = field(default_factory=list)
    key_length_bytes: Optional[int] = None

    @property
    def verified(self) -> bool:
        return self.status == VERIFIED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "verified": self.verified,
            "algorithm": self.algorithm,
            "message": self.message,
            "details": list(self.details),
        }


def _is_pem(key: bytes) -> bool:
    return b"-----BEGIN" in key


def _result(status, alg, message, details=None, key_len=None):
    return VerificationResult(status, alg, message, list(details or []), key_len)


def verify_signature(
    decoded: DecodedJWT,
    key: Optional[bytes] = None,
    allowed_algorithms: Optional[Iterable[str]] = None,
) -> VerificationResult:
    """Verify the token signature with a user-supplied key.

    key: HMAC secret (bytes) for HS*, or a PEM public key / certificate for RS*/PS*/ES*.
    allowed_algorithms: pin the algorithms you expect (recommended).
    """
    alg = decoded.header.get("alg")
    if not isinstance(alg, str) or not alg:
        return _result(REJECTED, None, "Header has no usable 'alg' value; refusing to verify.")
    if alg.strip().lower() == "none":
        return _result(
            REJECTED,
            alg,
            "Algorithm 'none' means NO signature. It is never accepted as valid verification.",
        )
    if alg in UNSUPPORTED_KNOWN_ALGORITHMS:
        return _result(NOT_VERIFIED, alg, "Algorithm %s is not supported by this version." % alg)
    supported = HMAC_ALGORITHMS + RSA_ALGORITHMS + ECDSA_ALGORITHMS
    if alg not in supported:
        return _result(REJECTED, alg, "Unknown or unsafe algorithm '%s'; refusing to verify." % alg)
    if allowed_algorithms:
        allowed = set(allowed_algorithms)
        if alg not in allowed:
            return _result(
                REJECTED,
                alg,
                "Token algorithm %s is not in the allowed list (%s)."
                % (alg, ", ".join(sorted(allowed))),
            )
    if key is None:
        return _result(
            NOT_VERIFIED,
            alg,
            "No key supplied: token was decoded only. Its contents are NOT verified.",
        )
    if len(key) == 0:
        return _result(
            REJECTED,
            alg,
            "An empty key/secret is refused: a token 'verified' with an empty secret proves nothing.",
        )

    if alg in HMAC_ALGORITHMS:
        return _verify_hmac(decoded, alg, key)
    return _verify_asymmetric(decoded, alg, key)


def _verify_hmac(decoded: DecodedJWT, alg: str, key: bytes) -> VerificationResult:
    if _is_pem(key):
        return _result(
            REJECTED,
            alg,
            "Algorithm confusion blocked: a PEM key/certificate must not be used as an HMAC secret.",
            ["Public keys are not secrets. Pin the expected algorithm on the server."],
        )
    if not decoded.signature:
        return _result(FAILED, alg, "Signature segment is empty; token is unsigned.", key_len=len(key))
    digest = _HASHES[alg[2:]]
    expected = hmac.new(key, decoded.signing_input, digest).digest()
    key_len = len(key)
    if hmac.compare_digest(expected, decoded.signature):
        details = []
        if key_len < digest().digest_size:
            details.append(
                "Secret is shorter than the hash output (%d bytes); RFC 7518 requires at least that."
                % digest().digest_size
            )
        return _result(VERIFIED, alg, "Signature is VALID for the supplied secret.", details, key_len)
    return _result(FAILED, alg, "Signature does NOT match the supplied secret.", key_len=key_len)


def _load_public_key(pem: bytes, serialization, x509):
    if b"BEGIN CERTIFICATE" in pem:
        return x509.load_pem_x509_certificate(pem).public_key()
    if b"PRIVATE KEY" in pem:
        return serialization.load_pem_private_key(pem, password=None).public_key()
    return serialization.load_pem_public_key(pem)


def _verify_asymmetric(decoded: DecodedJWT, alg: str, key: bytes) -> VerificationResult:
    if not _is_pem(key):
        return _result(
            REJECTED,
            alg,
            "Algorithm %s needs a PEM public key or certificate, not a plain secret." % alg,
            ["Key/algorithm mismatch is blocked to prevent algorithm confusion."],
        )
    try:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    except Exception as exc:  # ImportError or broken native bindings
        return _result(
            NOT_VERIFIED,
            alg,
            "RSA/ECDSA verification unavailable: the 'cryptography' package could not be loaded.",
            ["Reason: %s" % exc, "Install it (see README) or use HS256/HS384/HS512 only."],
        )

    try:
        public_key = _load_public_key(key, serialization, x509)
    except Exception as exc:
        return _result(REJECTED, alg, "Could not load the supplied key: %s" % exc)

    hash_cls = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}[alg[2:]]
    details: List[str] = []
    try:
        if alg in RSA_ALGORITHMS:
            if not isinstance(public_key, rsa.RSAPublicKey):
                return _result(REJECTED, alg, "Key type mismatch: %s requires an RSA key." % alg)
            if public_key.key_size < 2048:
                details.append("RSA key is only %d bits; 2048+ is recommended." % public_key.key_size)
            if alg.startswith("RS"):
                pad = padding.PKCS1v15()
            else:
                pad = padding.PSS(mgf=padding.MGF1(hash_cls()), salt_length=hash_cls().digest_size)
            public_key.verify(decoded.signature, decoded.signing_input, pad, hash_cls())
        else:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return _result(REJECTED, alg, "Key type mismatch: %s requires an EC key." % alg)
            if public_key.curve.name != _EC_CURVES[alg]:
                return _result(
                    REJECTED,
                    alg,
                    "Curve mismatch: %s requires %s but key uses %s."
                    % (alg, _EC_CURVES[alg], public_key.curve.name),
                )
            sig = decoded.signature
            if len(sig) != _EC_SIG_LEN[alg]:
                return _result(FAILED, alg, "ECDSA signature has the wrong length for %s." % alg)
            half = len(sig) // 2
            der = encode_dss_signature(
                int.from_bytes(sig[:half], "big"), int.from_bytes(sig[half:], "big")
            )
            public_key.verify(der, decoded.signing_input, ec.ECDSA(hash_cls()))
    except InvalidSignature:
        return _result(FAILED, alg, "Signature does NOT match the supplied key.", details)
    except Exception as exc:
        return _result(FAILED, alg, "Verification error: %s" % exc, details)
    return _result(VERIFIED, alg, "Signature is VALID for the supplied public key.", details)
