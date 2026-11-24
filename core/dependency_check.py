"""Graceful dependency checks. The core tool needs only the Python standard library."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List


@dataclass
class DependencyStatus:
    name: str
    required: bool
    available: bool
    version: str
    note: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def check_cryptography() -> DependencyStatus:
    try:
        import cryptography  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: F401

        version = getattr(cryptography, "__version__", "unknown")
        return DependencyStatus("cryptography", False, True, version,
                                "RSA / RSA-PSS / ECDSA verification available.")
    except Exception as exc:  # ImportError or broken native extension
        return DependencyStatus(
            "cryptography", False, False, "",
            "Not usable (%s). HS256/HS384/HS512 still work; RSA/ECDSA verification disabled." % exc,
        )


def check_dependencies() -> List[DependencyStatus]:
    stdlib = DependencyStatus("python-stdlib", True, True, "", "Decoding, analysis, HMAC verification, reports.")
    return [stdlib, check_cryptography()]


def feature_matrix(deps: List[DependencyStatus]) -> Dict[str, Dict[str, Any]]:
    crypto = next((d for d in deps if d.name == "cryptography"), None)
    asym = bool(crypto and crypto.available)
    note = "" if asym else "needs the optional 'cryptography' package"
    return {
        "Offline decoding": {"available": True, "note": ""},
        "HS256/HS384/HS512 verification": {"available": True, "note": ""},
        "RS256/RS384/RS512 verification": {"available": asym, "note": note},
        "PS256/PS384/PS512 verification": {"available": asym, "note": note},
        "ES256/ES384/ES512 verification": {"available": asym, "note": note},
        "JSON report export": {"available": True, "note": ""},
    }
