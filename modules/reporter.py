"""JSON report building with redaction. Reports are saved only with explicit consent."""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
from modules.decoder import DecodedJWT
from modules.security import is_sensitive_key

REDACTED = "[REDACTED]"
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MAX_DEPTH = 8


def fingerprint(token: str) -> str:
    """Short SHA-256 fingerprint so a report can be matched to a token without containing it."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def redact_value(value: Any, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        return REDACTED
    if isinstance(value, dict):
        return {
            k: (REDACTED if is_sensitive_key(str(k)) else redact_value(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_value(v, depth + 1) for v in value]
    if isinstance(value, str) and _EMAIL_RE.match(value):
        return "[REDACTED_EMAIL]"
    return value


def build_report(
    decoded: DecodedJWT,
    header_info: Dict[str, Any],
    payload_info: Dict[str, Any],
    time_info: Dict[str, Any],
    verification,
    findings: List[Dict[str, str]],
    platform_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a redacted, JSON-serialisable report. The raw token and signature are never included."""
    return {
        "tool": {
            "name": config.APP_NAME,
            "version": config.VERSION,
            "developer": config.DEVELOPER,
            "title": config.TITLE,
            "github": config.GITHUB,
            "telegram": config.TELEGRAM,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "notice": (
            "Decoding is not verification. Claims are trustworthy only when "
            "verification.status is 'verified'. Sensitive values are redacted."
        ),
        "token": {
            "fingerprint_sha256_16": fingerprint(decoded.token),
            "length": len(decoded.token),
            "value": REDACTED,
        },
        "header": redact_value(decoded.header),
        "payload": redact_value(decoded.payload),
        "signature": {
            "present": bool(decoded.signature),
            "length_bytes": len(decoded.signature),
            "value": REDACTED,
        },
        "header_analysis": redact_value(header_info),
        "payload_analysis": {
            "missing_registered": payload_info["missing_registered"],
            "custom_claims": payload_info["custom_claims"],
            "claim_count": payload_info["claim_count"],
        },
        "time_analysis": redact_value(time_info),
        "verification": verification.to_dict(),
        "security_findings": findings,
        "environment": platform_info or {},
    }


def default_report_path(report: Dict[str, Any]) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    name = "jwt-report-%s-%s.json" % (report["token"]["fingerprint_sha256_16"][:8], stamp)
    return config.REPORTS_DIR / name


def to_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def save_report(report: Dict[str, Any], path, consent: bool = False) -> Path:
    """Write the report to disk. Refuses unless the user explicitly consented."""
    if not consent:
        raise PermissionError("Saving requires explicit user consent.")
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(to_json(report) + "\n", encoding="utf-8")
    try:
        os.chmod(str(target), 0o600)
    except OSError:
        pass  # e.g. filesystems without POSIX permissions (some Android storage)
    return target
