"""Lightweight secret redaction.

By default all results are redacted. Operators can pass --include-secrets
to keep sensitive material (intended for isolated lab use only).
"""

from __future__ import annotations

from typing import Any


SENSITIVE_KEYS = {
    "password",
    "hash",
    "ntlm",
    "aes128",
    "aes256",
    "ticket",
    "kirbi",
    "pfx",
    "private_key",
    "secret",
    "cleartext",
    "credential",
}


def redact(obj: Any, include_secrets: bool = False) -> Any:
    """Recursively redact sensitive values unless include_secrets is True."""
    if include_secrets:
        return obj

    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            key_lower = str(k).lower()
            if any(s in key_lower for s in SENSITIVE_KEYS):
                out[k] = "[REDACTED]"
            else:
                out[k] = redact(v, include_secrets=False)
        return out

    if isinstance(obj, list):
        return [redact(item, include_secrets=False) for item in obj]

    return obj
