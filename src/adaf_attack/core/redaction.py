"""Lightweight secret redaction.

By default all results are redacted. Operators can pass --include-secrets
to keep sensitive material out of ordinary operator output.

Redaction works on two independent layers:

* **Key-name redaction** - a value whose *key* names a sensitive concept
  (``password``, ``hash``, ``ticket``, ...) is replaced wholesale.
* **Value-pattern redaction** - a string *value* that matches a
  high-confidence secret shape (Kerberos hashcat blobs, ``LM:NT`` hash
  pairs, PEM private keys, cloud/VCS tokens) is replaced even when it lands
  in an unstructured field such as ``notes``, ``stdout``, or a free-text log
  line. This closes the gap where a secret leaks through a field whose key is
  not itself sensitive.

The value patterns are intentionally high-confidence only. In particular a
bare 64-character hex string is *not* treated as a secret because evidence
manifests legitimately carry SHA-256 digests in that shape.
"""

from __future__ import annotations

import re
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
    "plaintext",
    "decrypted_password",
    "recovered_secret",
}


PROFILES: dict[str, set[str]] = {
    "operator": SENSITIVE_KEYS,
    "purple": SENSITIVE_KEYS | {"path", "dn_binary"},
    "client": SENSITIVE_KEYS | {"path", "dn", "sid", "username", "principal"},
}

REDACTED = "[REDACTED]"

# High-confidence secret value shapes. Each entry is matched against string
# values regardless of the key they appear under. Keep these specific: a
# false positive silently drops legitimate evidence, and a pattern that is
# too broad (e.g. bare 64-hex) collides with SHA-256 artifact digests.
_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Kerberos hashcat material: $krb5tgs$, $krb5asrep$, $krb5pa$, $krb5$
    re.compile(r"\$krb5(?:tgs|asrep|pa)?\$", re.IGNORECASE),
    # PEM private key blocks (any flavour).
    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    # LM:NT hash pair (pwdump / secretsdump style), optionally with a leading
    # principal such as ``user:1001:aad3b4..:31d6cf..:::``.
    re.compile(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b"),
    # GPP cpassword is AES-encrypted then base64; the decrypted marker.
    re.compile(r"\bcpassword\s*[:=]", re.IGNORECASE),
    # Explicit password assignments leaked into free-text log/message fields.
    re.compile(r"\bpassword\s*[:=]\s*\S+", re.IGNORECASE),
    # Cloud / VCS access tokens (mirrors the CI secret scan).
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
)


def _value_is_secret(value: str) -> bool:
    """Return True when a string value matches a high-confidence secret shape."""
    return any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS)


def redact(obj: Any, include_secrets: bool = False, profile: str = "operator") -> Any:
    """Recursively redact sensitive values unless include_secrets is True."""
    if include_secrets:
        return obj

    sensitive = PROFILES.get(profile)
    if sensitive is None:
        raise ValueError(f"Unknown redaction profile: {profile}")
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            key_lower = str(k).lower()
            if any(s in key_lower for s in sensitive):
                out[k] = REDACTED
            else:
                out[k] = redact(v, include_secrets=False, profile=profile)
        return out

    if isinstance(obj, list):
        return [redact(item, include_secrets=False, profile=profile) for item in obj]

    if isinstance(obj, str) and _value_is_secret(obj):
        return REDACTED

    return obj
