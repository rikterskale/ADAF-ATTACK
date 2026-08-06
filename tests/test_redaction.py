"""Redaction tests."""

from adaf_attack.core.redaction import redact


def test_redact_sensitive_keys() -> None:
    data = {
        "username": "alice",
        "password": "SuperSecret123!",
        "ntlm": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        "nested": {"ticket": "doI..."},
    }
    redacted = redact(data)
    assert redacted["username"] == "alice"
    assert redacted["password"] == "[REDACTED]"
    assert redacted["ntlm"] == "[REDACTED]"
    assert redacted["nested"]["ticket"] == "[REDACTED]"


def test_include_secrets() -> None:
    data = {"password": "keepme"}
    assert redact(data, include_secrets=True)["password"] == "keepme"
