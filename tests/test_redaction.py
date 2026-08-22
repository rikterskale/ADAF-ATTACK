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


def test_redact_secret_value_under_nonsensitive_key() -> None:
    # A secret that lands in a field whose key is NOT sensitive must still be
    # redacted by value-pattern matching.
    data = {
        "note": "recovered $krb5tgs$23$*svc$CORP$HTTP/app*$aa$bb from the host",
        "stdout": "user:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
        "summary": "nothing sensitive here",
    }
    redacted = redact(data)
    assert redacted["note"] == "[REDACTED]"
    assert redacted["stdout"] == "[REDACTED]"
    assert redacted["summary"] == "nothing sensitive here"


def test_redact_secret_value_in_list_and_nested() -> None:
    data = {"lines": ["clean line", "-----BEGIN RSA PRIVATE KEY-----MIIE"]}
    redacted = redact(data)
    assert redacted["lines"][0] == "clean line"
    assert redacted["lines"][1] == "[REDACTED]"


def test_value_redaction_preserves_sha256_digests() -> None:
    # Evidence manifests carry SHA-256 (64 hex) digests; these must survive.
    digest = "a" * 64
    data = {"artifact": "report.html", "sha256": digest, "path": "reports/report.html"}
    redacted = redact(data)
    assert redacted["sha256"] == digest


def test_value_redaction_catches_cloud_tokens() -> None:
    data = {"env": "AKIAABCDEFGHIJKLMNOP", "vcs": "ghp_" + "a" * 30}
    redacted = redact(data)
    assert redacted["env"] == "[REDACTED]"
    assert redacted["vcs"] == "[REDACTED]"
