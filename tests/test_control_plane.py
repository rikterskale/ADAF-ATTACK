from __future__ import annotations

import json

import pytest

from adaf_attack.core.control_plane import package_evidence, resolve_opsec
from adaf_attack.core.session import Session


def test_opsec_profiles() -> None:
    assert resolve_opsec("stealth")["prefer_ldaps"]
    assert resolve_opsec("loud")["max_concurrency"] > 1


def test_package_redacts_and_excludes_vault(tmp_path) -> None:
    session = Session(base_dir=tmp_path)
    session.path("finding.json").write_text(
        json.dumps({"password": "secret", "username": "alice"}), encoding="utf-8"
    )
    session.path("vault/secret.vault").write_bytes(b"ciphertext")
    result = package_evidence(session.root, tmp_path / "package.zip")
    assert result["file_count"] >= 1
    staged = tmp_path / "package"
    data = json.loads((staged / "finding.json").read_text(encoding="utf-8"))
    assert data["password"] == "[REDACTED]"
    assert not (staged / "vault").exists()


def test_package_redacts_jsonl_and_excludes_secret_files(tmp_path) -> None:
    session = Session(base_dir=tmp_path)
    session.path("events.jsonl").write_text(
        json.dumps({"type": "result", "password": "secret"}) + "\n", encoding="utf-8"
    )
    session.path("capture.pfx").write_bytes(b"private")
    session.path("raw.log").write_text("password=secret", encoding="utf-8")
    session.path("broken.jsonl").write_text("not-json\n", encoding="utf-8")
    session.path("credential-inventory.json").write_text(
        json.dumps({"password": "secret", "count": 1}), encoding="utf-8"
    )
    package_evidence(session.root, tmp_path / "safe.zip")
    staged = tmp_path / "safe"
    assert json.loads((staged / "events.jsonl").read_text())["password"] == "[REDACTED]"
    assert not (staged / "capture.pfx").exists()
    assert not (staged / "raw.log").exists()
    assert not (staged / "broken.jsonl").exists()
    assert (staged / "credential-inventory.json").exists()


def test_package_rejects_output_inside_session(tmp_path) -> None:
    session = Session(base_dir=tmp_path)
    with pytest.raises(ValueError, match="outside the source session"):
        package_evidence(session.root, session.root / "package.zip")
    with pytest.raises(ValueError, match="overwrite the source session"):
        package_evidence(session.root, session.root)


def test_session_rejects_escape_paths_and_reserved_event_fields(tmp_path) -> None:
    session = Session(base_dir=tmp_path)
    with pytest.raises(ValueError, match="inside the session root"):
        session.path("..", "escape.txt")
    with pytest.raises(ValueError, match="reserved audit fields"):
        session.log("test", type="spoofed")
    with pytest.raises(ValueError, match="event_type must be non-empty"):
        session.log("   ")
    session.log("test", value="ok")
    event = json.loads((session.root / "events.jsonl").read_text().splitlines()[-1])
    assert event["type"] == "test"
