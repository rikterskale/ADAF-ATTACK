from __future__ import annotations

import json

from adaf_attack.core.control_plane import package_evidence, resolve_opsec
from adaf_attack.core.session import Session


def test_opsec_profiles() -> None:
    assert resolve_opsec("stealth")["prefer_ldaps"]
    assert resolve_opsec("loud")["max_concurrency"] > 1


def test_package_redacts_and_excludes_vault(tmp_path) -> None:
    session = Session(base_dir=tmp_path)
    session.path("finding.json").write_text(json.dumps({"password": "secret", "username": "alice"}), encoding="utf-8")
    session.path("vault/secret.vault").write_bytes(b"ciphertext")
    result = package_evidence(session.root, tmp_path / "package.zip")
    assert result["file_count"] >= 1
    staged = tmp_path / "package"
    data = json.loads((staged / "finding.json").read_text(encoding="utf-8"))
    assert data["password"] == "[REDACTED]"
    assert not (staged / "vault").exists()
