"""Tests for shared engineering contracts and infrastructure."""

from __future__ import annotations

from pathlib import Path

import pytest

from adaf_attack.core.engineering import (
    SCHEMA_VERSION,
    SessionStore,
    execute_with_controls,
    migrate_document,
    validate_finding,
)


def test_contract_migration_preserves_fields() -> None:
    result = migrate_document({"id": "F-1", "title": "Finding", "custom": True}, kind="finding")
    assert result["schema_version"] == SCHEMA_VERSION
    assert result["status"] == "open"
    assert result["custom"] is True
    assert validate_finding(result).id == "F-1"


def test_session_store_indexes_and_filters_findings(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "sessions.sqlite")
    store.index_session(
        {"session_id": "s1", "created_at": "2026-01-01T00:00:00Z", "root": str(tmp_path)},
        capability="ldap-enum",
        findings=[{"id": "F-1", "title": "High issue", "severity": "high"}],
    )
    found = store.search_findings(severity="high")
    assert found[0]["id"] == "F-1"
    assert found[0]["session_id"] == "s1"


def test_execute_with_controls_retries() -> None:
    attempts = 0

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("transient")
        return "ok"

    assert execute_with_controls(operation, retries=1) == "ok"
    assert attempts == 2


def test_execute_with_controls_rejects_invalid_settings() -> None:
    with pytest.raises(ValueError):
        execute_with_controls(lambda: None, retries=-1)
    with pytest.raises(ValueError):
        execute_with_controls(lambda: None, timeout=0)
