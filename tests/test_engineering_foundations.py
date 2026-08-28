"""Tests for shared engineering contracts and infrastructure."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from adaf_attack.core import engineering
from adaf_attack.core.engineering import (
    SCHEMA_VERSION,
    SessionStore,
    distribution_closure,
    execute_with_controls,
    migrate_document,
    relevant_pip_failures,
    validate_finding,
)


def test_contract_migration_preserves_fields() -> None:
    result = migrate_document({"id": "F-1", "title": "Finding", "custom": True}, kind="finding")
    assert result["schema_version"] == SCHEMA_VERSION
    assert result["status"] == "open"
    assert result["custom"] is True
    assert validate_finding(result).id == "F-1"


def test_distribution_closure_and_pip_failure_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    class Distribution:
        def __init__(self, requires: list[str] | None) -> None:
            self.requires = requires

    installed = {
        "adaf-attack": Distribution(["Typer==0.27.1", "Rich>=15"]),
        "typer": Distribution([]),
        "rich": Distribution(None),
    }

    def resolve(name: str) -> Distribution:
        try:
            return installed[name]
        except KeyError as exc:
            raise engineering.PackageNotFoundError(name) from exc

    monkeypatch.setattr(engineering, "distribution", resolve)
    assert distribution_closure() == {"adaf-attack", "typer", "rich"}
    output = "\n".join(
        (
            "unrelated-tool 1.0 has requirement typer==1, but you have typer 2.",
            "adaf-attack 0.10.1 has requirement rich==15, but you have rich 14.",
        )
    )
    assert relevant_pip_failures(output, {"adaf-attack", "typer", "rich"}) == [
        "adaf-attack 0.10.1 has requirement rich==15, but you have rich 14."
    ]


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


def test_migrate_document_rejects_newer_schema() -> None:
    with pytest.raises(ValueError, match="schema version"):
        migrate_document({"schema_version": SCHEMA_VERSION + 1}, kind="session")


def test_session_store_search_filters_and_limit(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "sessions.sqlite")
    base = {"created_at": "2026-01-01T00:00:00Z", "root": str(tmp_path)}
    store.index_session(
        {**base, "session_id": "s1"},
        capability="ldap-enum",
        findings=[
            {"id": "F-1", "title": "Open high", "severity": "high", "status": "open"},
            {"id": "F-2", "title": "Done low", "severity": "low", "status": "remediated"},
        ],
    )
    store.index_session(
        {**base, "session_id": "s2"},
        capability="kerberoast",
        findings=[{"id": "F-3", "title": "Done high", "severity": "high", "status": "remediated"}],
    )
    assert [f["id"] for f in store.search_findings(status="remediated")] == ["F-3", "F-2"]
    assert [f["id"] for f in store.search_findings(severity="high", status="open")] == ["F-1"]
    assert len(store.search_findings(limit=1)) == 1
    assert store.search_findings(severity="critical") == []


def test_json_log_formatter_includes_structured_fields() -> None:
    import logging

    from adaf_attack.core.engineering import JsonLogFormatter

    formatter = JsonLogFormatter()
    record = logging.LogRecord("adaf_attack.test", logging.INFO, __file__, 1, "hello", None, None)
    record.event = "cap.complete"  # type: ignore[attr-defined]
    record.capability = "ldap-enum"  # type: ignore[attr-defined]
    payload = json.loads(formatter.format(record))
    assert payload["message"] == "hello"
    assert payload["event"] == "cap.complete"
    assert payload["capability"] == "ldap-enum"
    assert "session_id" not in payload


def test_configure_logging_is_idempotent() -> None:
    import logging

    from adaf_attack.core.engineering import configure_logging

    # Isolate from global logger state: other tests (and the CLI `--debug`
    # flag) may have already attached handlers to the shared "adaf_attack"
    # logger, and pytest injects its own capture handlers. Clear them so this
    # test verifies exactly what it claims: configure_logging adds one handler
    # and is idempotent on repeat calls.
    package_logger = logging.getLogger("adaf_attack")
    saved = package_logger.handlers[:]
    package_logger.handlers.clear()
    try:
        logger = configure_logging(level=logging.DEBUG, stream=None)
        again = configure_logging(level=logging.DEBUG, stream=None)
        assert logger is again
        assert len(logger.handlers) == 1
    finally:
        package_logger.handlers[:] = saved


def test_execute_with_controls_timeout_and_exhaustion() -> None:
    with pytest.raises(TimeoutError, match="timeout"):
        execute_with_controls(lambda: time.sleep(5), timeout=0.05, retries=1, backoff=0.0)

    def always_fails() -> None:
        raise RuntimeError("nope")

    with pytest.raises(RuntimeError, match="nope"):
        execute_with_controls(always_fails, retries=2, backoff=0.0)

    assert execute_with_controls(lambda: "fast", timeout=5.0) == "fast"


def test_diagnostics_snapshot_and_plugin_discovery(tmp_path: Path) -> None:
    from adaf_attack.core.engineering import diagnostics_snapshot, discover_plugins

    snapshot = diagnostics_snapshot(package_version="0.0.0", workspace=tmp_path)
    assert snapshot["package_version"] == "0.0.0"
    assert snapshot["workspace"] == tmp_path.name
    assert snapshot["workspace_exists"] is True
    assert isinstance(snapshot["plugins"], list)
    assert isinstance(discover_plugins(), list)


def test_migrate_document_session_kind_and_unknown_kind() -> None:
    session_doc = migrate_document({"session_id": "s1"}, kind="session")
    assert session_doc["tool"] == "adaf-attack"
    unknown = migrate_document({"a": 1}, kind="other")
    assert unknown["schema_version"] == SCHEMA_VERSION
