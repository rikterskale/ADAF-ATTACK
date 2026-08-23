"""Shared engineering primitives: contracts, persistence, logging, plugins, and controls.

These helpers are deliberately transport-agnostic so the CLI, TUI, tests, and
future integrations can use the same contracts without importing each other's
presentation code.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import closing
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path
from threading import Lock
from typing import Any, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from adaf_attack.core.paths import ensure_dir

SCHEMA_VERSION = 2
PLUGIN_GROUP = "adaf_attack.capabilities"
_PLUGIN_STATUS: list[dict[str, str]] = []


class SessionContract(BaseModel):
    """Stable persisted session metadata contract."""

    model_config = ConfigDict(extra="allow")
    schema_version: int = SCHEMA_VERSION
    session_id: str
    created_at: str
    tool: str = "adaf-attack"
    root: str | None = None


class FindingContract(BaseModel):
    """Stable finding contract shared by reports and integrations."""

    model_config = ConfigDict(extra="allow")
    id: str
    title: str
    severity: str = "unknown"
    status: str = "open"
    tags: list[str] = Field(default_factory=list)
    evidence: list[Any] = Field(default_factory=list)


class RunResultContract(BaseModel):
    """Minimum contract every capability run result must satisfy."""

    model_config = ConfigDict(extra="allow")
    ok: bool
    capability: str
    session_id: str
    session_path: str


class CapabilityResultContract(BaseModel):
    """Normalized boundary contract returned by every capability runner."""

    model_config = ConfigDict(extra="allow")
    ok: bool
    error: str | None = None


def validate_capability_result(document: Mapping[str, Any]) -> CapabilityResultContract:
    """Validate the explicit success/failure field at the runner boundary."""
    return CapabilityResultContract.model_validate(document)


def validate_session(document: Mapping[str, Any]) -> SessionContract:
    """Validate session metadata while allowing forward-compatible fields."""
    return SessionContract.model_validate(document)


def validate_finding(document: Mapping[str, Any]) -> FindingContract:
    """Validate and normalize one finding document."""
    normalized = dict(document)
    normalized.setdefault(
        "id", normalized.get("finding_id") or normalized.get("title") or "finding"
    )
    normalized.setdefault("title", normalized.get("name") or normalized["id"])
    return FindingContract.model_validate(normalized)


def migrate_document(document: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
    """Upgrade known persisted documents without deleting unknown fields."""
    result = dict(document)
    current = int(result.get("schema_version", 1))
    if current > SCHEMA_VERSION:
        raise ValueError(f"Unsupported {kind} schema version: {current}")
    if kind == "session":
        result.setdefault("tool", "adaf-attack")
    elif kind == "finding":
        result.setdefault("status", "open")
        result.setdefault("tags", [])
        result.setdefault("evidence", [])
    result["schema_version"] = SCHEMA_VERSION
    return result


class SessionStore:
    """Small SQLite index over completed sessions for fast history queries."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path).expanduser()
        ensure_dir(self.path.parent)
        self._lock = Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as db, db:
            db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    root TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    capability TEXT,
                    schema_version INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings (
                    session_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    document TEXT NOT NULL,
                    PRIMARY KEY (session_id, finding_id),
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                );
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
                """
            )

    def index_session(
        self,
        metadata: Mapping[str, Any],
        *,
        capability: str | None = None,
        findings: Iterable[Mapping[str, Any]] = (),
    ) -> None:
        session = validate_session(migrate_document(metadata, kind="session"))
        with self._lock, closing(self._connect()) as db, db:
            db.execute(
                """
                INSERT INTO sessions(session_id, root, created_at, capability, schema_version)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    root = excluded.root,
                    created_at = excluded.created_at,
                    capability = excluded.capability,
                    schema_version = excluded.schema_version
                """,
                (
                    session.session_id,
                    session.root or "",
                    session.created_at,
                    capability,
                    session.schema_version,
                ),
            )
            for raw in findings:
                finding = validate_finding(migrate_document(raw, kind="finding"))
                db.execute(
                    "INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        session.session_id,
                        finding.id,
                        finding.title,
                        finding.severity,
                        finding.status,
                        finding.model_dump_json(),
                    ),
                )

    def search_findings(
        self, *, severity: str | None = None, status: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with closing(self._connect()) as db, db:
            rows = db.execute(
                # nosec B608 - `where` is composed only from a fixed allowlist of
                # column names ("severity", "status"); all values bind through
                # the parameter tuple below.
                f"SELECT session_id, finding_id, title, severity, status, document FROM findings {where} ORDER BY rowid DESC LIMIT ?",  # nosec B608
                (*params, max(1, min(limit, 1000))),
            ).fetchall()
        return [
            json.loads(str(row["document"])) | {"session_id": row["session_id"]} for row in rows
        ]


class JsonLogFormatter(logging.Formatter):
    """Compact structured logger with safe, predictable fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("event", "session_id", "capability", "correlation_id"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        return json.dumps(payload, sort_keys=True)


def configure_logging(*, level: int = logging.INFO, stream: Any = None) -> logging.Logger:
    """Configure the package logger once and return it."""
    logger = logging.getLogger("adaf_attack")
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
        logger.propagate = False
    return logger


T = TypeVar("T")


def execute_with_controls(
    operation: Callable[[], T],
    *,
    timeout: float | None = None,
    retries: int = 0,
    backoff: float = 0.25,
    mutating: bool = False,
) -> T:
    """Run an operation with bounded controls.

    Mutating operations are deliberately single-shot: a thread timeout cannot
    stop the underlying network call and a retry can duplicate a directory
    change.  Callers must use an operation-specific cancellation/rollback
    strategy for those cases instead of this generic wrapper.
    """
    if retries < 0 or (timeout is not None and timeout <= 0):
        raise ValueError("retries must be non-negative and timeout must be positive")
    if mutating and (retries or timeout is not None):
        raise ValueError("timeouts and retries are not permitted for mutating operations")
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            if timeout is None:
                return operation()
            pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="adaf-run")
            future = pool.submit(operation)
            try:
                return future.result(timeout=timeout)
            finally:
                # A running Python thread cannot be force-killed; avoid making
                # the caller wait for it after the bounded wait has expired.
                pool.shutdown(wait=False, cancel_futures=True)
        except FutureTimeoutError:
            last_error = TimeoutError(f"operation exceeded {timeout:.1f}s timeout")
        except Exception as exc:
            last_error = exc
        if attempt < retries:
            time.sleep(backoff * (2**attempt))
    assert last_error is not None
    raise last_error


@dataclass(frozen=True)
class PluginDescriptor:
    """Metadata for a discovered third-party capability plugin."""

    name: str
    value: str
    loader: Callable[[], Any]


def diagnostics_snapshot(*, package_version: str, workspace: Path) -> dict[str, Any]:
    """Return a redaction-safe diagnostics snapshot for support bundles."""
    import platform
    import sys

    return {
        "schema_version": SCHEMA_VERSION,
        "package_version": package_version,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "workspace": workspace.name or "workspace",
        "workspace_exists": workspace.exists(),
        "plugins": _PLUGIN_STATUS
        or [{"name": item.name, "value": item.value} for item in discover_plugins()],
        "implementation": sys.implementation.name,
    }


def discover_plugins() -> list[PluginDescriptor]:
    """Discover optional plugins through the standard package entry-point API."""
    discovered = entry_points()
    selected = (
        discovered.select(group=PLUGIN_GROUP)
        if hasattr(discovered, "select")
        else discovered.get(PLUGIN_GROUP, ())
    )
    return [PluginDescriptor(item.name, item.value, item.load) for item in selected]


def load_plugins() -> list[dict[str, str]]:
    """Load discovered plugins with per-plugin failure isolation.

    Entry points may register capabilities as an import side effect or expose
    a zero-argument registration function.  A broken optional plugin is
    reported, not allowed to prevent built-in capabilities from loading.
    """
    global _PLUGIN_STATUS
    statuses: list[dict[str, str]] = []
    for descriptor in discover_plugins():
        try:
            loaded = descriptor.loader()
            if callable(loaded) and not hasattr(loaded, "__path__"):
                loaded()
            statuses.append(
                {"name": descriptor.name, "value": descriptor.value, "status": "loaded"}
            )
        except Exception as exc:
            statuses.append(
                {
                    "name": descriptor.name,
                    "value": descriptor.value,
                    "status": "failed",
                    "error": str(exc)[:240],
                }
            )
    _PLUGIN_STATUS = statuses
    return list(statuses)
