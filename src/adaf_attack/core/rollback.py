"""Destructive-action rollback registry.

Records pre-change state for any capability that modifies the directory and
exposes a unified, force-gated rollback path.  Builds on the existing
session.register_cleanup / cleanup.execute_cleanup mechanism.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from adaf_attack.core.session import Session

SUPPORTED_KINDS = {
    "acl-write",
    "rbcd",
    "shadow-creds",
    "template-mod",
    "gpo-abuse",
    "gpo-sysvol",
    "ntlm-relay",
    "rodc",
    "gmsa",
    "certificate-enroll",
    "local-artifact",
}


def record_pre_state(
    session: Session,
    *,
    kind: str,
    target: str,
    attribute: str | None = None,
    previous: Any = None,
    previous_hex: str | None = None,
    artifact: str | Path | None = None,
    host: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record enough state to reverse a destructive change later.

    Returns the registered cleanup entry.
    """
    if kind not in SUPPORTED_KINDS:
        raise ValueError(f"Unsupported rollback kind: {kind}. Supported: {sorted(SUPPORTED_KINDS)}")

    action: dict[str, Any] = {
        "kind": kind,
        "target": target,
        "status": "pending",
        "registered_at": datetime.now(UTC).isoformat(),
    }
    if attribute is not None:
        action["attribute"] = attribute
    if previous is not None:
        action["previous"] = previous
    if previous_hex is not None:
        action["previous_hex"] = previous_hex
    if artifact is not None:
        action["artifact"] = str(artifact)
    if host is not None:
        action["host"] = host
    if extra:
        action.update(extra)

    session.register_cleanup(action)
    return action


def list_pending(session_dir: Path) -> list[dict[str, Any]]:
    """Return all pending rollback entries for a session."""
    path = session_dir / "cleanup.json"
    if not path.is_file():
        return []
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [e for e in entries if e.get("status") == "pending"]


def summarize_rollbacks(session_dir: Path) -> dict[str, Any]:
    """Human/JSON friendly summary of rollback state."""
    path = session_dir / "cleanup.json"
    entries: list[dict[str, Any]] = []
    if path.is_file():
        try:
            entries = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            entries = []

    by_status: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    for e in entries:
        status = str(e.get("status") or "unknown")
        kind = str(e.get("kind") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
        by_kind[kind] = by_kind.get(kind, 0) + 1

    return {
        "session": str(session_dir),
        "total": len(entries),
        "pending": by_status.get("pending", 0),
        "completed": by_status.get("completed", 0),
        "failed": by_status.get("failed", 0),
        "by_status": by_status,
        "by_kind": by_kind,
        "entries": entries,
    }
