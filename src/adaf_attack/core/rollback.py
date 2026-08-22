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

REVERTABLE_KINDS = {
    "acl-write",
    "acl",
    "computer-identity",
    "ldap-attribute",
    "ldap-add-value",
    "ldap-object",
    "rbcd",
    "shadow-creds",
    "shadow-credential",
    "keycred-write",
    "gpo-link",
    "template-mod",
    "gpo-sysvol",
    "local-artifact",
}

# These effects may require operator judgment or a separate product-specific
# rollback procedure, but they must still be tracked and surfaced.
ADVISORY_KINDS = {
    "coercion",
    "gpo-abuse",
    "gmsa",
    "krb-relay",
    "ntlm-challenge",
    "ntlm-hash",
    "ntlm-relay",
    "password-reset",
    "remote-exec",
    "rodc",
    "sccm-push",
    "cert-enroll",
    "certificate-enroll",
}

SUPPORTED_KINDS = REVERTABLE_KINDS | ADVISORY_KINDS


def classification_for_kind(kind: str) -> str:
    """Return whether a recorded effect has an automatic rollback handler."""
    if kind in REVERTABLE_KINDS:
        return "revertable"
    if kind in ADVISORY_KINDS:
        return "advisory"
    return "unsupported"


def validate_cleanup_entry(action: dict[str, Any]) -> None:
    """Reject unclassified cleanup entries before they enter the ledger."""
    kind = str(action.get("kind") or "")
    if classification_for_kind(kind) == "unsupported":
        raise ValueError(f"Unsupported cleanup kind: {kind or '<missing>'}")


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
    if classification_for_kind(kind) == "unsupported":
        raise ValueError(f"Unsupported rollback kind: {kind}. Supported: {sorted(SUPPORTED_KINDS)}")

    action: dict[str, Any] = {
        "kind": kind,
        "target": target,
        "status": "pending",
        "classification": classification_for_kind(kind),
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
    by_classification: dict[str, int] = {}
    for e in entries:
        status = str(e.get("status") or "unknown")
        kind = str(e.get("kind") or "unknown")
        classification = str(e.get("classification") or classification_for_kind(kind))
        by_status[status] = by_status.get(status, 0) + 1
        by_kind[kind] = by_kind.get(kind, 0) + 1
        by_classification[classification] = by_classification.get(classification, 0) + 1

    return {
        "session": str(session_dir),
        "total": len(entries),
        "pending": by_status.get("pending", 0),
        "completed": by_status.get("completed", 0),
        "failed": by_status.get("failed", 0),
        "advisory": by_classification.get("advisory", 0),
        "by_classification": by_classification,
        "by_status": by_status,
        "by_kind": by_kind,
        "entries": entries,
    }


def cleanup_dashboard(session_dir: Path) -> dict[str, Any]:
    """Return operator-facing cleanup readiness without contacting a target."""
    summary = summarize_rollbacks(session_dir)
    outstanding = summary["pending"] + summary["failed"]
    return {
        **summary,
        "rollback_readiness": "ready" if summary["pending"] else "not-required",
        "all_changes_restored": outstanding == 0,
        "status": "restored"
        if outstanding == 0
        else ("blocked" if summary["failed"] else "pending"),
        "next_action": (
            "No cleanup is outstanding."
            if outstanding == 0
            else "Run `adaf-attack cleanup --session <path> ... --force`, then recheck this dashboard."
        ),
    }
