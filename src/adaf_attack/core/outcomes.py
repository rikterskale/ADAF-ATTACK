"""Post-execution result normalization for operator and machine consumers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from adaf_attack.core.engineering import validate_capability_result
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.paths import atomic_write_text, ensure_dir

DETECTION_STATUSES = ("detected", "not-detected", "inconclusive", "not-recorded")


def normalize_capability_result(result: Any) -> dict[str, Any]:
    """Give every capability result an explicit top-level success field."""
    if isinstance(result, dict):
        normalized = dict(result)
        nested = normalized.get("outcome")
        if "ok" in normalized:
            normalized["ok"] = bool(normalized["ok"])
        elif isinstance(nested, dict) and "ok" in nested:
            normalized["ok"] = bool(nested["ok"])
        elif isinstance(normalized.get("return_code"), int):
            normalized["ok"] = normalized["return_code"] == 0
        else:
            normalized["ok"] = "error" not in normalized
        return validate_capability_result(normalized).model_dump(exclude_none=True)
    return validate_capability_result({"ok": bool(result), "value": result}).model_dump(
        exclude_none=True
    )


def build_post_execution_outcome(
    session: Path,
    *,
    capability: str,
    result: Any,
    graph: AttackGraph,
    auth: str,
) -> dict[str, Any]:
    """Create a stable outcome document without exposing credential material."""
    normalized = normalize_capability_result(result)
    success = normalized["ok"] is True
    files = sorted(
        path.name
        for path in Path(session).iterdir()
        if path.is_file() and path.name not in {"session.json", "events.jsonl"}
    )
    cleanup = _load_cleanup(Path(session) / "cleanup.json")
    pending = sum(item.get("status", "pending") == "pending" for item in cleanup)
    failed_cleanup = sum(item.get("status") == "failed" for item in cleanup)
    graph_summary = graph.summary()
    if failed_cleanup:
        rollback_status = "failed"
    elif pending:
        rollback_status = "pending"
    elif cleanup:
        rollback_status = "verified"
    else:
        rollback_status = "not-required"
    return {
        "schema_version": 1,
        "capability": capability,
        "status": "success" if success else "partial",
        "offensive_success": success,
        "validation": {
            "status": "passed" if success else "needs-review",
            "operator_verified": False,
        },
        "rollback": {
            "status": rollback_status,
            "pending": pending,
            "registered": len(cleanup),
            "failed": failed_cleanup,
        },
        "evidence": {"captured": bool(files), "artifacts": files, "count": len(files)},
        "graph_changes": {
            "nodes_added": graph_summary["nodes"],
            "edges_added": graph_summary["edges"],
            "summary": graph_summary,
        },
        "detection": {"status": "not-recorded", "expected_telemetry": [], "operator_notes": None},
        "auth_context": auth,
    }


def _load_cleanup(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def record_detection_status(
    session: Path,
    *,
    status: str,
    notes: str | None = None,
    telemetry: list[str] | None = None,
) -> dict[str, Any]:
    """Record defensive validation separately from offensive success."""
    normalized = status.strip().lower()
    if normalized not in DETECTION_STATUSES:
        raise ValueError(f"status must be one of: {', '.join(DETECTION_STATUSES)}")
    record = {
        "status": normalized,
        "operator_notes": notes,
        "observed_telemetry": list(telemetry or []),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    session = Path(session)
    ensure_dir(session)
    atomic_write_text(
        session / "detection.json", json.dumps(record, indent=2, sort_keys=True) + "\n"
    )
    outcome_path = session / "outcome.json"
    outcome = _load_object(outcome_path)
    outcome.setdefault("schema_version", 1)
    outcome["detection"] = record
    atomic_write_text(outcome_path, json.dumps(outcome, indent=2, sort_keys=True) + "\n")
    return record


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}
