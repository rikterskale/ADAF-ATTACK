"""Post-execution result normalization for operator and machine consumers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.graph import AttackGraph


def build_post_execution_outcome(
    session: Path,
    *,
    capability: str,
    result: Any,
    graph: AttackGraph,
    auth: str,
) -> dict[str, Any]:
    """Create a stable outcome document without exposing credential material."""
    success = isinstance(result, dict) and result.get("ok", True) is True
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
