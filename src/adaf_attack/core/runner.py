"""Shared capability execution helper used by CLI and TUI."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import Capability, capability_registry
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class RunError(Exception):
    pass


def execute_capability(
    capability_id: str,
    target: Target,
    *,
    force: bool = False,
    include_secrets: bool = False,
    workspace: Path | str = "workspaces",
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run a capability and return a structured result dict."""
    import adaf_attack.capabilities  # noqa: F401

    def _log(msg: str) -> None:
        if log:
            log(msg)

    cap = capability_registry.get(capability_id)
    if cap is None:
        raise RunError(f"Unknown capability: {capability_id}")

    if cap.destructive and not force:
        raise RunError(
            f"Capability '{capability_id}' is DESTRUCTIVE. Pass force=True / --force to proceed."
        )

    if cap.runner is None:
        raise RunError(f"Capability '{capability_id}' has no runner implemented yet.")

    session = Session(base_dir=workspace)
    graph = AttackGraph()

    _log(f"Running {capability_id} against {target.domain} @ {target.dc_ip}")
    _log(f"Session: {session.session_id}")

    session.log(
        "run.start",
        capability=capability_id,
        domain=target.domain,
        dc_ip=target.dc_ip,
        username=target.username,
    )

    try:
        result = cap.runner.run(
            target,
            session,
            graph,
            include_secrets=include_secrets,
            force=force,
        )
        # Resolve DN-based edges after collection
        resolved = graph.resolve_dn_edges()
        if resolved:
            graph.save(session.path("graph.json"))
            _log(f"Resolved {resolved} MemberOf DN edges")

        interesting = graph.interesting_summary()
        (session.path("interesting.json")).write_text(
            __import__("json").dumps(interesting, indent=2, default=str)
        )

        session.log("run.complete", capability=capability_id, ok=True)
        _log(f"Session directory: {session.root}")

        return {
            "ok": True,
            "capability": capability_id,
            "session_id": session.session_id,
            "session_path": str(session.root),
            "result": result,
            "graph_summary": graph.summary(),
            "interesting": interesting,
        }
    except Exception as exc:
        session.log("run.error", capability=capability_id, error=str(exc))
        raise RunError(str(exc)) from exc
