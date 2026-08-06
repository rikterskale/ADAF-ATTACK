"""Shared capability execution helper used by CLI and TUI.

Supports multi-credential rotation: when a CredentialSet or creds_file is
provided, each credential is probed (LDAP bind) in order and the first that
works is used for the capability run.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from adaf_attack.core.auth import describe_auth
from adaf_attack.core.creds import CredentialSet, load_credentials_json
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.paths import default_workspace_dir, normalize_path
from adaf_attack.core.registry import capability_registry
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class RunError(Exception):
    pass


def _probe_ldap(target: Target) -> bool:
    """Return True if LDAP bind succeeds with this target."""
    from adaf_attack.core.ldap_util import ldap_connect

    try:
        conn, _dn, _cfg = ldap_connect(target)
        conn.unbind()
        return True
    except Exception:  # noqa: BLE001
        return False


def _resolve_target(
    target: Target,
    *,
    creds_file: str | Path | None = None,
    credential_set: CredentialSet | None = None,
    log: Callable[[str], None] | None = None,
) -> tuple[Target, list[str]]:
    """Pick a working target, rotating through credentials when provided.

    Returns (chosen_target, attempt_log).
    """
    def _log(msg: str) -> None:
        if log:
            log(msg)

    attempts: list[str] = []

    # Build ordered candidate list
    candidates: list[Target] = []
    cs: CredentialSet | None = credential_set
    if creds_file is not None:
        cs = load_credentials_json(creds_file)
        _log(f"Loaded {len(cs)} credential(s) from {creds_file}")

    if cs and len(cs) > 0:
        for cred in cs:
            t = cred.to_target(target.dc_ip, domain=target.domain or cred.domain, ldaps=target.ldaps)
            candidates.append(t)
        # Also try the primary CLI target last if it has distinct credentials
        if target.has_credentials:
            primary_user = (target.username or "").lower()
            if not any((c.username or "").lower() == primary_user for c in candidates):
                candidates.append(target)
    else:
        candidates = [target]

    # Single candidate with no secrets → use as-is (anonymous / offline caps)
    if len(candidates) == 1 and not candidates[0].has_credentials:
        attempts.append("anonymous/no-creds (no probe)")
        return candidates[0], attempts

    # Multi-cred or single with secrets: probe LDAP
    if len(candidates) > 1 or (cs and len(cs) > 0):
        for i, cand in enumerate(candidates):
            label = cand.username or f"candidate-{i}"
            _log(f"Probing credential [{i + 1}/{len(candidates)}]: {label} ({describe_auth(cand)})")
            if _probe_ldap(cand):
                attempts.append(f"{label}: ok")
                _log(f"Credential accepted: {label}")
                return cand, attempts
            attempts.append(f"{label}: bind failed")
            _log(f"Credential failed: {label}")

        raise RunError(
            "All credentials failed LDAP bind. Attempts: " + "; ".join(attempts)
        )

    # Single credentialed target — still probe once for clearer errors
    cand = candidates[0]
    _log(f"Probing primary credential: {cand.username or 'anonymous'} ({describe_auth(cand)})")
    if cand.has_credentials and not _probe_ldap(cand):
        attempts.append(f"{cand.username}: bind failed")
        raise RunError(
            f"LDAP bind failed for {cand.username or 'target'} @ {cand.dc_ip}. "
            f"Auth mode: {describe_auth(cand)}"
        )
    attempts.append(f"{cand.username or 'anonymous'}: ok")
    return cand, attempts


def execute_capability(
    capability_id: str,
    target: Target,
    *,
    force: bool = False,
    include_secrets: bool = False,
    workspace: Path | str | None = None,
    log: Callable[[str], None] | None = None,
    creds_file: str | Path | None = None,
    credential_set: CredentialSet | None = None,
    **runner_kwargs: Any,
) -> dict[str, Any]:
    """Run a capability and return a structured result dict.

    When ``creds_file`` or ``credential_set`` is provided, credentials are
    rotated until an LDAP bind succeeds; that target is then used for the run.
    """
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

    # Resolve working credentials (rotation / failover)
    try:
        resolved_target, cred_attempts = _resolve_target(
            target,
            creds_file=creds_file,
            credential_set=credential_set,
            log=log,
        )
    except RunError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise RunError(f"Credential resolution failed: {exc}") from exc

    ws = normalize_path(workspace) if workspace else default_workspace_dir()
    session = Session(base_dir=ws)
    graph = AttackGraph()

    _log(f"Running {capability_id} against {resolved_target.domain} @ {resolved_target.dc_ip}")
    _log(f"Auth: {describe_auth(resolved_target)}")
    _log(f"Session: {session.session_id}")
    _log(f"Workspace: {session.root}")

    session.log(
        "run.start",
        capability=capability_id,
        domain=resolved_target.domain,
        dc_ip=resolved_target.dc_ip,
        username=resolved_target.username,
        auth=describe_auth(resolved_target),
        cred_attempts=cred_attempts,
    )

    try:
        result = cap.runner.run(
            resolved_target,
            session,
            graph,
            include_secrets=include_secrets,
            force=force,
            **runner_kwargs,
        )
        resolved = graph.resolve_dn_edges()
        if resolved:
            graph.save(session.path("graph.json"))
            _log(f"Resolved {resolved} MemberOf DN edges")

        interesting = graph.interesting_summary()
        session.path("interesting.json").write_text(
            __import__("json").dumps(interesting, indent=2, default=str) + "\n",
            encoding="utf-8",
            newline="\n",
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
            "auth": describe_auth(resolved_target),
            "username": resolved_target.username,
            "cred_attempts": cred_attempts,
        }
    except Exception as exc:
        session.log("run.error", capability=capability_id, error=str(exc))
        raise RunError(str(exc)) from exc
