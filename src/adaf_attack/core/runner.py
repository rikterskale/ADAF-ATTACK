"""Shared capability execution helper used by CLI and TUI.

Supports multi-credential rotation: when a CredentialSet or creds_file is
provided, each credential is probed (LDAP bind) in order and the first that
works is used for the capability run.
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from adaf_attack.core.auth import describe_auth
from adaf_attack.core.creds import CredentialSet, load_credentials_json
from adaf_attack.core.engineering import SessionStore, execute_with_controls
from adaf_attack.core.execution_policy import (
    ExecutionRequest,
    PolicyError,
    enforce_execution_policy,
    safety_for_operation,
)
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.outcomes import build_post_execution_outcome, normalize_capability_result
from adaf_attack.core.paths import atomic_write_text, default_workspace_dir, normalize_path
from adaf_attack.core.registry import capability_registry
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

# Diagnostic logger. Configured (and made visible) by the CLI `--debug` flag
# via adaf_attack.core.engineering.configure_logging; silent otherwise.
_logger = logging.getLogger("adaf_attack.runner")


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
            t = cred.to_target(
                target.dc_ip, domain=target.domain or cred.domain, ldaps=target.ldaps
            )
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

        raise RunError("All credentials failed LDAP bind. Attempts: " + "; ".join(attempts))

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
    acknowledged: bool = False,
    approval_token: str | None = None,
    json_mode: bool = False,
    include_secrets: bool = False,
    workspace: Path | str | None = None,
    session: Session | None = None,
    graph: AttackGraph | None = None,
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

    _logger.debug("execute_capability requested: %s (force=%s)", capability_id, force)
    cap = capability_registry.get(capability_id)
    if cap is None:
        raise RunError(f"Unknown capability: {capability_id}")

    if cap.runner is None:
        raise RunError(f"Capability '{capability_id}' has no runner implemented yet.")
    runner = cap.runner

    safety_parameters = dict(runner_kwargs)
    safety_parameters["_force"] = force
    active_safety = safety_for_operation(cap, safety_parameters)
    try:
        enforce_execution_policy(
            ExecutionRequest(
                capability=cap,
                target=target,
                safety=active_safety,
                force=force,
                acknowledged=acknowledged,
                approval_token=approval_token,
            )
        )
    except PolicyError as exc:
        raise RunError(str(exc)) from exc

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
    session = session or Session(base_dir=ws)
    graph = graph or AttackGraph()

    _log(f"Running {capability_id} against {resolved_target.domain} @ {resolved_target.dc_ip}")
    _log(f"Auth: {describe_auth(resolved_target)}")
    _log(f"Session: {session.session_id}")
    _log(f"Workspace: {session.root}")
    _logger.debug(
        "running %s domain=%s dc_ip=%s session=%s cred_attempts=%d",
        capability_id,
        resolved_target.domain,
        resolved_target.dc_ip,
        session.session_id,
        len(cred_attempts),
    )

    import time as _time

    _run_start_monotonic = _time.monotonic()
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
        timeout = runner_kwargs.pop("timeout", None)
        retries = int(runner_kwargs.pop("retries", 0))

        def _run() -> dict[str, Any]:
            return runner.run(
                resolved_target,
                session,
                graph,
                include_secrets=include_secrets,
                force=force,
                **runner_kwargs,
            )

        output_context: Any = (
            contextlib.redirect_stdout(io.StringIO()) if json_mode else contextlib.nullcontext()
        )
        with output_context:
            result = execute_with_controls(
                _run,
                timeout=timeout,
                retries=retries,
                mutating=active_safety.is_mutating,
            )
        result = normalize_capability_result(result)
        resolved = graph.resolve_dn_edges()
        if resolved:
            graph.save(session.path("graph.json"))
            _log(f"Resolved {resolved} MemberOf DN edges")

        interesting = graph.interesting_summary()
        atomic_write_text(
            session.path("interesting.json"),
            __import__("json").dumps(interesting, indent=2, default=str) + "\n",
        )

        outcome = build_post_execution_outcome(
            session.root,
            capability=capability_id,
            result=result,
            graph=graph,
            auth=describe_auth(resolved_target),
        )
        atomic_write_text(
            session.path("outcome.json"),
            json.dumps(outcome, indent=2, sort_keys=True) + "\n",
        )

        session.log(
            "run.complete",
            capability=capability_id,
            ok=True,
            duration_ms=int((_time.monotonic() - _run_start_monotonic) * 1000),
        )
        try:
            metadata = json.loads(session.path("session.json").read_text(encoding="utf-8"))
            findings_path = session.path("findings.json")
            findings_doc = (
                json.loads(findings_path.read_text(encoding="utf-8"))
                if findings_path.is_file()
                else {}
            )
            findings = findings_doc.get("findings", []) if isinstance(findings_doc, dict) else []
            SessionStore(ws / "sessions.sqlite").index_session(
                metadata,
                capability=capability_id,
                findings=findings if isinstance(findings, list) else [],
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            _log(f"Session index warning: {exc}")
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
            "outcome": outcome,
        }
    except Exception as exc:
        session.log(
            "run.error",
            capability=capability_id,
            error=str(exc),
            duration_ms=int((_time.monotonic() - _run_start_monotonic) * 1000),
        )
        raise RunError(str(exc)) from exc
