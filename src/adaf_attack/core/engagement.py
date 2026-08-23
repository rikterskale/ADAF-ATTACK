"""Engagement plans, scoped approval tokens, and phase execution."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import yaml

from adaf_attack.core.findings import findings_from_session, write_findings
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import capability_registry
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class EngagementError(ValueError):
    pass


_TARGET_OPTION_KEYS = {
    "host",
    "target",
    "target_host",
    "target_ip",
    "remote_host",
    "remote_ip",
    "dc_ip",
    "set_on",
    "set_from",
    "listener",
    "relay_target",
    "relay_targets",
    "write_target",
}
_RESERVED_PHASE_OPTIONS = {
    "force",
    "acknowledged",
    "approval_token",
    "session",
    "graph",
    "workspace",
    "include_secrets",
}


def _normalize_target(value: Any) -> str:
    return str(value).strip().lower().rstrip(".")


def parameters_digest(parameters: Mapping[str, Any]) -> str:
    """Return the canonical digest bound into scoped approvals."""
    encoded = json.dumps(dict(parameters), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_phase(phase: Any, index: int) -> dict[str, Any]:
    if not isinstance(phase, dict):
        raise EngagementError(f"Phase {index} must be a mapping")
    raw_caps = phase.get("capabilities", [])
    if not isinstance(raw_caps, list) or any(not isinstance(item, str) for item in raw_caps):
        raise EngagementError(f"Phase {index}.capabilities must be a list of strings")
    options = phase.get("options", {})
    if not isinstance(options, dict):
        raise EngagementError(f"Phase {index}.options must be a mapping")
    reserved = sorted(_RESERVED_PHASE_OPTIONS.intersection(options))
    if reserved:
        raise EngagementError(
            f"Phase {index}.options contains reserved execution fields: {', '.join(reserved)}"
        )
    return {
        "name": str(phase.get("name", "unnamed")),
        "capabilities": list(raw_caps),
        "options": dict(options),
    }


def _validate_phase_targets(options: Mapping[str, Any], allowed_targets: tuple[str, ...]) -> None:
    allowed = {_normalize_target(item) for item in allowed_targets}
    for key, raw_value in options.items():
        if key not in _TARGET_OPTION_KEYS:
            continue
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        for value in values:
            normalized = _normalize_target(value)
            if normalized and normalized not in allowed:
                raise EngagementError(
                    f"Phase option '{key}' targets '{value}', which is outside allowed_targets"
                )


def _validate_approved_parameters(parameters: Mapping[str, Any], targets: list[Any]) -> None:
    allowed = {_normalize_target(item) for item in targets}
    for key, raw_value in parameters.items():
        if key not in _TARGET_OPTION_KEYS:
            continue
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        for value in values:
            normalized = _normalize_target(value)
            if normalized and normalized not in allowed:
                raise EngagementError(
                    f"Approval token does not permit phase target '{value}' from option '{key}'"
                )


@dataclass(frozen=True)
class EngagementPlan:
    engagement_id: str
    domain: str
    dc_ip: str
    allowed_capabilities: tuple[str, ...]
    phases: tuple[dict[str, Any], ...]
    allowed_targets: tuple[str, ...]
    opsec_profile: str = "balanced"


def load_plan(path: Path) -> EngagementPlan:
    import adaf_attack.capabilities  # noqa: F401

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise EngagementError(f"Cannot load engagement YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise EngagementError("Engagement YAML root must be a mapping")
    required = ("engagement_id", "target", "allowed_capabilities", "phases")
    missing = [key for key in required if key not in raw]
    if missing:
        raise EngagementError(f"Missing required keys: {', '.join(missing)}")
    target = raw["target"] or {}
    if not isinstance(target, dict):
        raise EngagementError("target must be a mapping")
    if not target.get("domain") or not target.get("dc_ip"):
        raise EngagementError("target.domain and target.dc_ip are required")
    if not isinstance(raw["allowed_capabilities"], list) or any(
        not isinstance(item, str) for item in raw["allowed_capabilities"]
    ):
        raise EngagementError("allowed_capabilities must be a list of strings")
    caps = tuple(str(item) for item in raw["allowed_capabilities"])
    invalid = [item for item in caps if capability_registry.get(item) is None]
    if invalid:
        raise EngagementError(f"Unknown allowed capabilities: {', '.join(invalid)}")
    if not isinstance(raw["phases"], list):
        raise EngagementError("phases must be a list")
    phases = tuple(_validate_phase(phase, index) for index, phase in enumerate(raw["phases"]))
    for phase in phases:
        invalid_phase_caps = [item for item in phase["capabilities"] if item not in caps]
        if invalid_phase_caps:
            raise EngagementError(
                "Phase capabilities are not allowed by engagement scope: "
                + ", ".join(invalid_phase_caps)
            )
    allowed_targets_raw = raw.get("allowed_targets", [target["dc_ip"]])
    if not isinstance(allowed_targets_raw, list) or any(
        not isinstance(item, str) for item in allowed_targets_raw
    ):
        raise EngagementError("allowed_targets must be a list of strings")
    allowed_targets = tuple(str(x) for x in allowed_targets_raw)
    for phase in phases:
        _validate_phase_targets(phase["options"], allowed_targets)
    from adaf_attack.core.control_plane import resolve_opsec

    profile = str(raw.get("opsec_profile", "balanced"))
    resolve_opsec(profile)
    return EngagementPlan(
        str(raw["engagement_id"]),
        str(target["domain"]),
        str(target["dc_ip"]),
        caps,
        phases,
        allowed_targets,
        profile,
    )


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def verify_scoped_approval(
    token: str,
    *,
    engagement_id: str,
    dc_ip: str,
    capability: str,
    parameters: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify an HMAC-signed approval scoped to one campaign and target.

    The service and CLI share a rotation-managed verification key in this
    minimal deployment. Production deployments should replace this with
    asymmetric JWKS.
    """
    env_name = os.environ.get("ADAF_ATTACK_ENV", "").strip().lower()
    if env_name in ("prod", "production"):
        ack = os.environ.get("ADAF_APPROVAL_HMAC_ACKNOWLEDGE_PROD", "").strip()
        if ack not in ("1", "true", "yes"):
            raise EngagementError(
                "APPROVAL_VERIFIER_INSECURE: the built-in HMAC verifier is not permitted "
                "when ADAF_ATTACK_ENV=prod. Deploy an asymmetric JWKS verifier or set "
                "ADAF_APPROVAL_HMAC_ACKNOWLEDGE_PROD=1 to accept the shared-secret verifier."
            )
    key = os.environ.get("ADAF_APPROVAL_HMAC_KEY")
    if not key:
        raise EngagementError("ADAF_APPROVAL_HMAC_KEY is required for approval verification")
    try:
        encoded, signature = token.split(".", 1)
        expected = _b64(hmac.new(key.encode(), encoded.encode(), hashlib.sha256).digest())
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    except Exception as exc:  # noqa: BLE001
        raise EngagementError("Invalid approval token format") from exc
    if not isinstance(payload, dict) or not hmac.compare_digest(expected, signature):
        raise EngagementError("Approval token signature is invalid")
    capabilities = payload.get("capabilities", [])
    targets = payload.get("targets", [])
    if not isinstance(capabilities, list) or not isinstance(targets, list):
        raise EngagementError("Approval token scope fields are malformed")
    if payload.get("engagement_id") != engagement_id or capability not in capabilities:
        raise EngagementError("Approval token scope does not match the requested action")
    if _normalize_target(dc_ip) not in {_normalize_target(item) for item in targets}:
        raise EngagementError("Approval token does not permit this target")
    if parameters:
        _validate_approved_parameters(parameters, targets)
        expected_digest = parameters_digest(parameters)
        if payload.get("parameters_sha256") != expected_digest:
            raise EngagementError("Approval token does not match the requested parameters")
    try:
        expires_at = int(payload.get("exp", 0))
    except (TypeError, ValueError) as exc:
        raise EngagementError("Approval token expiry is malformed") from exc
    if expires_at <= int(datetime.now(UTC).timestamp()):
        raise EngagementError("Approval token has expired")
    return cast(dict[str, Any], payload)


def verify_approval(token: str, plan: EngagementPlan, capability: str) -> dict[str, Any]:
    """Verify an approval against an engagement plan."""
    return verify_scoped_approval(
        token,
        engagement_id=plan.engagement_id,
        dc_ip=plan.dc_ip,
        capability=capability,
    )


def run_engagement(
    plan: EngagementPlan,
    *,
    workspace: Path,
    username: str | None = None,
    password: str | None = None,
    approval_token: str | None = None,
    ccache: str | None = None,
) -> dict[str, Any]:
    import adaf_attack.capabilities  # noqa: F401

    if _normalize_target(plan.dc_ip) not in {
        _normalize_target(item) for item in plan.allowed_targets
    }:
        raise EngagementError("The domain controller is not in allowed_targets")
    session = Session(base_dir=workspace)
    target = Target(
        domain=plan.domain,
        dc_ip=plan.dc_ip,
        username=username,
        password=password,
        ccache=ccache,
        use_kerberos=bool(ccache),
    )
    graph = AttackGraph()
    from adaf_attack.core.control_plane import resolve_opsec

    opsec = resolve_opsec(plan.opsec_profile)
    session.log(
        "engagement.start",
        engagement_id=plan.engagement_id,
        allowed_capabilities=list(plan.allowed_capabilities),
        target=plan.dc_ip,
        opsec=opsec,
    )
    complete: list[str] = []
    from adaf_attack.core.runner import RunError, execute_capability

    for phase in plan.phases:
        name = str(phase.get("name", "unnamed"))
        for capability in phase.get("capabilities", []):
            capability = str(capability)
            if capability not in plan.allowed_capabilities:
                raise EngagementError(f"{capability} is not allowed by engagement scope")
            cap = capability_registry.get(capability)
            if cap is None or cap.runner is None:
                raise EngagementError(f"Capability unavailable: {capability}")
            options = phase.get("options", {})
            if not isinstance(options, dict):
                raise EngagementError(f"Phase '{name}' options must be a mapping")
            _validate_phase_targets(options, plan.allowed_targets)
            from adaf_attack.core.execution_policy import safety_for_operation

            requires_approval = safety_for_operation(
                cap, {**options, "_force": False}
            ).requires_force
            force = False
            if requires_approval:
                if not approval_token:
                    raise EngagementError(
                        f"Approval token required for approved capability: {capability}"
                    )
                approval = verify_scoped_approval(
                    approval_token,
                    engagement_id=plan.engagement_id,
                    dc_ip=plan.dc_ip,
                    capability=capability,
                    parameters=options,
                )
                session.log(
                    "approval.accepted",
                    approval_id=approval.get("approval_id"),
                    capability=capability,
                    approver=approval.get("approved_by"),
                )
                force = True
            session.log("phase.start", phase=name, capability=capability)
            try:
                execute_capability(
                    capability,
                    target,
                    force=force,
                    acknowledged=True,
                    approval_token=approval_token,
                    include_secrets=False,
                    workspace=workspace,
                    session=session,
                    graph=graph,
                    opsec=opsec,
                    **options,
                )
            except RunError as exc:
                raise EngagementError(f"Phase '{name}' failed: {exc}") from exc
            session.log("phase.complete", phase=name, capability=capability)
            complete.append(capability)
    graph.resolve_dn_edges()
    graph.save(session.path("graph.json"))
    findings = findings_from_session(session.root)
    findings_path = write_findings(session.root, findings)
    session.log(
        "engagement.complete",
        engagement_id=plan.engagement_id,
        capabilities=complete,
        findings=len(findings),
        findings_path=str(findings_path),
    )
    return {
        "engagement_id": plan.engagement_id,
        "session_path": str(session.root),
        "capabilities": complete,
        "finding_count": len(findings),
        "findings_path": str(findings_path),
    }
