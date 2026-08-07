"""Engagement plans, scoped approval tokens, and phase execution."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
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
    required = ("engagement_id", "target", "allowed_capabilities", "phases")
    missing = [key for key in required if key not in raw]
    if missing:
        raise EngagementError(f"Missing required keys: {', '.join(missing)}")
    target = raw["target"] or {}
    if not target.get("domain") or not target.get("dc_ip"):
        raise EngagementError("target.domain and target.dc_ip are required")
    caps = tuple(str(item) for item in raw["allowed_capabilities"])
    invalid = [item for item in caps if capability_registry.get(item) is None]
    if invalid:
        raise EngagementError(f"Unknown allowed capabilities: {', '.join(invalid)}")
    from adaf_attack.core.control_plane import resolve_opsec

    profile = str(raw.get("opsec_profile", "balanced"))
    resolve_opsec(profile)
    return EngagementPlan(
        str(raw["engagement_id"]),
        str(target["domain"]),
        str(target["dc_ip"]),
        caps,
        tuple(raw["phases"]),
        tuple(str(x) for x in raw.get("allowed_targets", [target["dc_ip"]])),
        profile,
    )


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def verify_approval(token: str, plan: EngagementPlan, capability: str) -> dict[str, Any]:
    """Verify HMAC-signed approval issued by an internal service.

    The service and CLI share a rotation-managed verification key in this minimal
    deployment. Production deployments should replace this with asymmetric JWKS.
    """
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
    if payload.get("engagement_id") != plan.engagement_id or capability not in payload.get(
        "capabilities", []
    ):
        raise EngagementError("Approval token scope does not match the requested action")
    if plan.dc_ip not in payload.get("targets", []):
        raise EngagementError("Approval token does not permit this target")
    if int(payload.get("exp", 0)) <= int(datetime.now(UTC).timestamp()):
        raise EngagementError("Approval token has expired")
    return cast(dict[str, Any], payload)


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

    if plan.dc_ip not in plan.allowed_targets:
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
    for phase in plan.phases:
        name = str(phase.get("name", "unnamed"))
        for capability in phase.get("capabilities", []):
            capability = str(capability)
            if capability not in plan.allowed_capabilities:
                raise EngagementError(f"{capability} is not allowed by engagement scope")
            cap = capability_registry.get(capability)
            if cap is None or cap.runner is None:
                raise EngagementError(f"Capability unavailable: {capability}")
            force = False
            if cap.destructive:
                if not approval_token:
                    raise EngagementError(
                        f"Approval token required for destructive capability: {capability}"
                    )
                approval = verify_approval(approval_token, plan, capability)
                session.log(
                    "approval.accepted",
                    approval_id=approval.get("approval_id"),
                    capability=capability,
                    approver=approval.get("approved_by"),
                )
                force = True
            session.log("phase.start", phase=name, capability=capability)
            cap.runner.run(
                target,
                session,
                graph,
                force=force,
                include_secrets=False,
                opsec=opsec,
                **dict(phase.get("options", {})),
            )
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
