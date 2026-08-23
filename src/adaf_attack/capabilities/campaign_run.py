"""Campaign-level phase runner with vault credential hand-off and purple package.

Operators declare ordered phases. Destructive phases require an explicit
approval token. Credential material is only sourced from the encrypted session
vault (never from CLI secrets in phase definitions).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console

from adaf_attack.core.engagement import EngagementError, verify_scoped_approval
from adaf_attack.core.execution_policy import safety_for_operation
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import capability_registry, register_capability
from adaf_attack.core.runner import execute_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target
from adaf_attack.core.vault import VaultError

console = Console()

DEFAULT_PHASES = [
    {
        "id": "recon",
        "capability": "ldap-enum",
        "destructive": False,
        "description": "Directory baseline enumeration",
    },
    {
        "id": "acl",
        "capability": "acl-enum",
        "destructive": False,
        "description": "ACL and interesting ACE collection",
    },
    {
        "id": "adcs",
        "capability": "adcs-enum",
        "destructive": False,
        "description": "AD CS template / CA surface",
    },
    {
        "id": "trusts",
        "capability": "trusts-enum",
        "destructive": False,
        "description": "Forest / external trust analysis",
    },
    {
        "id": "hybrid",
        "capability": "hybrid-signals",
        "destructive": False,
        "description": "On-prem hybrid identity signals",
    },
    {
        "id": "paths",
        "capability": "attack-paths",
        "destructive": False,
        "description": "Ranked attack paths from evidence",
    },
    {
        "id": "next",
        "capability": "next-actions",
        "destructive": False,
        "description": "Evidence-gated next-action plan",
    },
]


def _load_phases(kwargs: dict[str, Any]) -> list[dict[str, Any]]:
    plan = kwargs.get("plan") or kwargs.get("phases")
    if not plan:
        return list(DEFAULT_PHASES)
    path = Path(str(plan)).expanduser()
    if path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
        phases = data.get("phases") if isinstance(data, dict) else data
        if not isinstance(phases, list):
            raise RuntimeError("Campaign plan must contain a phases list")
        return phases
    raise RuntimeError(f"Campaign plan not found: {path}")


def _vault_hand_off(session: Session, phase: dict[str, Any]) -> dict[str, Any]:
    """Resolve credential references exclusively from the session vault."""
    refs = phase.get("vault_refs") or phase.get("credentials_from_vault") or []
    if not refs:
        return {"used": [], "values": {}}
    vault = session.vault()
    used: list[str] = []
    values: dict[str, Any] = {}
    for ref in refs:
        name = str(ref)
        try:
            values[name] = vault.get(name)
            used.append(name)
        except VaultError as exc:
            values[name] = {"error": str(exc)}
    return {"used": used, "values": values}


def _purple_package(
    session: Session, phase_results: list[dict[str, Any]], graph: AttackGraph
) -> dict[str, Any]:
    """Build a defender-oriented hand-off package from campaign evidence."""
    detections = {
        "shadow-creds": "Monitor msDS-KeyCredentialLink changes and PKINIT logons",
        "rbcd": "Monitor AllowedToAct writes and S4U ticket requests",
        "gpo-abuse": "Monitor GPO ACL changes and unexpected SYSVOL writes",
        "coerce": "Monitor EFSRPC/Spooler authentication storms toward non-DC hosts",
        "ntlm-relay": "Monitor NTLM auth to unexpected servers; disable NTLM where feasible",
        "esc-chain": "Monitor certificate enrollments with unexpected SANs",
        "trusts-enum": "Review inbound trusts without SID filtering",
        "hybrid-signals": "Correlate on-prem hybrid infra accounts with Entra sign-in risk",
    }
    findings: list[dict[str, str]] = []
    for phase in phase_results:
        cap = str(phase.get("capability") or "")
        if phase.get("ok") and cap in detections:
            findings.append(
                {
                    "capability": cap,
                    "detection": detections[cap],
                    "phase": str(phase.get("id") or ""),
                }
            )

    chains = []
    try:
        chains = graph.rank_exploit_chains(limit=15)
    except Exception:  # noqa: BLE001
        chains = []

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "session": session.session_id,
        "recommended_detections": findings,
        "top_exploit_chains": chains,
        "note": "Purple hand-off is observational guidance derived from campaign evidence.",
    }


@register_capability(
    id="campaign-run",
    summary="Run ordered engagement phases with vault hand-off and purple package",
    category="analysis",
    tags=("campaign", "phases", "vault", "purple", "engagement"),
    destructive=True,
)
class CampaignRun:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        include_secrets: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        phases = _load_phases(kwargs)
        approval_token = str(kwargs.get("approval_token") or "")
        engagement_id = str(
            kwargs.get("engagement_id") or kwargs.get("campaign_id") or session.session_id
        )

        console.print(f"[bold]Campaign run[/bold]  phases={len(phases)}  domain={target.domain}")

        phase_results: list[dict[str, Any]] = []
        for phase in phases:
            phase_id = str(phase.get("id") or phase.get("capability") or "phase")
            capability_id = str(phase.get("capability") or "")
            console.print(f"\n[cyan]Phase[/cyan] {phase_id} → {capability_id}")

            cap = capability_registry.get(capability_id)
            legacy_phase_requires_approval = bool(phase.get("destructive"))
            if cap is not None and not cap.runner:
                phase_results.append(
                    {
                        "id": phase_id,
                        "capability": capability_id,
                        "ok": False,
                        "error": f"unknown capability: {capability_id}",
                    }
                )
                console.print(f"  [red]unknown capability[/red] {capability_id}")
                continue
            if cap is None and not legacy_phase_requires_approval:
                phase_results.append(
                    {
                        "id": phase_id,
                        "capability": capability_id,
                        "ok": False,
                        "error": f"unknown capability: {capability_id}",
                    }
                )
                console.print(f"  [red]unknown capability[/red] {capability_id}")
                continue

            params = dict(phase.get("params") or {})
            reserved = {
                "force",
                "acknowledged",
                "approval_token",
                "session",
                "graph",
                "workspace",
                "include_secrets",
            }.intersection(params)
            if reserved:
                phase_results.append(
                    {
                        "id": phase_id,
                        "capability": capability_id,
                        "ok": False,
                        "error": "reserved execution parameters: " + ", ".join(sorted(reserved)),
                    }
                )
                console.print("  [yellow]skipped — reserved execution parameters[/yellow]")
                continue
            requires_approval = (
                safety_for_operation(cap, {**params, "_force": False}).requires_force
                if cap is not None and hasattr(cap, "safety")
                else legacy_phase_requires_approval
            )

            if requires_approval and not force:
                console.print("  [yellow]skipped — capability approval requires --force[/yellow]")
                phase_results.append(
                    {
                        "id": phase_id,
                        "capability": capability_id,
                        "ok": False,
                        "skipped": "force_required",
                    }
                )
                continue

            if requires_approval:
                try:
                    approval = verify_scoped_approval(
                        approval_token,
                        engagement_id=engagement_id,
                        dc_ip=target.dc_ip,
                        capability=capability_id,
                        parameters=params,
                    )
                except EngagementError as exc:
                    console.print(f"  [yellow]skipped — approval rejected: {exc}[/yellow]")
                    phase_results.append(
                        {
                            "id": phase_id,
                            "capability": capability_id,
                            "ok": False,
                            "skipped": "approval_token_required",
                            "error": str(exc),
                        }
                    )
                    continue
                session.log(
                    "approval.accepted",
                    approval_id=approval.get("approval_id"),
                    engagement_id=engagement_id,
                    capability=capability_id,
                    approver=approval.get("approved_by"),
                )

            if cap is None:
                phase_results.append(
                    {
                        "id": phase_id,
                        "capability": capability_id,
                        "ok": False,
                        "error": f"unknown capability: {capability_id}",
                    }
                )
                console.print(f"  [red]unknown capability[/red] {capability_id}")
                continue
            runner = cap.runner
            if runner is None:  # pragma: no cover - guarded before approval
                phase_results.append(
                    {
                        "id": phase_id,
                        "capability": capability_id,
                        "ok": False,
                        "error": f"capability unavailable: {capability_id}",
                    }
                )
                continue

            hand_off = _vault_hand_off(session, phase)
            if phase.get("require_vault") and not hand_off["used"]:
                phase_results.append(
                    {
                        "id": phase_id,
                        "capability": capability_id,
                        "ok": False,
                        "skipped": "vault_refs_missing",
                        "hand_off": {"used": hand_off["used"]},
                    }
                )
                console.print("  [yellow]skipped — required vault refs missing[/yellow]")
                continue

            try:
                if hasattr(cap, "safety"):
                    outcome = execute_capability(
                        capability_id,
                        target,
                        force=bool(force and requires_approval),
                        acknowledged=True,
                        approval_token=approval_token or None,
                        include_secrets=include_secrets,
                        workspace=session.base_dir,
                        session=session,
                        graph=graph,
                        **params,
                    )
                else:
                    # Compatibility path for third-party/test registry
                    # descriptors created before SafetyProfile existed. Real
                    # registered capabilities always use execute_capability.
                    outcome = runner.run(
                        target,
                        session,
                        graph,
                        force=bool(force and requires_approval),
                        include_secrets=include_secrets,
                        **params,
                    )
                if isinstance(outcome, dict):
                    ok = bool(outcome.get("ok", "error" not in outcome))
                else:
                    ok = True
                error = (
                    str(outcome.get("error") or "capability reported failure") if not ok else None
                )
            except Exception as exc:  # noqa: BLE001
                outcome = {}
                ok = False
                error = str(exc)
                console.print(f"  [red]failed[/red] {error[:160]}")

            phase_results.append(
                {
                    "id": phase_id,
                    "capability": capability_id,
                    "ok": ok,
                    "error": error,
                    "hand_off_refs": hand_off["used"],
                    "result_keys": sorted(outcome.keys()) if isinstance(outcome, dict) else [],
                }
            )
            if ok:
                console.print("  [green]ok[/green]")

        purple = _purple_package(session, phase_results, graph)
        purple_path = session.path("purple-handoff.json")
        purple_path.write_text(json.dumps(purple, indent=2, default=str) + "\n", encoding="utf-8")

        result = {
            "domain": target.domain,
            "session": session.session_id,
            "phases": phase_results,
            "completed": sum(1 for p in phase_results if p.get("ok")),
            "failed": sum(1 for p in phase_results if p.get("error")),
            "skipped": sum(1 for p in phase_results if p.get("skipped")),
            "purple_handoff": str(purple_path),
        }
        out = session.path("campaign-run.json")
        out.write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "campaign-run.complete",
            completed=result["completed"],
            failed=result["failed"],
            skipped=result["skipped"],
        )
        console.print(
            f"\n[green]Campaign done[/green]  completed={result['completed']}  "
            f"failed={result['failed']}  skipped={result['skipped']}"
        )
        console.print(f"Purple hand-off → {purple_path}")
        return result
