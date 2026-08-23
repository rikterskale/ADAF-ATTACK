"""Export attack graph to BloodHound JSON + CE ingest zip."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console

from adaf_attack.core.bloodhound import save_bloodhound, save_bloodhound_zip
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


def _hydrate_graph_from_session(session: Session, graph: AttackGraph) -> bool:
    path = session.path("graph.json")
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text())
        for n in data.get("nodes", []):
            graph.add_node(n["id"], n.get("kind", "Unknown"), **(n.get("properties") or {}))
        for e in data.get("edges", []):
            graph.add_edge(
                e["source"],
                e["target"],
                e.get("kind", "Related"),
                **(e.get("properties") or {}),
            )
        return len(graph.nodes) > 0
    except Exception:
        return False


@register_capability(
    id="bloodhound-export",
    summary="Export attack graph to BloodHound CE JSON + ingest zip",
    category="export",
    tags=("bloodhound", "graph", "export", "zip"),
)
class BloodhoundExport:
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
        console.print(f"[bold]BloodHound export[/bold] → {target.domain}")

        if not graph.nodes:
            loaded = _hydrate_graph_from_session(session, graph)
            if not loaded:
                console.print(
                    "[yellow]Graph empty — running ldap-enum first to seed nodes/edges[/yellow]"
                )
                from adaf_attack.capabilities.ldap_enum import LdapEnum

                LdapEnum().run(
                    target,
                    session,
                    graph,
                    include_secrets=include_secrets,
                    force=force,
                )
                graph.resolve_dn_edges()

        json_path = session.path("bloodhound.json")
        zip_path = session.path("bloodhound.zip")
        save_bloodhound(graph, json_path, domain=target.domain)
        save_bloodhound_zip(graph, zip_path, domain=target.domain)

        summary = graph.summary()
        session.log(
            "bloodhound-export.complete",
            nodes=summary.get("nodes", 0),
            edges=summary.get("edges", 0),
            json=str(json_path),
            zip=str(zip_path),
        )

        console.print(
            f"[green]Exported[/green]  nodes={summary.get('nodes', 0)}  "
            f"edges={summary.get('edges', 0)}"
        )
        console.print(f"JSON → {json_path}")
        console.print(f"Zip  → {zip_path}  (bloodhound.json / nodes.json / edges.json / meta.json)")
        return {
            "domain": target.domain,
            "json_path": str(json_path),
            "zip_path": str(zip_path),
            "summary": summary,
        }
