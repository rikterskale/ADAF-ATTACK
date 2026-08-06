"""Ranked attack-path analysis capability.

Loads an existing session graph.json (from ldap-enum / acl-enum / etc.) or
accepts an explicit --graph path via kwargs, then ranks weighted paths toward
high-value groups and domains.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


@register_capability(
    id="attack-paths",
    summary="Rank weighted attack paths from principals toward high-value targets",
    category="analysis",
    tags=("graph", "paths", "bloodhound", "ranking"),
)
class AttackPaths:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        include_secrets: bool = False,
        force: bool = False,
        graph_path: str | Path | None = None,
        start: str | None = None,
        max_depth: int = 6,
        limit: int = 25,
        **kwargs: Any,
    ) -> dict[str, Any]:
        console.print("[bold]Attack path ranking[/bold]")

        loaded_from: str | None = None
        if graph_path:
            p = Path(graph_path).expanduser()
            if not p.is_file():
                raise RuntimeError(f"Graph file not found: {p}")
            loaded = AttackGraph.from_file(p)
            graph.nodes = loaded.nodes
            graph.edges = loaded.edges
            graph._adj = loaded._adj  # noqa: SLF001
            graph._dn_index = loaded._dn_index  # noqa: SLF001
            loaded_from = str(p)
            console.print(f"Loaded graph from [cyan]{p}[/cyan]")
        elif not graph.nodes:
            # Try newest graph.json under workspace parent sessions
            candidates = sorted(
                session.root.parent.glob("*/graph.json"),
                key=lambda x: x.stat().st_mtime,
                reverse=True,
            )
            if candidates:
                loaded = AttackGraph.from_file(candidates[0])
                graph.nodes = loaded.nodes
                graph.edges = loaded.edges
                graph._adj = loaded._adj  # noqa: SLF001
                graph._dn_index = loaded._dn_index  # noqa: SLF001
                loaded_from = str(candidates[0])
                console.print(f"Loaded latest session graph: [cyan]{candidates[0]}[/cyan]")
            else:
                raise RuntimeError(
                    "No graph loaded. Run ldap-enum (and ideally acl-enum) first, "
                    "or pass graph_path= to an existing graph.json"
                )

        summary = graph.summary()
        console.print(
            f"Graph: [cyan]{summary['nodes']}[/cyan] nodes, "
            f"[cyan]{summary['edges']}[/cyan] edges"
        )

        starts = [start] if start else None
        ranked = graph.rank_from_principals(
            starts,
            max_depth=max_depth,
            limit=limit,
            per_start=8 if start else 4,
        )

        table = Table(title="Top ranked attack paths", show_header=True, header_style="bold")
        table.add_column("#", style="dim", width=4)
        table.add_column("Score", justify="right")
        table.add_column("Len", justify="right")
        table.add_column("Path")

        for i, p in enumerate(ranked[:15], 1):
            short = " → ".join(
                (x.split("@")[1] if "@" in x else x) for x in p["path"][:8]
            )
            if len(p["path"]) > 8:
                short += " → …"
            table.add_row(str(i), f"{p['score']:.1f}", str(p["length"]), short)

        if ranked:
            console.print(table)
        else:
            console.print("[yellow]No paths found — expand enum coverage or raise max_depth[/yellow]")

        result: dict[str, Any] = {
            "domain": target.domain,
            "loaded_from": loaded_from,
            "graph": summary,
            "start": start,
            "max_depth": max_depth,
            "paths": ranked,
            "count": len(ranked),
        }

        out_path = session.path("ranked-paths.json")
        out_path.write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
        graph.save(session.path("graph.json"))

        interesting = graph.interesting_summary(limit=limit)
        session.path("interesting.json").write_text(
            json.dumps(interesting, indent=2, default=str) + "\n", encoding="utf-8"
        )

        session.log(
            "attack-paths.complete",
            count=len(ranked),
            start=start,
            loaded_from=loaded_from,
        )
        console.print(f"Results → {out_path}")
        return result
