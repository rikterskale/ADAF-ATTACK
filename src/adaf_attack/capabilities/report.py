"""Operator report — Markdown (+ optional HTML) from session artifacts."""

from __future__ import annotations

import json
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from rich.console import Console

from adaf_attack import __version__
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.reporting import generate_report_bundle
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

FINDING_FILES = [
    ("ldap-enum.json", "LDAP enumeration"),
    ("acl-enum.json", "ACL edges"),
    ("adcs-enum.json", "AD CS / ESC"),
    ("trusts-enum.json", "Trusts"),
    ("kerberoast.json", "Kerberoast"),
    ("asrep-roast.json", "AS-REP roast"),
    ("gmsa-laps-enum.json", "gMSA / LAPS"),
    ("shadow-creds.json", "Shadow credentials"),
    ("rbcd.json", "RBCD"),
    ("gpo-abuse.json", "GPO abuse"),
    ("coercion-map.json", "Coercion surface"),
    ("pkinit-auth.json", "PKINIT auth"),
    ("cert-request.json", "Certificate request"),
    ("gpo-sysvol.json", "GPO SYSVOL"),
    ("attack-paths.json", "Attack paths"),
    ("interesting.json", "Interesting graph summary"),
]


def _load(session: Session, name: str) -> Any | None:
    p = session.path(name)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|")


@register_capability(
    id="report",
    summary="Generate operator Markdown/HTML report from current session artifacts",
    category="export",
    tags=("report", "markdown", "html", "engagement"),
)
class Report:
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
        console.print(f"[bold]Operator report[/bold] → session {session.session_id}")

        # Hydrate graph if empty
        if not graph.nodes:
            gp = session.path("graph.json")
            if gp.exists():
                with suppress(Exception):  # noqa: BLE001
                    graph = AttackGraph.from_file(gp)

        lines: list[str] = []
        lines.append("# ADAF-ATTACK Operator Report")
        lines.append("")
        lines.append(f"- **Generated:** {datetime.now(UTC).isoformat()}")
        lines.append(f"- **Toolkit:** adaf-attack {__version__}")
        lines.append(f"- **Session:** `{session.session_id}`")
        lines.append(f"- **Domain:** `{target.domain}`")
        lines.append(f"- **DC:** `{target.dc_ip}`")
        lines.append(f"- **Principal:** `{target.username or 'anonymous'}`")
        lines.append("")

        summary: dict[str, Any] = graph.summary() if graph.nodes else {"nodes": 0, "edges": 0}
        lines.append("## Graph summary")
        lines.append("")
        lines.append(f"- Nodes: **{summary.get('nodes', 0)}**")
        lines.append(f"- Edges: **{summary.get('edges', 0)}**")
        if summary.get("edge_kinds"):
            lines.append("- Edge kinds:")
            for k, v in sorted(summary["edge_kinds"].items(), key=lambda x: -x[1])[:20]:
                lines.append(f"  - `{k}`: {v}")
        lines.append("")

        # Interesting paths
        interesting = _load(session, "interesting.json") or {}
        top = interesting.get("top_paths") or []
        if top:
            lines.append("## Top ranked attack paths")
            lines.append("")
            for i, p in enumerate(top[:15], 1):
                path = p.get("path") or []
                short = " → ".join((x.split("@")[1] if "@" in x else x) for x in path[:8])
                lines.append(f"{i}. score=`{p.get('score')}` len=`{p.get('length')}` — {short}")
            lines.append("")

        # Per-capability findings
        lines.append("## Capability findings")
        lines.append("")
        findings_index: dict[str, Any] = {}
        for fname, title in FINDING_FILES:
            data = _load(session, fname)
            if data is None:
                continue
            findings_index[fname] = True
            lines.append(f"### {title} (`{fname}`)")
            lines.append("")
            if fname == "adcs-enum.json":
                lines.append(f"- CAs: {len(data.get('cas') or [])}")
                lines.append(f"- Templates: {len(data.get('templates') or [])}")
                lines.append(f"- ESC1: {data.get('esc1_candidates') or []}")
                lines.append(f"- ESC2: {data.get('esc2_candidates') or []}")
                lines.append(f"- ESC4 ACL templates: {len(data.get('esc4_acl_templates') or [])}")
                lines.append(f"- ESC7: {len(data.get('esc7_ca_acl') or [])}")
                lines.append(f"- ESC8: {len(data.get('esc8_web_enrollment') or [])}")
                esc6 = data.get("esc6") or {}
                lines.append(f"- ESC6 resolved: {esc6.get('resolved')} value={esc6.get('esc6')}")
            elif fname == "kerberoast.json":
                lines.append(
                    f"- Tickets/hashes: {data.get('count', len(data.get('tickets') or []))}"
                )
            elif fname == "asrep-roast.json":
                lines.append(
                    f"- AS-REP tickets: {data.get('count', len(data.get('tickets') or []))}"
                )
            elif fname == "acl-enum.json":
                lines.append(f"- Objects scanned: {data.get('objects_scanned')}")
                lines.append(f"- Interesting edges: {data.get('interesting_edge_count')}")
                lines.append(f"- DCSync principals: {data.get('dcsync_principals') or []}")
            elif fname == "shadow-creds.json":
                lines.append(
                    f"- Accounts with KeyCredentialLink: {len(data.get('accounts_with_keycred') or [])}"
                )
                lines.append(f"- Writable ACE hits: {len(data.get('writable_principals') or [])}")
            elif fname == "rbcd.json":
                lines.append(f"- RBCD configured: {len(data.get('rbcd_configured') or [])}")
                lines.append(
                    f"- Writable computer ACEs: {len(data.get('writable_computers') or [])}"
                )
            elif fname == "gpo-abuse.json":
                lines.append(f"- GPOs: {len(data.get('gpos') or [])}")
                lines.append(f"- Writable GPOs: {len(data.get('writable_gpos') or [])}")
                lines.append(f"- Links: {len(data.get('links') or [])}")
            elif fname == "coercion-map.json":
                lines.append(f"- Hosts checked: {data.get('hosts_checked')}")
                lines.append(f"- Spooler: {data.get('spooler_open')}")
                lines.append(f"- EFSRPC: {data.get('efsrpc_open')}")
            elif fname == "ldap-enum.json":
                lines.append(f"- Users: {len(data.get('users') or [])}")
                lines.append(f"- Computers: {len(data.get('computers') or [])}")
                lines.append(f"- Groups: {len(data.get('groups') or [])}")
                lines.append(f"- Delegation entries: {len(data.get('delegation') or [])}")
                lines.append(f"- SID history: {len(data.get('sid_history') or [])}")
            else:
                if isinstance(data, dict):
                    for k in list(data.keys())[:12]:
                        v = data[k]
                        if isinstance(v, int | str | bool | float):
                            lines.append(f"- {k}: {v}")
                        elif isinstance(v, list):
                            lines.append(f"- {k}: {len(v)} items")
            lines.append("")

        lines.append("## Session artifacts")
        lines.append("")
        try:
            arts = sorted(p.name for p in session.root.iterdir() if p.is_file())
        except Exception:  # noqa: BLE001
            arts = []
        for a in arts:
            lines.append(f"- `{a}`")
        lines.append("")
        lines.append("---")
        lines.append(
            "_Generated by ADAF-ATTACK. Redacted by default unless --include-secrets was used._"
        )

        md = "\n".join(lines) + "\n"
        md_path = session.path("report.md")
        md_path.write_text(md, encoding="utf-8")

        html = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>ADAF-ATTACK Report {target.domain}</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;"
            "background:#0d1117;color:#e6edf3} code,pre{background:#161b22;padding:.1rem .3rem;border-radius:4px}"
            "h1,h2,h3{color:#58a6ff} a{color:#58a6ff}</style></head><body>\n"
        )
        # Minimal MD→HTML: preformatted blocks
        html += f"<pre style='white-space:pre-wrap'>{md.replace('<', '&lt;')}</pre></body></html>\n"
        html_path = session.path("report.html")
        html_path.write_text(html, encoding="utf-8")

        bundle = generate_report_bundle(session.root)

        session.log("report.complete", md=str(md_path), html=str(html_path), bundle=bundle)
        console.print(f"[green]Markdown[/green] → {md_path}")
        console.print(f"[green]HTML[/green]     → {html_path}")
        return {
            "domain": target.domain,
            "md_path": str(md_path),
            "html_path": str(html_path),
            "artifacts_used": list(findings_index.keys()),
            "graph_summary": summary,
            "report_bundle": bundle,
        }
