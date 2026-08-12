"""Unified rollback of the most recent approved destructive changes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console

from adaf_attack.core.cleanup import execute_cleanup
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.rollback import list_pending, summarize_rollbacks
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


@register_capability(
    id="rollback",
    summary="Reverse pending destructive changes recorded in a session (requires --force)",
    category="analysis",
    tags=("rollback", "cleanup", "safety"),
    destructive=True,
)
class Rollback:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        source = Path(str(kwargs.get("session") or kwargs.get("from_session") or session.root))
        if not source.is_dir():
            raise RuntimeError(f"Session directory not found: {source}")

        summary = summarize_rollbacks(source)
        pending = list_pending(source)

        console.print(f"[bold]Rollback[/bold]  session={source.name}")
        console.print(
            f"  pending={summary['pending']}  completed={summary['completed']}  "
            f"failed={summary['failed']}"
        )

        if not pending:
            result = {
                "ok": True,
                "message": "No pending rollback actions",
                "summary": summary,
            }
            session.path("rollback.json").write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8"
            )
            session.log("rollback.complete", pending=0)
            return result

        if not force:
            console.print(
                "[yellow]Pending actions exist. Re-run with --force to apply rollbacks.[/yellow]"
            )
            for item in pending[:10]:
                console.print(f"  • {item.get('kind')} → {item.get('target')}")
            result = {
                "ok": False,
                "message": "force_required",
                "pending": pending,
                "summary": summary,
            }
            session.path("rollback.json").write_text(
                json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8"
            )
            return result

        console.print(f"[red]Applying {len(pending)} rollback action(s)…[/red]")
        outcome = execute_cleanup(source, target)
        final_summary = summarize_rollbacks(source)

        result = {
            "ok": True,
            "applied": outcome.get("completed", 0),
            "outcome": outcome,
            "summary": final_summary,
        }
        session.path("rollback.json").write_text(
            json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8"
        )
        session.log(
            "rollback.complete",
            applied=outcome.get("completed", 0),
            pending_before=len(pending),
        )
        console.print(
            f"[green]Done[/green]  completed={outcome.get('completed', 0)}  "
            f"remaining_pending={final_summary['pending']}"
        )
        return result
