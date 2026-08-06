"""Session / workspace logging.

Every run creates a session directory so operators can later answer
"what exactly ran?".
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from adaf_attack.core.paths import default_workspace_dir, ensure_dir, normalize_path

if TYPE_CHECKING:
    from adaf_attack.core.vault import SessionVault


class Session:
    def __init__(self, base_dir: Path | str | None = None) -> None:
        base = default_workspace_dir() if base_dir is None else normalize_path(base_dir)
        self.base_dir = ensure_dir(base)
        self.session_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        self.root = ensure_dir(self.base_dir / self.session_id)
        self._events: list[dict[str, Any]] = []
        self._write_meta()

    def _write_meta(self) -> None:
        meta = {
            "session_id": self.session_id,
            "created_at": datetime.now(UTC).isoformat(),
            "tool": "adaf-attack",
            "root": str(self.root),
        }
        (self.root / "session.json").write_text(
            json.dumps(meta, indent=2) + "\n", encoding="utf-8", newline="\n"
        )

    def log(self, event_type: str, **payload: Any) -> None:
        event = {
            "ts": datetime.now(UTC).isoformat(),
            "type": event_type,
            **payload,
        }
        self._events.append(event)
        with (self.root / "events.jsonl").open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(event) + "\n")

    def path(self, *parts: str) -> Path:
        p = self.root.joinpath(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def vault(self) -> SessionVault:
        from adaf_attack.core.vault import SessionVault

        return SessionVault(self.root)

    def register_cleanup(self, action: dict[str, Any]) -> None:
        path = self.path("cleanup.json")
        try:
            entries = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            entries = []
        entries.append({"registered_at": datetime.now(UTC).isoformat(), "status": "pending", **action})
        path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
        self.log("cleanup.registered", kind=action.get("kind"), target=action.get("target"))
