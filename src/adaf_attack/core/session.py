"""Session / workspace logging.

Every run creates a session directory so operators can later answer
"what exactly ran?".
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adaf_attack.core.paths import default_workspace_dir, ensure_dir, normalize_path


class Session:
    def __init__(self, base_dir: Path | str | None = None) -> None:
        if base_dir is None:
            base = default_workspace_dir()
        else:
            base = normalize_path(base_dir)
        self.base_dir = ensure_dir(base)
        self.session_id = (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        )
        self.root = ensure_dir(self.base_dir / self.session_id)
        self._events: list[dict[str, Any]] = []
        self._write_meta()

    def _write_meta(self) -> None:
        meta = {
            "session_id": self.session_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "tool": "adaf-attack",
            "root": str(self.root),
        }
        # newline="\n" keeps JSON portable across Windows/Unix
        (self.root / "session.json").write_text(
            json.dumps(meta, indent=2) + "\n", encoding="utf-8", newline="\n"
        )

    def log(self, event_type: str, **payload: Any) -> None:
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
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
