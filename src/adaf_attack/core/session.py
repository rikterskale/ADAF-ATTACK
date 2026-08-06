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


class Session:
    def __init__(self, base_dir: Path | str = "workspaces") -> None:
        self.base_dir = Path(base_dir)
        self.session_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        self.root = self.base_dir / self.session_id
        self.root.mkdir(parents=True, exist_ok=True)
        self._events: list[dict[str, Any]] = []
        self._write_meta()

    def _write_meta(self) -> None:
        meta = {
            "session_id": self.session_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "tool": "adaf-attack",
        }
        (self.root / "session.json").write_text(json.dumps(meta, indent=2))

    def log(self, event_type: str, **payload: Any) -> None:
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            **payload,
        }
        self._events.append(event)
        with (self.root / "events.jsonl").open("a") as f:
            f.write(json.dumps(event) + "\n")

    def path(self, *parts: str) -> Path:
        p = self.root.joinpath(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
