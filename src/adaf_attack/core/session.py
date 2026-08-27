"""Session / workspace logging.

Every run creates a session directory so operators can later answer
"what exactly ran?".
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from adaf_attack.core.paths import (
    atomic_write_text,
    default_workspace_dir,
    ensure_dir,
    normalize_path,
)

if TYPE_CHECKING:
    from adaf_attack.core.vault import SessionVault


class Session:
    def __init__(self, base_dir: Path | str | None = None) -> None:
        base = default_workspace_dir() if base_dir is None else normalize_path(base_dir)
        self.base_dir = ensure_dir(base)
        self.session_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        self.correlation_id = uuid.uuid4().hex
        self.root = ensure_dir(self.base_dir / self.session_id)
        self._events: list[dict[str, Any]] = []
        self._event_lock = threading.Lock()
        self._last_event_hash = ""
        self._started_monotonic = time.monotonic()
        self._write_meta()

    def _write_meta(self) -> None:
        meta = {
            "schema_version": 2,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
            "created_at": datetime.now(UTC).isoformat(),
            "tool": "adaf-attack",
            "root": str(self.root),
            "audit_integrity": "sha256-chain",
        }
        atomic_write_text(self.root / "session.json", json.dumps(meta, indent=2) + "\n")

    def log(self, event_type: str, **payload: Any) -> None:
        if not event_type.strip():
            raise ValueError("event_type must be non-empty")
        reserved = {
            "type",
            "ts",
            "event_schema_version",
            "correlation_id",
            "prev_hash",
            "event_hash",
        }
        if reserved & payload.keys():
            raise ValueError(
                f"event payload cannot override reserved audit fields: "
                f"{sorted(reserved & payload.keys())}"
            )
        with self._event_lock:
            event = {
                "event_schema_version": 2,
                "ts": datetime.now(UTC).isoformat(),
                "type": event_type,
                "correlation_id": self.correlation_id,
                "prev_hash": self._last_event_hash,
                **payload,
            }
            # Stamp elapsed time for mid-run events when callers omit duration_ms.
            if "duration_ms" not in event:
                event["duration_ms"] = int((time.monotonic() - self._started_monotonic) * 1000)
            unsigned = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
            event["event_hash"] = hashlib.sha256(unsigned).hexdigest()
            self._events.append(event)
            event_path = self.root / "events.jsonl"
            with event_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
                handle.flush()
                # An audit event should not disappear silently on process loss.
                os.fsync(handle.fileno())
            with suppress(OSError):
                event_path.chmod(0o600)
            self._last_event_hash = event["event_hash"]

    def path(self, *parts: str) -> Path:
        p = self.root.joinpath(*parts).resolve(strict=False)
        try:
            p.relative_to(self.root.resolve())
        except ValueError as exc:
            raise ValueError("Session paths must remain inside the session root") from exc
        ensure_dir(p.parent)
        return p

    def vault(self) -> SessionVault:
        from adaf_attack.core.vault import SessionVault

        return SessionVault(self.root)

    def register_cleanup(self, action: dict[str, Any]) -> None:
        from adaf_attack.core.rollback import classification_for_kind, validate_cleanup_entry

        validate_cleanup_entry(action)
        path = self.path("cleanup.json")
        with self._event_lock:
            try:
                entries = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                entries = []
            if not isinstance(entries, list):
                raise ValueError("cleanup ledger must contain a list")
            entry = {
                **action,
                "registered_at": datetime.now(UTC).isoformat(),
                "status": "pending",
                "classification": classification_for_kind(str(action["kind"])),
            }
            entries.append(entry)
            atomic_write_text(path, json.dumps(entries, indent=2) + "\n")
        self.log("cleanup.registered", kind=action.get("kind"), target=action.get("target"))


def verify_event_log(path: Path | str) -> dict[str, Any]:
    """Verify the tamper-evident SHA-256 chain in an events JSONL file."""
    event_path = Path(path)
    if not event_path.is_file():
        return {"ok": False, "events": 0, "error": "event log not found"}
    previous = ""
    count = 0
    try:
        for line_number, line in enumerate(event_path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict) or event.get("event_schema_version") != 2:
                return {
                    "ok": False,
                    "events": count,
                    "error": f"invalid event at line {line_number}",
                }
            if event.get("prev_hash") != previous:
                return {"ok": False, "events": count, "error": f"chain break at line {line_number}"}
            supplied = event.get("event_hash")
            unsigned = {key: value for key, value in event.items() if key != "event_hash"}
            expected = hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if not isinstance(supplied, str) or not hmac_compare(supplied, expected):
                return {
                    "ok": False,
                    "events": count,
                    "error": f"hash mismatch at line {line_number}",
                }
            previous = supplied
            count += 1
    except (OSError, json.JSONDecodeError, TypeError):
        return {"ok": False, "events": count, "error": "event log is unreadable"}
    return {"ok": True, "events": count, "last_hash": previous}


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time string comparison for audit hashes."""
    import hmac

    return hmac.compare_digest(left, right)
