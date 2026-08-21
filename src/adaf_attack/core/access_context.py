"""Safe credential and identity context derived from session metadata."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def session_access_context(session: Path) -> dict[str, Any]:
    """Summarize identities and credential forms without reading secret contents."""
    session = Path(session)
    identities: dict[str, dict[str, Any]] = {}
    actions: list[dict[str, Any]] = []
    events_path = session / "events.jsonl"
    if events_path.is_file():
        for line in events_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            username = str(event.get("username") or "").strip()
            auth = str(event.get("auth") or "not-recorded")
            if username:
                identities.setdefault(
                    username, {"identity": username, "auth_modes": set(), "capabilities": set()}
                )
                identities[username]["auth_modes"].add(auth)
                if event.get("capability"):
                    identities[username]["capabilities"].add(str(event["capability"]))
            if event.get("capability") and event.get("type") in {
                "run.start",
                "run.complete",
                "run.error",
            }:
                actions.append(
                    {
                        "capability": str(event["capability"]),
                        "identity": username or None,
                        "auth": auth,
                        "event": event.get("type"),
                    }
                )
    artifacts = []
    for path in sorted(session.iterdir()) if session.is_dir() else []:
        if not path.is_file() or path.name in {"session.json", "events.jsonl"}:
            continue
        lower = path.name.lower()
        if any(token in lower for token in ("ccache", ".kirbi", "ticket", "tgt")):
            kind = "ticket"
        elif any(token in lower for token in (".pfx", ".p12", ".pem", ".key", "cert")):
            kind = "certificate-or-key"
        elif any(
            token in lower for token in ("hash", "credential", "password", "secret", "cpassword")
        ):
            kind = "password-or-hash"
        else:
            continue
        artifacts.append({"name": path.name, "kind": kind, "present": True})
    for item in identities.values():
        item["auth_modes"] = sorted(item["auth_modes"])
        item["capabilities"] = sorted(item["capabilities"])
    recommended = next((item for item in reversed(actions) if item["identity"]), None)
    return {
        "ok": True,
        "session": str(session),
        "identities": sorted(identities.values(), key=lambda item: item["identity"]),
        "credential_artifacts": artifacts,
        "actions": actions,
        "recommended_identity": recommended["identity"] if recommended else None,
        "safety": "secret values are never read or returned",
    }
