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
    raw_events: list[dict[str, Any]] = []
    events_path = session / "events.jsonl"
    if events_path.is_file():
        for line in events_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            raw_events.append(event)
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
    artifacts: list[dict[str, Any]] = []
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
    lifecycle: list[dict[str, Any]] = []
    for artifact in artifacts:
        related = [
            event
            for event in raw_events
            if artifact["name"].casefold() in json.dumps(event, sort_keys=True).casefold()
        ]
        lifecycle.append(
            {
                "artifact": artifact["name"],
                "kind": artifact["kind"],
                "source": "session evidence",
                "used_by": sorted(
                    {str(event["capability"]) for event in related if event.get("capability")}
                ),
                "identities": sorted(
                    {
                        str(event.get("username") or event.get("identity"))
                        for event in related
                        if event.get("username") or event.get("identity")
                    }
                ),
                "enables": sorted(
                    {str(event["enables"]) for event in related if event.get("enables")}
                ),
            }
        )
    recommended = next((item for item in reversed(actions) if item["identity"]), None)
    return {
        "ok": True,
        "session": str(session),
        "identities": sorted(identities.values(), key=lambda item: item["identity"]),
        "credential_artifacts": artifacts,
        "credential_lifecycle": lifecycle,
        "actions": actions,
        "recommended_identity": recommended["identity"] if recommended else None,
        "safety": "secret values are never read or returned",
    }


def best_identity_for_capability(session: Path, capability: str) -> dict[str, Any]:
    """Recommend a recorded identity for a capability without exposing secrets."""
    context = session_access_context(session)
    for action in reversed(context["actions"]):
        if action["capability"] == capability and action["identity"]:
            return {
                "identity": action["identity"],
                "auth": action["auth"],
                "reason": "Previously used for this capability in the session.",
            }
    if context["recommended_identity"]:
        return {
            "identity": context["recommended_identity"],
            "auth": "last-recorded",
            "reason": "Most recently recorded identity with an executed action.",
        }
    if context["identities"]:
        identity = context["identities"][0]
        return {
            "identity": identity["identity"],
            "auth": identity["auth_modes"][0] if identity["auth_modes"] else "not-recorded",
            "reason": "Only recorded identity available in the session.",
        }
    return {
        "identity": None,
        "auth": None,
        "reason": "No identity has been recorded; review access before execution.",
    }
