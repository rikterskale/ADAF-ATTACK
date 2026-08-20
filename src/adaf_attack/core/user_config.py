"""Persistent per-user CLI/TUI defaults."""

from __future__ import annotations

import json
from contextlib import suppress
from pathlib import Path
from typing import Any

from adaf_attack.core.paths import user_config_dir

_ALLOWED_KEYS = {
    "target.domain",
    "target.dc_ip",
    "target.username",
    "target.ldaps",
    "target.kerberos",
    "acl.scope",
    "acl.max_objects",
    "run.max_depth",
    "run.limit",
    "workspace",
    "opsec.profile",
    "profile.default",
    "novice.safe_mode",
    "ui.recent_capabilities",
    "ui.favorite_capabilities",
    "ui.recent_targets",
    "ui.command_complete",
}


def config_path() -> Path:
    return user_config_dir() / "config.json"


def load_user_config() -> dict[str, Any]:
    path = config_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_user_config(data: dict[str, Any]) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def allowed_keys() -> list[str]:
    return sorted(_ALLOWED_KEYS)


def set_key(key: str, value: str) -> tuple[Path, dict[str, Any]]:
    if key not in _ALLOWED_KEYS:
        raise ValueError(f"Unknown config key: {key}. Allowed: {', '.join(sorted(_ALLOWED_KEYS))}")
    data = load_user_config()
    parsed: Any = value
    if value.lower() in {"true", "false"}:
        parsed = value.lower() == "true"
    else:
        try:
            parsed = int(value)
        except ValueError:
            parsed = value
    data[key] = parsed
    path = save_user_config(data)
    return path, data


def unset_key(key: str) -> tuple[Path, dict[str, Any]]:
    data = load_user_config()
    data.pop(key, None)
    path = save_user_config(data)
    return path, data


def get_key(key: str) -> Any:
    return load_user_config().get(key)


def record_recent_capability(capability_id: str, *, limit: int = 5) -> list[str]:
    """Record a capability selection without storing target or credential data."""
    data = load_user_config()
    existing = data.get("ui.recent_capabilities", [])
    recent = [str(item) for item in existing if isinstance(item, str) and item != capability_id]
    recent.insert(0, capability_id)
    trimmed = recent[:limit]
    data["ui.recent_capabilities"] = trimmed
    # Recent-use history is an optional UX enhancement. A managed workstation
    # may expose a read-only profile, but that must not prevent help or planning
    # commands from completing successfully.
    with suppress(OSError):
        save_user_config(data)
    return trimmed


def recent_capabilities(*, limit: int = 5) -> list[str]:
    """Return recently selected capability IDs, newest first."""
    value = load_user_config().get("ui.recent_capabilities", [])
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)][:limit]


def favorite_capabilities() -> list[str]:
    """Return capability IDs pinned by the user."""
    value = load_user_config().get("ui.favorite_capabilities", [])
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def set_favorite_capability(capability_id: str, *, favorite: bool) -> list[str]:
    """Pin or unpin a capability without persisting target or credential data."""
    current = favorite_capabilities()
    updated = [item for item in current if item != capability_id]
    if favorite:
        updated.append(capability_id)
    data = load_user_config()
    data["ui.favorite_capabilities"] = updated
    save_user_config(data)
    return updated


def record_recent_target(
    domain: str, dc_ip: str, scope: str, *, limit: int = 5
) -> list[dict[str, str]]:
    """Store a short, non-secret target history for form recall."""
    entry = {"domain": domain.strip(), "dc_ip": dc_ip.strip(), "scope": scope.strip()}
    if not entry["domain"] or not entry["dc_ip"]:
        return recent_targets(limit=limit)
    existing = recent_targets(limit=limit)
    updated = [item for item in existing if item != entry]
    updated.insert(0, entry)
    data = load_user_config()
    data["ui.recent_targets"] = updated[:limit]
    with suppress(OSError):
        save_user_config(data)
    return updated[:limit]


def recent_targets(*, limit: int = 5) -> list[dict[str, str]]:
    """Return recently used non-secret target identifiers, newest first."""
    value = load_user_config().get("ui.recent_targets", [])
    if not isinstance(value, list):
        return []
    targets: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        domain = item.get("domain")
        dc_ip = item.get("dc_ip")
        scope = item.get("scope", "high-value")
        if isinstance(domain, str) and isinstance(dc_ip, str) and isinstance(scope, str):
            targets.append({"domain": domain, "dc_ip": dc_ip, "scope": scope})
    return targets[:limit]
