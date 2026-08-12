"""Persistent per-user CLI/TUI defaults."""

from __future__ import annotations

import json
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
    "ui.tour_complete",
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
    data["ui.recent_capabilities"] = recent[:limit]
    save_user_config(data)
    return data["ui.recent_capabilities"]


def recent_capabilities(*, limit: int = 5) -> list[str]:
    """Return recently selected capability IDs, newest first."""
    value = load_user_config().get("ui.recent_capabilities", [])
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)][:limit]
