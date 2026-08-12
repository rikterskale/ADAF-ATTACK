"""Persistent per-user CLI/TUI defaults."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.paths import default_config_path, ensure_dir


def _config_path() -> Path:
    return default_config_path()


def load_user_config() -> dict[str, Any]:
    path = _config_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_user_config(data: dict[str, Any]) -> Path:
    path = _config_path()
    ensure_dir(path.parent)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def get_config_value(key: str, default: Any = None) -> Any:
    return load_user_config().get(key, default)


def set_config_value(key: str, value: Any) -> dict[str, Any]:
    data = load_user_config()
    data[key] = value
    save_user_config(data)
    return data


def unset_config_value(key: str) -> dict[str, Any]:
    data = load_user_config()
    if key in data:
        del data[key]
        save_user_config(data)
    return data


def known_config_keys() -> list[str]:
    return [
        "ui.theme",
        "ui.recent_capabilities",
        "ui.default_workspace",
        "operator.default_domain",
        "operator.default_dc_ip",
        "safety.require_force_confirm",
    ]


def remember_capability(capability_id: str, *, limit: int = 10) -> list[str]:
    """Record a capability selection without storing target or credential data."""
    data = load_user_config()
    existing = data.get("ui.recent_capabilities", [])
    recent = [str(item) for item in existing if isinstance(item, str) and item != capability_id]
    recent.insert(0, capability_id)
    trimmed = recent[:limit]
    data["ui.recent_capabilities"] = trimmed
    save_user_config(data)
    return trimmed


def recent_capabilities(*, limit: int = 5) -> list[str]:
    """Return recently selected capability IDs, newest first."""
    value = load_user_config().get("ui.recent_capabilities", [])
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)][:limit]
