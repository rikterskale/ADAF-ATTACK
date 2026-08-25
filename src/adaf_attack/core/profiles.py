"""Named target profiles persisted in user config (enhancement #10)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.paths import user_config_dir

_PROFILE_KEYS = {
    "domain",
    "dc_ip",
    "username",
    "ldaps",
    "kerberos",
    "scope",
    "opsec_profile",
    "notes",
}

VALID_OPSEC = ("stealth", "balanced", "loud")


def profiles_path() -> Path:
    return user_config_dir() / "profiles.json"


def load_profiles() -> dict[str, dict[str, Any]]:
    path = profiles_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        return {str(k): v for k, v in data.items() if isinstance(v, dict)}
    except (OSError, json.JSONDecodeError):
        return {}


def save_profiles(data: dict[str, dict[str, Any]]) -> Path:
    path = profiles_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def get_profile(name: str) -> dict[str, Any] | None:
    return load_profiles().get(name)


def set_profile(name: str, values: dict[str, Any]) -> dict[str, Any]:
    if not name or any(ch.isspace() for ch in name):
        raise ValueError("Profile name must be a non-empty token without spaces")
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if key not in _PROFILE_KEYS:
            raise ValueError(
                f"Unknown profile field: {key}. Allowed: {', '.join(sorted(_PROFILE_KEYS))}"
            )
        if key == "opsec_profile" and value not in VALID_OPSEC:
            raise ValueError(f"opsec_profile must be one of: {', '.join(VALID_OPSEC)}")
        if key in {"ldaps", "kerberos"} and isinstance(value, str):
            cleaned[key] = value.lower() in {"1", "true", "yes", "on"}
        else:
            cleaned[key] = value
    data = load_profiles()
    data[name] = cleaned
    save_profiles(data)
    return cleaned


def delete_profile(name: str) -> bool:
    data = load_profiles()
    if name not in data:
        return False
    del data[name]
    save_profiles(data)
    return True


def list_profiles() -> list[dict[str, Any]]:
    data = load_profiles()
    return [{"name": name, **values} for name, values in sorted(data.items())]


def apply_profile_to_defaults(name: str) -> dict[str, Any]:
    profile = get_profile(name)
    if profile is None:
        raise ValueError(f"Unknown profile: {name}")
    from adaf_attack.core.user_config import load_user_config, save_user_config

    mapping = {
        "target.domain": profile.get("domain"),
        "target.dc_ip": profile.get("dc_ip"),
        "target.username": profile.get("username"),
        "target.ldaps": profile.get("ldaps"),
        "target.kerberos": profile.get("kerberos"),
        "acl.scope": profile.get("scope"),
        "opsec.profile": profile.get("opsec_profile") or "balanced",
        "profile.default": name,
    }
    data = load_user_config()
    applied: dict[str, Any] = {}
    for key, value in mapping.items():
        if value is not None:
            data[key] = value
            applied[key] = value
    save_user_config(data)
    return applied


def active_opsec(explicit: str | None = None, profile_name: str | None = None) -> str:
    if explicit in VALID_OPSEC:
        return explicit
    if profile_name:
        profile = get_profile(profile_name)
        if profile and profile.get("opsec_profile") in VALID_OPSEC:
            return str(profile["opsec_profile"])
    from adaf_attack.core.user_config import load_user_config

    cfg = load_user_config()
    value = cfg.get("opsec.profile") or cfg.get("opsec_profile") or "balanced"
    return value if value in VALID_OPSEC else "balanced"


OPSEC_HINTS = {
    "stealth": "Prefer low-and-slow queries; avoid spray/coerce by default.",
    "balanced": "Standard internal tempo with moderate request rates.",
    "loud": "Aggressive enumeration acceptable only when explicitly authorized.",
}
