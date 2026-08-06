"""Cross-platform path helpers for ADAF-ATTACK."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def is_windows() -> bool:
    return sys.platform == "win32"


def is_macos() -> bool:
    return sys.platform == "darwin"


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def is_kali(os_release_path: Path = Path("/etc/os-release")) -> bool:
    """Return whether the current Linux distribution identifies as Kali."""
    if not is_linux():
        return False
    try:
        values: dict[str, str] = {}
        for line in os_release_path.read_text(encoding="utf-8").splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"').lower()
        return values.get("ID") == "kali" or "kali" in values.get("ID_LIKE", "").split()
    except OSError:
        return False


def platform_name() -> str:
    if is_windows():
        return "Windows"
    if is_macos():
        return "macOS"
    if is_kali():
        return "Kali Linux"
    if is_linux():
        return "Linux"
    return sys.platform


def user_data_dir(app_name: str = "adaf-attack") -> Path:
    """Per-user application data directory."""
    if is_windows():
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / app_name
    if is_macos():
        return Path.home() / "Library" / "Application Support" / app_name
    # Linux / other Unix — XDG
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / app_name
    return Path.home() / ".local" / "share" / app_name


def user_config_dir(app_name: str = "adaf-attack") -> Path:
    if is_windows():
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / app_name / "config"
    if is_macos():
        return Path.home() / "Library" / "Preferences" / app_name
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / app_name
    return Path.home() / ".config" / app_name


def default_workspace_dir() -> Path:
    """Default session/workspace root.

    Prefer ADAF_ATTACK_WORKSPACE env, else platform data dir / workspaces.
    """
    env = os.environ.get("ADAF_ATTACK_WORKSPACE")
    if env:
        return Path(env).expanduser()
    return user_data_dir() / "workspaces"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def normalize_path(path: str | Path) -> Path:
    """Expand ~ and resolve without requiring the path to exist."""
    p = Path(path).expanduser()
    try:
        return p.resolve(strict=False)
    except Exception:  # noqa: BLE001
        return p.absolute()
