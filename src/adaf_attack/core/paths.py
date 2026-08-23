"""Cross-platform path helpers for ADAF-ATTACK."""

from __future__ import annotations

import os
import sys
import tempfile
from contextlib import suppress
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
    override = os.environ.get("ADAF_ATTACK_DATA_DIR")
    if override:
        return Path(override).expanduser()
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
    override = os.environ.get("ADAF_ATTACK_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
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


def restrict_permissions(path: Path, mode: int = 0o600) -> Path:
    """Best-effort least-privilege permissions for local artifacts."""
    try:
        if not is_windows():
            path.chmod(mode)
    except OSError:
        # ACLs and read-only filesystems can make chmod unavailable.  The
        # caller still gets the normal filesystem error for the actual write.
        pass
    return path


def ensure_dir(path: Path, mode: int = 0o700) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if not is_windows():
        restrict_permissions(path, mode)
    return path


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> Path:
    """Atomically replace a local file and apply restrictive permissions."""
    ensure_dir(path.parent)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        restrict_permissions(temporary, mode)
        os.replace(temporary, path)
        restrict_permissions(path, mode)
    except BaseException:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise
    return path


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8", mode: int = 0o600) -> Path:
    """Atomically write text using a temporary file in the destination dir."""
    return atomic_write_bytes(path, text.encode(encoding), mode=mode)


def normalize_path(path: str | Path) -> Path:
    """Expand ~ and resolve without requiring the path to exist."""
    p = Path(path).expanduser()
    try:
        return p.resolve(strict=False)
    except Exception:
        return p.absolute()
