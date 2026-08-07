"""Platform-branch coverage for cross-platform path helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import adaf_attack.core.paths as paths


def _force_platform(
    monkeypatch: Any, *, windows: bool = False, macos: bool = False, linux: bool = False
) -> None:
    monkeypatch.setattr(paths, "is_windows", lambda: windows)
    monkeypatch.setattr(paths, "is_macos", lambda: macos)
    monkeypatch.setattr(paths, "is_linux", lambda: linux)
    monkeypatch.setattr(paths, "is_kali", lambda *a, **k: False)


def test_platform_predicates_match_sys_platform(monkeypatch: Any) -> None:
    monkeypatch.setattr(paths.sys, "platform", "win32")
    assert paths.is_windows() and not paths.is_macos() and not paths.is_linux()
    monkeypatch.setattr(paths.sys, "platform", "darwin")
    assert paths.is_macos() and not paths.is_windows()
    monkeypatch.setattr(paths.sys, "platform", "linux")
    assert paths.is_linux()


def test_is_kali_returns_false_off_linux(monkeypatch: Any) -> None:
    monkeypatch.setattr(paths, "is_linux", lambda: False)
    assert paths.is_kali(Path("/nonexistent/os-release")) is False


def test_is_kali_handles_missing_file(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(paths, "is_linux", lambda: True)
    assert paths.is_kali(tmp_path / "does-not-exist") is False


def test_platform_name_branches(monkeypatch: Any) -> None:
    _force_platform(monkeypatch, windows=True)
    assert paths.platform_name() == "Windows"
    _force_platform(monkeypatch, macos=True)
    assert paths.platform_name() == "macOS"
    _force_platform(monkeypatch, linux=True)
    monkeypatch.setattr(paths, "is_kali", lambda *a, **k: True)
    assert paths.platform_name() == "Kali Linux"
    _force_platform(monkeypatch, linux=True)
    assert paths.platform_name() == "Linux"
    _force_platform(monkeypatch)
    monkeypatch.setattr(paths.sys, "platform", "sunos")
    assert paths.platform_name() == "sunos"


def test_user_data_dir_windows(monkeypatch: Any) -> None:
    _force_platform(monkeypatch, windows=True)
    monkeypatch.setenv("LOCALAPPDATA", str(Path("C:/Users/x/AppData/Local")))
    assert paths.user_data_dir().name == "adaf-attack"


def test_user_data_dir_windows_without_localappdata(monkeypatch: Any) -> None:
    _force_platform(monkeypatch, windows=True)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    assert paths.user_data_dir().name == "adaf-attack"


def test_user_data_dir_macos(monkeypatch: Any) -> None:
    _force_platform(monkeypatch, macos=True)
    p = paths.user_data_dir()
    assert "Application Support" in str(p)


def test_user_data_dir_linux_xdg(monkeypatch: Any, tmp_path: Path) -> None:
    _force_platform(monkeypatch, linux=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert paths.user_data_dir() == tmp_path / "adaf-attack"


def test_user_data_dir_linux_default(monkeypatch: Any) -> None:
    _force_platform(monkeypatch, linux=True)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert str(paths.user_data_dir()).endswith(str(Path(".local") / "share" / "adaf-attack"))


def test_user_config_dir_branches(monkeypatch: Any, tmp_path: Path) -> None:
    _force_platform(monkeypatch, windows=True)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert paths.user_config_dir() == tmp_path / "adaf-attack" / "config"

    _force_platform(monkeypatch, macos=True)
    assert "Preferences" in str(paths.user_config_dir())

    _force_platform(monkeypatch, linux=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert paths.user_config_dir() == tmp_path / "adaf-attack"

    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    assert str(paths.user_config_dir()).endswith(str(Path(".config") / "adaf-attack"))


def test_default_workspace_dir_env_override(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "ws"))
    assert paths.default_workspace_dir() == tmp_path / "ws"


def test_ensure_dir_creates(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b"
    out = paths.ensure_dir(target)
    assert out == target and target.is_dir()


def test_normalize_path_absolute_fallback(monkeypatch: Any) -> None:
    class _P:
        def expanduser(self) -> Any:
            return self

        def resolve(self, strict: bool = False) -> Any:
            raise OSError("boom")

        def absolute(self) -> str:
            return "/abs/path"

    monkeypatch.setattr(paths, "Path", lambda _p: _P())
    assert paths.normalize_path("whatever") == "/abs/path"
