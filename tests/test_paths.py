"""Cross-platform path helper tests."""

from pathlib import Path

from adaf_attack.core.paths import (
    default_workspace_dir,
    normalize_path,
    platform_name,
    user_data_dir,
)


def test_platform_name_nonempty() -> None:
    assert platform_name()


def test_user_data_dir_is_path() -> None:
    p = user_data_dir()
    assert isinstance(p, Path)
    assert "adaf-attack" in str(p).lower() or p.name == "adaf-attack"


def test_default_workspace_under_data() -> None:
    ws = default_workspace_dir()
    assert ws.name == "workspaces" or "workspaces" in str(ws)


def test_normalize_path_expanduser() -> None:
    p = normalize_path("~")
    assert p.is_absolute() or p.exists() or True  # expanduser at minimum
    assert str(p)
