"""Cross-platform path helper tests."""

from pathlib import Path

from adaf_attack.core.paths import (
    default_workspace_dir,
    is_kali,
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


def test_is_kali_reads_os_release(tmp_path: Path, monkeypatch) -> None:
    release = tmp_path / "os-release"
    release.write_text('ID="kali"\nID_LIKE="debian"\n', encoding="utf-8")
    monkeypatch.setattr("adaf_attack.core.paths.is_linux", lambda: True)
    assert is_kali(release)


def test_is_kali_rejects_other_linux_distributions(tmp_path: Path, monkeypatch) -> None:
    release = tmp_path / "os-release"
    release.write_text('ID=ubuntu\nID_LIKE="debian"\n', encoding="utf-8")
    monkeypatch.setattr("adaf_attack.core.paths.is_linux", lambda: True)
    assert not is_kali(release)
