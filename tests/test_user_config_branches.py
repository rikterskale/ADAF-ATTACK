"""Branch-closure tests for per-user config helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adaf_attack.core import user_config


@pytest.fixture(autouse=True)
def _config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_CONFIG_DIR", str(tmp_path / "config"))


def test_favorite_capabilities_non_list_value() -> None:
    user_config.save_user_config({"ui.favorite_capabilities": "not-a-list"})
    assert user_config.favorite_capabilities() == []
    updated = user_config.set_favorite_capability("ldap-enum", favorite=True)
    assert updated == ["ldap-enum"]
    assert user_config.set_favorite_capability("ldap-enum", favorite=False) == []


def test_saved_missions_round_trip_and_non_list_value() -> None:
    user_config.save_user_config({"ui.saved_missions": "not-a-list"})
    assert user_config.saved_missions() == []
    assert user_config.set_saved_mission("tier-0-paths", saved=True) == ["tier-0-paths"]
    assert user_config.set_saved_mission("tier-0-paths", saved=True) == ["tier-0-paths"]
    assert user_config.set_saved_mission("tier-0-paths", saved=False) == []


def test_record_recent_target_requires_domain_and_dc(tmp_path: Path) -> None:
    assert user_config.record_recent_target("", "", "high-value") == []
    entry = user_config.record_recent_target("corp.example", "10.0.0.10", " domain ")
    assert entry[0]["domain"] == "corp.example"
    # Duplicate entries are not repeated.
    again = user_config.record_recent_target("corp.example", "10.0.0.10", "domain")
    assert again.count(again[0]) == 1
    path = user_config.config_path()
    assert isinstance(json.loads(path.read_text(encoding="utf-8")), dict)


def test_recent_targets_skips_malformed_entries() -> None:
    user_config.save_user_config(
        {
            "ui.recent_targets": [
                "not-a-dict",
                {"domain": 1, "dc_ip": "x"},
                {"domain": "d", "dc_ip": "1.1.1.1"},
            ]
        }
    )
    targets = user_config.recent_targets()
    assert targets == [{"domain": "d", "dc_ip": "1.1.1.1", "scope": "high-value"}]

    user_config.save_user_config({"ui.recent_targets": None})
    assert user_config.recent_targets() == []
