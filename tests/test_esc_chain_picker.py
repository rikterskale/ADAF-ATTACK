"""ESC-chain template-selection tests (pure Python)."""

from __future__ import annotations

from adaf_attack.capabilities.esc_chain import _pick_template


def test_picks_esc1_over_esc4() -> None:
    adcs = {
        "templates": [
            {"name": "GenericUser", "esc": ["ESC4"], "ca": "CA-1"},
            {"name": "UserESC1", "esc": ["ESC1"], "ca": "CA-1"},
        ]
    }
    chosen = _pick_template(adcs)
    assert chosen and chosen["name"] == "UserESC1"


def test_ignores_templates_without_signals() -> None:
    adcs = {"templates": [{"name": "Boring", "ca": "CA-1"}]}
    assert _pick_template(adcs) is None


def test_reads_esc_signals_alias() -> None:
    adcs = {
        "templates": [
            {"name": "Old", "esc_signals": ["ESC8"], "ca": "CA-1"},
            {"name": "New", "esc_signals": ["ESC3"], "ca": "CA-1"},
        ]
    }
    chosen = _pick_template(adcs)
    assert chosen and chosen["name"] == "New"
