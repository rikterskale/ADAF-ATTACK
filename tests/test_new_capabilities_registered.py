"""Smoke tests that every new capability registers with a valid option spec."""

from __future__ import annotations

import pytest

import adaf_attack.capabilities  # noqa: F401 — triggers registration
from adaf_attack.capabilities.planned_offensive import planned_ids
from adaf_attack.core.capability_help_data import capability_option_spec
from adaf_attack.core.registry import capability_registry

NEW_IDS = [
    "dcsync",
    "password-spray",
    "laps-read",
    "gpp-cpassword-hunt",
    "unpac-the-hash",
    "ticket-forge",
    "s4u-abuse",
    "asreq-userhunt",
    "coerce",
    "ntlm-relay",
    "esc-chain",
    "template-mod",
    "secretsdump-local",
    "impacket-exec",
    "ad-cve-scan",
]

TRACKING_IDS = list(planned_ids())


@pytest.mark.parametrize("cap_id", NEW_IDS)
def test_capability_is_registered(cap_id: str) -> None:
    cap = capability_registry.get(cap_id)
    assert cap is not None, f"Missing capability: {cap_id}"
    assert cap.runner is not None, f"Capability {cap_id} has no runner"


@pytest.mark.parametrize("cap_id", NEW_IDS)
def test_capability_option_spec_present(cap_id: str) -> None:
    cap = capability_registry.get(cap_id)
    assert cap is not None
    spec = capability_option_spec(cap_id, cap.destructive)
    assert spec.required or spec.optional, f"No spec entries for {cap_id}"


@pytest.mark.parametrize("cap_id", TRACKING_IDS)
def test_promoted_capability_is_registered(cap_id: str) -> None:
    cap = capability_registry.get(cap_id)
    assert cap is not None, f"Missing capability: {cap_id}"
    assert cap.runner is not None, f"Capability {cap_id} has no runner"
    assert "experimental" not in cap.tags
    assert "tracking" not in cap.tags
