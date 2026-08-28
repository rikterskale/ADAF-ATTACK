"""Catalog of the 40 promoted offensive capabilities stays unique and registered."""

from __future__ import annotations

from pathlib import Path

import pytest

from adaf_attack.capabilities.capability_catalog import (
    CAPABILITY_CATALOG,
    catalog_destructive_ids,
    catalog_entry,
    catalog_ids,
    register_from_catalog,
)
from adaf_attack.core.registry import (
    KNOWN_ENVIRONMENTS,
    ApprovalPolicy,
    Capability,
    RiskLevel,
    SafetyProfile,
    capability_registry,
    infer_environment,
)


def test_generated_catalog_has_no_unknown_environment() -> None:
    catalog = (Path(__file__).resolve().parents[1] / "docs" / "CAPABILITY_CATALOG.md").read_text(
        encoding="utf-8"
    )
    assert "| unknown |" not in catalog


def test_catalog_ids_are_unique() -> None:
    ids = catalog_ids()
    assert len(ids) == len(set(ids))
    assert len(ids) == 40


def test_destructive_flags_match_tuple() -> None:
    destructive = set(catalog_destructive_ids())
    for cap_id, _summary, is_destructive, *_rest in CAPABILITY_CATALOG:
        cap = capability_registry.get(cap_id)
        assert cap is not None
        assert cap.destructive is is_destructive
        if is_destructive:
            assert cap_id in destructive


def test_promoted_capabilities_are_supported_not_experimental() -> None:
    for cap_id in catalog_ids():
        cap = capability_registry.get(cap_id)
        assert cap is not None, cap_id
        assert cap.runner is not None, cap_id
        assert "experimental" not in cap.tags
        assert "tracking" not in cap.tags


def test_catalog_entry_and_unknown_id() -> None:
    item = catalog_entry("add-member")
    assert item[0] == "add-member"
    with pytest.raises(KeyError):
        catalog_entry("not-a-real-capability")


def test_register_from_catalog_rejects_duplicate() -> None:
    with pytest.raises(ValueError, match="already registered"):

        @register_from_catalog("add-member")
        class _Dup:
            def run(self, *args: object, **kwargs: object) -> dict[str, object]:
                return {}


def test_registered_capabilities_have_known_environments() -> None:
    for cap in capability_registry.list():
        assert cap.environment in KNOWN_ENVIRONMENTS, cap.id


def test_infer_environment_from_safety_and_category() -> None:
    assert infer_environment(environment="live-read-only") == "live-read-only"
    assert infer_environment(environment="offline") == "offline"
    assert infer_environment(environment="live-mutating") == "live-mutating"
    assert infer_environment(destructive=True) == "live-mutating"
    assert infer_environment(safety=SafetyProfile(modifies_directory=True)) == "live-mutating"
    assert infer_environment(safety=SafetyProfile(network_side_effect=True)) == "live-mutating"
    assert (
        infer_environment(safety=SafetyProfile(approval=ApprovalPolicy.FORCE_AND_ACK))
        == "live-mutating"
    )
    assert infer_environment(safety=SafetyProfile(risk=RiskLevel.DESTRUCTIVE)) == "live-mutating"
    assert infer_environment(safety=SafetyProfile(risk=RiskLevel.SIDE_EFFECT)) == "live-mutating"
    assert infer_environment(category="analysis") == "offline"
    assert infer_environment(category="export") == "offline"
    assert infer_environment(tags=("vault",)) == "offline"
    assert infer_environment(category="enumeration") == "live-read-only"
    assert infer_environment() == "live-read-only"


def test_capability_infers_environment_when_unknown() -> None:
    cap = Capability(id="test-enum", summary="Observe LDAP", category="enumeration")
    assert cap.environment == "live-read-only"
    mutating = Capability(
        id="test-write",
        summary="Mutate",
        destructive=True,
        category="privilege-escalation",
    )
    assert mutating.environment == "live-mutating"
    offline = Capability(
        id="test-report",
        summary="Report",
        category="export",
    )
    assert offline.environment == "offline"
    explicit = Capability(
        id="test-explicit",
        summary="Explicit",
        environment="live-read-only",
        category="enumeration",
    )
    assert explicit.environment == "live-read-only"
