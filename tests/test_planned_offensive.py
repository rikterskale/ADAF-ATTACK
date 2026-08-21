"""Catalog of the 40 promoted offensive capabilities stays unique and registered."""

from __future__ import annotations

import pytest

from adaf_attack.capabilities.planned_offensive import (
    PLANNED_CAPABILITIES,
    catalog_entry,
    planned_destructive_ids,
    planned_ids,
    register_from_catalog,
)
from adaf_attack.core.registry import capability_registry


def test_planned_ids_are_unique() -> None:
    ids = planned_ids()
    assert len(ids) == len(set(ids))
    assert len(ids) == 40


def test_destructive_flags_match_tuple() -> None:
    destructive = set(planned_destructive_ids())
    for cap_id, _summary, is_destructive, *_rest in PLANNED_CAPABILITIES:
        cap = capability_registry.get(cap_id)
        assert cap is not None
        assert cap.destructive is is_destructive
        if is_destructive:
            assert cap_id in destructive


def test_promoted_capabilities_are_supported_not_experimental() -> None:
    for cap_id in planned_ids():
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
