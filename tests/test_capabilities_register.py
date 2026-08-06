"""Ensure capability modules register on import."""

import adaf_attack.capabilities  # noqa: F401
from adaf_attack.core.registry import capability_registry


def test_core_capabilities_registered() -> None:
    ids = set(capability_registry.ids())
    expected = {
        "ldap-enum",
        "kerberoast",
        "asrep-roast",
        "trusts-enum",
        "adcs-enum",
        "acl-enum",
        "gmsa-laps-enum",
        "bloodhound-export",
    }
    missing = expected - ids
    assert not missing, f"Missing capabilities: {missing}"
