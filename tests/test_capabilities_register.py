"""Ensure capability modules register on import."""

import adaf_attack.capabilities  # noqa: F401
from adaf_attack.core.registry import capability_registry, registration_gaps


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


def test_every_builtin_capability_module_is_registered() -> None:
    gaps = registration_gaps()
    assert not gaps["unregistered_modules"], gaps


def test_registered_capabilities_expose_operator_run_contracts() -> None:
    for capability in capability_registry.list():
        runner = capability.runner
        if runner is None or not runner.__class__.__module__.startswith("adaf_attack.capabilities"):
            continue
        assert runner.run.__doc__, f"Missing run contract for {capability.id}"
