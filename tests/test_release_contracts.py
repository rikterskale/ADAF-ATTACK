"""Release-readiness contracts enforced automatically in CI.

These convert two gates from docs/RELEASE_READINESS.md into build failures:

* §3 Full-feature validation - every registered capability is reachable: it is
  listed by `list-capabilities` and `capability-help` returns a payload. A
  shipped capability can never be a dead id.
* §4 Tested recovery paths - every capability that mutates revertable target
  state wires a rollback primitive (`register_cleanup` / `record_pre_state`), or
  is explicitly exempted here with a reason. A new destructive capability that
  forgets recovery fails the build until it wires one or is consciously exempted.

They run in the `tests` matrix job (all supported OS/Python combinations).
"""

from __future__ import annotations

import inspect
import json

from typer.testing import CliRunner

import adaf_attack.capabilities  # noqa: F401  # registers every capability
from adaf_attack.cli import app
from adaf_attack.core.registry import capability_registry

runner = CliRunner()

_ROLLBACK_PRIMITIVES = (
    "register_cleanup",
    "record_pre_state",
    "register_attr_rollback",
    "register_add_value_rollback",
    "register_object_rollback",
    "register_advisory_rollback",
)

# Destructive capabilities that legitimately record no target rollback, each
# with the reason. Adding an id here is a reviewable, deliberate exception; the
# default expectation for a destructive capability is to wire a rollback.
_ROLLBACK_EXEMPT: dict[str, str] = {
    "rollback": "executes the revert itself; there is no prior state to record",
    "campaign-run": "orchestrator; each sub-capability registers its own rollback",
    "credential-inventory": "purges local session/vault material, not remote AD state",
    "cert-request": "requests a certificate from the CA; revocation is out of scope",
    "pkinit-auth": "authenticates to obtain a ticket; performs no target-state mutation",
    "rbcd-ticket-workflow": "composite delegating to rbcd, which records the rollback",
    "shadow-pkinit-workflow": "composite delegating to shadow-creds, which records the rollback",
}


def test_every_capability_is_reachable() -> None:
    """§3: every registered capability is listed and has working help."""
    caps = capability_registry.list()
    assert caps, "no capabilities registered"

    listed = runner.invoke(app, ["--format", "json", "list-capabilities"])
    assert listed.exit_code == 0, listed.output
    listed_ids = {row["id"] for row in json.loads(listed.output)["capabilities"]}

    for cap in caps:
        assert cap.id in listed_ids, f"{cap.id} is registered but missing from list-capabilities"
        helped = runner.invoke(app, ["--format", "json", "capability-help", cap.id])
        assert helped.exit_code == 0, f"capability-help failed for {cap.id}: {helped.output}"
        assert json.loads(helped.output).get("ok") is True, f"capability-help not ok for {cap.id}"


def test_destructive_capabilities_declare_rollback_or_are_exempt() -> None:
    """§4: destructive capabilities wire a rollback primitive or are exempted."""
    missing_rollback: list[str] = []
    stale_exemptions: list[str] = []
    for cap in capability_registry.list():
        if not cap.destructive:
            continue
        module = inspect.getmodule(type(cap.runner))
        assert module is not None, f"cannot resolve module for {cap.id}"
        wires_rollback = any(token in inspect.getsource(module) for token in _ROLLBACK_PRIMITIVES)
        if cap.id in _ROLLBACK_EXEMPT:
            if wires_rollback:
                stale_exemptions.append(cap.id)
            continue
        if not wires_rollback:
            missing_rollback.append(cap.id)

    assert not missing_rollback, (
        "destructive capabilities with no rollback primitive "
        f"{_ROLLBACK_PRIMITIVES} - wire one or add to _ROLLBACK_EXEMPT with a reason: "
        f"{sorted(missing_rollback)}"
    )
    assert not stale_exemptions, (
        "these capabilities now wire a rollback; remove them from _ROLLBACK_EXEMPT: "
        f"{sorted(stale_exemptions)}"
    )


def test_rollback_exemptions_stay_relevant() -> None:
    """The exemption allowlist must not accumulate stale ids."""
    destructive_ids = {cap.id for cap in capability_registry.list() if cap.destructive}
    unknown = sorted(set(_ROLLBACK_EXEMPT) - destructive_ids)
    assert not unknown, f"rollback exemptions that are not destructive capabilities: {unknown}"
