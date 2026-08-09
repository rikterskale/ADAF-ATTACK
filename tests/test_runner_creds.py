"""Runner credential rotation unit tests (offline, mocked probe)."""

from unittest.mock import patch

import pytest
from adaf_attack.core.creds import Credential, CredentialSet
from adaf_attack.core.runner import RunError, _resolve_target
from adaf_attack.core.target import Target


def test_single_anonymous_no_probe() -> None:
    t = Target(domain="corp.local", dc_ip="10.0.0.1")
    chosen, attempts = _resolve_target(t)
    assert chosen is t
    assert attempts


def test_rotation_picks_second_working() -> None:
    primary = Target(domain="corp.local", dc_ip="10.0.0.1", username="bad", password="x")
    cs = CredentialSet(
        credentials=[
            Credential(username="bad", password="x", domain="corp.local"),
            Credential(username="good", password="y", domain="corp.local", label="good"),
        ]
    )

    def fake_probe(target: Target) -> bool:
        return target.username == "good"

    with patch("adaf_attack.core.runner._probe_ldap", side_effect=fake_probe):
        chosen, attempts = _resolve_target(primary, credential_set=cs)
    assert chosen.username == "good"
    assert any("ok" in a for a in attempts)
    assert any("failed" in a for a in attempts)


def test_all_creds_fail_raises() -> None:
    primary = Target(domain="corp.local", dc_ip="10.0.0.1", username="a", password="x")
    cs = CredentialSet(
        credentials=[
            Credential(username="a", password="x"),
            Credential(username="b", password="y"),
        ]
    )
    with (
        patch("adaf_attack.core.runner._probe_ldap", return_value=False),
        pytest.raises(RunError, match="All credentials failed"),
    ):
        _resolve_target(primary, credential_set=cs)
