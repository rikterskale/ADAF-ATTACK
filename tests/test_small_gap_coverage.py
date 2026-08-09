"""Small-gap coverage for creds, runner, esc6, forest_campaign, and report edges."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import adaf_attack.core.esc6_probe as esc6
import adaf_attack.core.forest_campaign as fc
import adaf_attack.core.runner as runner_mod
import pytest
from adaf_attack.core.creds import (
    Credential,
    CredentialSet,
    first_working_target,
    load_credentials_json,
)
from adaf_attack.core.engagement import EngagementError, load_plan
from adaf_attack.core.runner import _resolve_target
from adaf_attack.core.target import Target

# --------------------------- creds ---------------------------


def test_credential_helpers() -> None:
    a = Credential(username="alice", password="p", label="A")
    b = Credential(username="bob", hashes=":aabb")
    empty = Credential(username="mallory")
    cs = CredentialSet(credentials=[a, b, empty])
    assert cs.labels() == ["A", "bob", "mallory"]
    assert cs.by_label("A") is a
    assert cs.by_label("missing") is None
    order = list(cs.rotate(start=1))
    assert order[0].username == "bob"
    targets = cs.to_targets("10.0.0.1", domain="corp.test")
    assert [t.username for t in targets] == ["alice", "bob", "mallory"]
    red = cs.dump_redacted()
    assert red[0]["password"] == "***"
    assert red[1]["hashes"] == "***"


def test_credential_set_empty_rotate_yields_nothing() -> None:
    assert list(CredentialSet().rotate()) == []


def test_load_credentials_json_shapes(tmp_path: Path) -> None:
    dict_form = tmp_path / "d.json"
    dict_form.write_text(
        json.dumps({"credentials": [{"username": "a", "password": "p"}]}), encoding="utf-8"
    )
    assert len(load_credentials_json(dict_form)) == 1

    list_form = tmp_path / "l.json"
    list_form.write_text(json.dumps([{"username": "b"}]), encoding="utf-8")
    assert len(load_credentials_json(list_form)) == 1

    # entry without username → skipped
    junk = tmp_path / "j.json"
    junk.write_text(json.dumps([{"no": "user"}, "not-a-dict"]), encoding="utf-8")
    assert len(load_credentials_json(junk)) == 0

    bad = tmp_path / "b.json"
    bad.write_text(json.dumps(42), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported credentials JSON shape"):
        load_credentials_json(bad)


def test_first_working_target_variants() -> None:
    empty = Credential(username="skip")
    good = Credential(username="alice", password="pw")
    bad = Credential(username="bad", password="pw")
    cs = CredentialSet(credentials=[empty, good, bad])

    # without probe → first with secrets
    t = first_working_target(cs, "10.0.0.1", "corp.test")
    assert t is not None and t.username == "alice"

    # probe path: first True wins
    def probe(target: Target) -> bool:
        return target.username == "alice"

    assert first_working_target(cs, "10.0.0.1", "corp.test", probe=probe).username == "alice"

    # probe raising falls through
    def broken_probe(target: Target) -> bool:
        raise RuntimeError("boom")

    assert first_working_target(cs, "10.0.0.1", "corp.test", probe=broken_probe) is None

    # probe returning False for every candidate → None
    assert first_working_target(cs, "10.0.0.1", "corp.test", probe=lambda t: False) is None


# --------------------------- runner ---------------------------


def test_probe_ldap_success_and_failure(monkeypatch: Any) -> None:
    class _OK:
        def unbind(self) -> None:
            pass

    def ok_connect(target: Target) -> Any:
        return _OK(), "DC=x", None

    import adaf_attack.core.ldap_util as ldap_util

    monkeypatch.setattr(ldap_util, "ldap_connect", ok_connect)
    assert runner_mod._probe_ldap(Target(domain="c", dc_ip="1.1.1.1")) is True

    def boom(target: Target) -> Any:
        raise RuntimeError("no bind")

    monkeypatch.setattr(ldap_util, "ldap_connect", boom)
    assert runner_mod._probe_ldap(Target(domain="c", dc_ip="1.1.1.1")) is False


def test_resolve_target_loads_creds_file(tmp_path: Path, monkeypatch: Any) -> None:
    creds_file = tmp_path / "c.json"
    creds_file.write_text(json.dumps([{"username": "alice", "password": "pw"}]), encoding="utf-8")
    monkeypatch.setattr(runner_mod, "_probe_ldap", lambda target: True)
    chosen, attempts = _resolve_target(
        Target(domain="corp.test", dc_ip="10.0.0.1"), creds_file=creds_file
    )
    assert chosen.username == "alice"
    assert any("ok" in a for a in attempts)


def test_resolve_target_single_credentialed_probe_failure(monkeypatch: Any) -> None:
    monkeypatch.setattr(runner_mod, "_probe_ldap", lambda target: False)
    with pytest.raises(runner_mod.RunError, match="LDAP bind failed"):
        _resolve_target(Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p"))


def test_resolve_target_primary_appended_when_distinct(monkeypatch: Any) -> None:
    monkeypatch.setattr(runner_mod, "_probe_ldap", lambda target: target.username == "primary")
    cs = CredentialSet(credentials=[Credential(username="other", password="x")])
    chosen, attempts = _resolve_target(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="primary", password="y"),
        credential_set=cs,
    )
    assert chosen.username == "primary"


# --------------------------- engagement plan errors ---------------------------


def test_load_plan_missing_dc_ip(tmp_path: Path) -> None:
    p = tmp_path / "plan.yaml"
    p.write_text(
        json.dumps(
            {
                "engagement_id": "E",
                "target": {"domain": "corp.test"},
                "allowed_capabilities": [],
                "phases": [],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(EngagementError, match="target.domain and target.dc_ip"):
        load_plan(p)


# --------------------------- esc6_probe remaining branches ---------------------------


def test_probe_esc6_certutil_ok_but_no_esc6_key(monkeypatch: Any) -> None:
    # When certutil returns ok but no 'esc6' field → falls through to RRP loop
    monkeypatch.setattr(
        esc6, "probe_certutil", lambda ca_config=None: {"method": "certutil", "ok": True}
    )
    monkeypatch.setattr(
        esc6,
        "probe_impacket_rrp",
        lambda target, ca_hostname=None: {"method": "impacket-rrp", "ok": False},
    )
    t = Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p")
    r = esc6.probe_esc6(t, ca_hostnames=["ca"])
    assert r["resolved"] is False


# --------------------------- forest_campaign manifest loader ---------------------------


def test_load_campaign_manifest_variants(tmp_path: Path) -> None:
    with pytest.raises(fc.CampaignError, match="Cannot load campaign YAML"):
        fc.load_campaign_manifest(tmp_path / "does-not-exist.yaml")

    empty = tmp_path / "empty.yaml"
    empty.write_text("{}", encoding="utf-8")
    with pytest.raises(fc.CampaignError, match="campaign_id"):
        fc.load_campaign_manifest(empty)

    no_plan = tmp_path / "no_plan.yaml"
    no_plan.write_text(json.dumps({"campaign_id": "C", "engagements": [{}]}), encoding="utf-8")
    with pytest.raises(fc.CampaignError, match="must specify a plan path"):
        fc.load_campaign_manifest(no_plan)

    missing_plan = tmp_path / "missing.yaml"
    missing_plan.write_text(
        json.dumps({"campaign_id": "C", "engagements": [{"plan": "no.yaml"}]}), encoding="utf-8"
    )
    with pytest.raises(fc.CampaignError, match="Engagement plan not found"):
        fc.load_campaign_manifest(missing_plan)

    # happy path
    real_plan = tmp_path / "plan.yaml"
    real_plan.write_text("engagement_id: E\n", encoding="utf-8")
    manifest = tmp_path / "campaign.yaml"
    manifest.write_text(
        json.dumps({"campaign_id": "C", "engagements": [{"plan": "plan.yaml"}]}),
        encoding="utf-8",
    )
    cid, plans = fc.load_campaign_manifest(manifest)
    assert cid == "C" and len(plans) == 1


def test_campaign_handoff_validations(tmp_path: Path) -> None:
    manifest = tmp_path / "m.yaml"
    manifest.write_text("dummy: true", encoding="utf-8")

    with pytest.raises(fc.CampaignError, match="allow: true"):
        fc._handoff_ccache({"credential_handoff": {"allow": False}}, manifest)
    with pytest.raises(fc.CampaignError, match="only the explicit vault item 'tgt'"):
        fc._handoff_ccache({"credential_handoff": {"allow": True, "item": "cert"}}, manifest)
    # None → passthrough
    assert fc._handoff_ccache({}, manifest) == (None, None)
