"""Behavioral tests for curated grouped capability selection."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

import adaf_attack.capabilities.credential_free as credential_free
from adaf_attack.cli import app
from adaf_attack.core.capability_profiles import profile_plan, resolve_profile
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

runner = CliRunner()


def test_adcs_profile_is_read_only_by_default_and_reports_skips() -> None:
    plan = profile_plan("adcs")

    assert plan["count"] > 0
    assert plan["read_only"] is True
    assert "adcs-enum" in [item["id"] for item in plan["capabilities"]]
    assert any(item["id"] == "esc9" for item in plan["skipped"])


def test_mutating_profile_selection_is_explicit() -> None:
    safe = resolve_profile("persistence")
    approved = resolve_profile("persistence", include_mutating=True)

    assert safe["capabilities"] == []
    assert {cap.id for cap in approved["capabilities"]} == {
        "adminsdholder-persist",
        "dcshadow",
        "golden-cert",
    }


def test_profile_list_json_is_stable() -> None:
    result = runner.invoke(app, ["--format", "json", "capability-profile", "list"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["count"] == 6
    assert {item["id"] for item in payload["profiles"]} == {
        "recon",
        "adcs",
        "lateral-movement",
        "persistence",
        "unauthenticated",
        "offline-analysis",
    }


def test_profile_run_requires_confirmation_before_target_contact() -> None:
    workspace = "profile-confirmation-test-workspace"
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "capability-profile",
            "run",
            "recon",
            "--domain",
            "corp.example",
            "--dc-ip",
            "10.0.0.10",
            "--workspace",
            workspace,
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["error"]["code"] == "PROFILE_CONFIRMATION_REQUIRED"


def test_unauthenticated_profile_labels_username_and_noise_requirements() -> None:
    default = profile_plan("unauthenticated")
    with_user_list = profile_plan("unauthenticated", include_username_dependent=True)
    with_noise = profile_plan("unauthenticated", include_noisy=True)

    assert any(item["id"] == "asreq-userhunt" for item in default["skipped"])
    assert "asreq-userhunt" in [item["id"] for item in with_user_list["capabilities"]]
    assert any(item["id"] == "pre2k-spray" for item in default["skipped"])
    assert any(item["id"] == "pre2k-spray" for item in with_noise["skipped"])
    with_mutating = profile_plan("unauthenticated", include_noisy=True, include_mutating=True)
    assert "pre2k-spray" in [item["id"] for item in with_mutating["capabilities"]]


def test_offline_profile_is_plan_only_and_lists_saved_evidence_steps() -> None:
    plan = profile_plan("offline-analysis")

    assert plan["mode"] == "offline"
    assert "credential-exposure" in plan["workflow_steps"]
    assert "engagement report" in plan["workflow_steps"]
    assert all(item["environment"] == "offline" for item in plan["capabilities"])


def test_credential_free_network_capabilities_write_redacted_posture(
    tmp_path: Path, monkeypatch: object
) -> None:
    session = Session(base_dir=tmp_path)
    target = Target(domain="corp.example", dc_ip="192.0.2.10")

    def fake_probe(host: str, port: int, timeout: float) -> dict[str, object]:
        return {
            "port": port,
            "service": credential_free._POSTURE_PORTS[port],
            "reachable": port in {389, 443},
        }

    monkeypatch.setattr(credential_free, "_tcp_probe", fake_probe)

    passive = credential_free.PassiveDiscovery().run(target, session, AttackGraph())
    exposure = credential_free.ExternalExposure().run(target, session, AttackGraph())

    assert passive["authentication"] == "anonymous"
    assert passive["reachable_services"] == ["ldap", "https"]
    assert len(exposure["signals"]) == 2
    assert session.path("passive-discovery.json").is_file()
    assert session.path("external-exposure.json").is_file()


def test_anonymous_ldap_probe_records_read_matrix(tmp_path: Path, monkeypatch: object) -> None:
    class FakeInfo:
        other = {"defaultNamingContext": ["DC=corp,DC=example"]}

    class FakeServer:
        info = FakeInfo()

    class FakeConnection:
        bound = True
        entries = [object()]

        def __init__(self, server: object, **kwargs: object) -> None:
            self.server = server

        def search(self, *args: object, **kwargs: object) -> bool:
            return True

        def unbind(self) -> None:
            return None

    monkeypatch.setattr(credential_free, "Server", lambda *args, **kwargs: FakeServer())
    monkeypatch.setattr(credential_free, "Connection", FakeConnection)
    session = Session(base_dir=tmp_path)
    result = credential_free.AnonymousLdapProbe().run(
        Target(domain="corp.example", dc_ip="192.0.2.10"), session, AttackGraph()
    )

    assert result["ok"] is True
    assert {item["name"] for item in result["checks"]} == {
        "anonymous_bind",
        "naming_context",
        "users",
        "computers",
        "groups",
    }
