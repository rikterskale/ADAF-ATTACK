"""Behavioral tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

import adaf_attack.cli as cli
import adaf_attack.core.workflows as workflows
from adaf_attack.cli import app
from adaf_attack.core.runner import RunError

runner = CliRunner()


def _ok(result: Any) -> None:
    assert result.exit_code == 0, result.output


# --------------------------- global + simple commands ---------------------------


def test_version_human() -> None:
    _ok(runner.invoke(app, ["--version"]))


def test_no_subcommand_prints_help() -> None:
    result = runner.invoke(app, ["--no-color"])
    assert result.exit_code == 0


def test_doctor_human_explain() -> None:
    result = runner.invoke(app, ["doctor", "--explain"])
    _ok(result)
    assert "doctor" in result.output.lower()


def test_list_capabilities_human() -> None:
    result = runner.invoke(app, ["list-capabilities"])
    _ok(result)
    assert "Capabilities" in result.output


def test_list_capabilities_full_and_copy_are_explicit(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        cli, "copy_to_clipboard", lambda value: {"ok": True, "characters": len(value)}
    )
    result = runner.invoke(app, ["--format", "json", "list-capabilities", "--full", "--copy"])
    _ok(result)
    payload = json.loads(result.output)
    assert payload["full"] is True
    assert payload["clipboard"]["ok"] is True


def test_paths_human() -> None:
    _ok(runner.invoke(app, ["paths"]))


def test_capability_help_all_human() -> None:
    result = runner.invoke(app, ["capability-help"])
    _ok(result)
    assert "reference" in result.output.lower()


def test_capability_help_single_human() -> None:
    result = runner.invoke(app, ["capability-help", "acl-enum"])
    _ok(result)
    assert "acl-enum" in result.output


def test_plan_human() -> None:
    result = runner.invoke(
        app, ["plan", "acl-enum", "--domain", "corp.test", "--dc-ip", "10.0.0.1"]
    )
    _ok(result)
    assert "Plan preview" in result.output


def test_plan_unknown_capability_human() -> None:
    result = runner.invoke(app, ["plan", "nope", "--domain", "corp.test", "--dc-ip", "10.0.0.1"])
    assert result.exit_code == 1
    assert "UNKNOWN_CAPABILITY" in result.output


def test_ad_recon_profile_and_template(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--format", "json", "ad-recon", "profile"])
    _ok(result)
    payload = json.loads(result.output)
    assert payload["read_only"] is True
    assert "ldap-enum" in payload["plan"]["allowed_capabilities"]

    output = tmp_path / "ad-recon.yaml"
    result = runner.invoke(app, ["ad-recon", "init", "--output", str(output)])
    _ok(result)
    text = output.read_text(encoding="utf-8")
    assert "identity-and-topology" in text
    assert "gmsa-laps-enum" in text


# --------------------------- sessions + cleanup ---------------------------


def _make_session(root: Path, name: str = "sess-1") -> Path:
    sdir = root / name
    sdir.mkdir(parents=True)
    (sdir / "session.json").write_text(
        json.dumps({"session_id": name, "created_at": "2026-01-01"}), encoding="utf-8"
    )
    (sdir / "events.jsonl").write_text('{"e":1}\n', encoding="utf-8")
    return sdir


def test_sessions_human_lists_entries(tmp_path: Path) -> None:
    _make_session(tmp_path)
    result = runner.invoke(app, ["sessions", "--workspace", str(tmp_path)])
    _ok(result)
    assert "sess-1" in result.output


def test_sessions_handles_corrupt_metadata(tmp_path: Path) -> None:
    sdir = tmp_path / "bad"
    sdir.mkdir()
    (sdir / "session.json").write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["--format", "json", "sessions", "--workspace", str(tmp_path)])
    _ok(result)
    payload = json.loads(result.output)
    assert payload["cleanup"]["session_count"] == 1


def test_sessions_filter_by_id(tmp_path: Path) -> None:
    _make_session(tmp_path, "keep")
    _make_session(tmp_path, "drop")
    result = runner.invoke(
        app, ["--format", "json", "sessions", "--workspace", str(tmp_path), "--session", "keep"]
    )
    _ok(result)
    payload = json.loads(result.output)
    assert [s["session_id"] for s in payload["sessions"]] == ["keep"]


def test_cleanup_requires_force() -> None:
    result = runner.invoke(
        app, ["cleanup", "--session", "x", "--domain", "corp.test", "--dc-ip", "10.0.0.1"]
    )
    assert result.exit_code != 0


def test_cleanup_executes_with_force(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.core.cleanup as cleanup_mod

    monkeypatch.setattr(cleanup_mod, "execute_cleanup", lambda s, t: {"completed": 3})
    result = runner.invoke(
        app,
        [
            "cleanup",
            "--session",
            str(tmp_path),
            "--domain",
            "corp.test",
            "--dc-ip",
            "10.0.0.1",
            "--force",
        ],
    )
    _ok(result)
    assert "Completed: 3" in result.output


# --------------------------- run (human mode) ---------------------------


def test_run_human_prints_paths_and_session(monkeypatch: Any, tmp_path: Path) -> None:
    def fake_run(capability: str, target: Any, **kwargs: Any) -> dict[str, Any]:
        log = kwargs.get("log")
        if callable(log):
            log("connecting to target")
            log("enumeration complete")
        return {
            "session_path": str(tmp_path),
            "interesting": {
                "top_paths": [{"score": 9, "length": 2, "path": ["A@X", "B@Y"]}],
            },
            "cred_attempts": ["alice: ok"],
            "username": "alice",
            "auth": "password",
        }

    monkeypatch.setattr(cli, "execute_capability", fake_run)
    result = runner.invoke(
        app, ["run", "ldap-enum", "--domain", "corp.test", "--dc-ip", "10.0.0.1"]
    )
    _ok(result)
    assert "Top ranked paths" in result.output
    assert "Session:" in result.output


def test_run_json_includes_progress_stages(monkeypatch: Any, tmp_path: Path) -> None:
    def fake_run(capability: str, target: Any, **kwargs: Any) -> dict[str, Any]:
        log = kwargs.get("log")
        if callable(log):
            log("preparing session")
            log("connected to ldap")
            log("harvested findings")
        return {"session_path": str(tmp_path), "session_id": "s1"}

    monkeypatch.setattr(cli, "execute_capability", fake_run)
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "run",
            "ldap-enum",
            "--domain",
            "corp.test",
            "--dc-ip",
            "10.0.0.1",
        ],
    )
    _ok(result)
    payload = json.loads(result.output)
    assert "progress" in payload
    assert isinstance(payload["progress"]["stages"], list)
    assert payload["progress"]["stages"]
    assert payload["progress"]["final_stage"]


def test_run_human_destructive_error(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        cli,
        "execute_capability",
        lambda *a, **k: (_ for _ in ()).throw(
            RunError("Capability 'x' is DESTRUCTIVE. Pass force=True / --force to proceed.")
        ),
    )
    result = runner.invoke(
        app, ["run", "shadow-creds", "--domain", "corp.test", "--dc-ip", "10.0.0.1"]
    )
    assert result.exit_code == 1
    assert "DESTRUCTIVE_CONFIRMATION_REQUIRED" in result.output


def test_run_reads_payload_file(monkeypatch: Any, tmp_path: Path) -> None:
    seen: dict[str, Any] = {}
    payload_file = tmp_path / "gpo.xml"
    payload_file.write_text("<gpo/>", encoding="utf-8")

    def fake_run(capability: str, target: Any, **kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return {"session_path": str(tmp_path), "ok": True}

    monkeypatch.setattr(cli, "execute_capability", fake_run)
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "run",
            "gpo-sysvol",
            "--domain",
            "corp.test",
            "--dc-ip",
            "10.0.0.1",
            "--payload",
            f"@{payload_file}",
            "--spn",
            "HTTP/x",
            "--operation",
            "renew",
            "--impersonate",
            "admin",
        ],
    )
    _ok(result)
    assert seen["payload"] == "<gpo/>"
    assert seen["spn"] == "HTTP/x" and seen["operation"] == "renew"


# --------------------------- rank-paths ---------------------------


class _FakeGraph:
    def summary(self) -> dict[str, int]:
        return {"nodes": 3, "edges": 2}

    def rank_from_principals(self, starts: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return [{"score": 12.0, "length": 2, "path": ["SID@S-1-5-21-1", "COMPUTER@DC$"]}]

    def rank_exploit_chains(self, starts: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return [
            {
                "score": 20,
                "terminal_relation": "DCSync",
                "impact": "domain compromise",
                "confidence": "high",
            }
        ]


def test_rank_paths_missing_graph(tmp_path: Path) -> None:
    result = runner.invoke(app, ["rank-paths", "--graph", str(tmp_path / "none.json")])
    assert result.exit_code == 1
    assert "GRAPH_NOT_FOUND" in result.output


def test_rank_paths_human_and_output(monkeypatch: Any, tmp_path: Path) -> None:
    graph_file = tmp_path / "graph.json"
    graph_file.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cli.AttackGraph, "from_file", staticmethod(lambda p: _FakeGraph()))
    out_file = tmp_path / "ranked.json"
    result = runner.invoke(
        app, ["rank-paths", "--graph", str(graph_file), "--output", str(out_file)]
    )
    _ok(result)
    assert "Ranked attack paths" in result.output
    assert out_file.is_file()


def test_rank_paths_json(monkeypatch: Any, tmp_path: Path) -> None:
    graph_file = tmp_path / "graph.json"
    graph_file.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cli.AttackGraph, "from_file", staticmethod(lambda p: _FakeGraph()))
    result = runner.invoke(
        app, ["--format", "json", "rank-paths", "--graph", str(graph_file), "--start", "alice"]
    )
    _ok(result)
    assert json.loads(result.output)["count"] == 1


# --------------------------- offline workflow wrappers ---------------------------


def test_credential_exposure(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(
        workflows, "credential_exposure", lambda s: {"count": 2, "next_step": "review"}
    )
    result = runner.invoke(app, ["credential-exposure", "--session", str(tmp_path)])
    _ok(result)
    assert "Exposure artifacts: 2" in result.output


def test_credential_exposure_missing_session(tmp_path: Path) -> None:
    result = runner.invoke(app, ["credential-exposure", "--session", str(tmp_path / "nope")])
    assert result.exit_code == 1
    assert "SESSION_NOT_FOUND" in result.output


def test_bloodhound_reconcile(monkeypatch: Any, tmp_path: Path) -> None:
    bh = tmp_path / "bh.json"
    bh.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        workflows,
        "bloodhound_reconcile",
        lambda s, b: {"only_local": [1], "only_bloodhound": [], "next_step": "x"},
    )
    result = runner.invoke(
        app, ["bloodhound-reconcile", "--session", str(tmp_path), "--bloodhound", str(bh)]
    )
    _ok(result)
    assert "Only local: 1" in result.output


def test_bloodhound_reconcile_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["bloodhound-reconcile", "--session", str(tmp_path), "--bloodhound", str(tmp_path / "x")],
    )
    assert result.exit_code == 1
    assert "BLOODHOUND_FILE_NOT_FOUND" in result.output


def test_trust_correlation(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(
        workflows, "correlate_trusts", lambda s: {"records": [1, 2], "next_step": "x"}
    )
    result = runner.invoke(app, ["trust-correlation", "--session", str(tmp_path)])
    _ok(result)
    assert "Sessions correlated: 2" in result.output


def test_delegation_and_adcs_validation(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(
        workflows, "validate_surface", lambda s, kind: {"validated": True, "next_step": "x"}
    )
    _ok(runner.invoke(app, ["delegation-validation", "--session", str(tmp_path)]))
    _ok(runner.invoke(app, ["adcs-validation", "--session", str(tmp_path)]))
    _ok(runner.invoke(app, ["gpo-impact-plan", "--session", str(tmp_path)]))


def test_campaign_compose(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(workflows, "compose_campaign", lambda s: {"phases": [1], "next_step": "x"})
    result = runner.invoke(app, ["campaign-compose", "--session", str(tmp_path)])
    _ok(result)
    assert "Campaign phases: 1" in result.output


def test_purple_handoff(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(
        workflows, "purple_handoff", lambda s: {"detections": [1, 2, 3], "next_step": "x"}
    )
    result = runner.invoke(app, ["purple-handoff", "--session", str(tmp_path)])
    _ok(result)
    assert "Detection hypotheses: 3" in result.output


def test_coercion_fixtures_requires_authorization(tmp_path: Path) -> None:
    result = runner.invoke(app, ["coercion-fixtures", "--fixtures", str(tmp_path)])
    assert result.exit_code == 1
    assert "FIXTURE_AUTHORIZATION_REQUIRED" in result.output


def test_coercion_fixtures_missing_dir(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["coercion-fixtures", "--fixtures", str(tmp_path / "nope"), "--authorized-fixtures"],
    )
    assert result.exit_code == 1
    assert "FIXTURE_DIRECTORY_NOT_FOUND" in result.output


def test_coercion_fixtures_valid(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(
        workflows,
        "validate_fixtures",
        lambda f: {"valid": True, "fixtures": [1], "next_step": "x"},
    )
    result = runner.invoke(
        app, ["coercion-fixtures", "--fixtures", str(tmp_path), "--authorized-fixtures"]
    )
    _ok(result)
    assert "Valid: yes" in result.output


def test_workflow_profiles_list_and_single() -> None:
    listed = runner.invoke(app, ["workflow-profiles"])
    _ok(listed)
    name = next(iter(workflows.PROFILES))
    single = runner.invoke(app, ["workflow-profiles", name])
    _ok(single)


def test_workflow_profiles_unknown() -> None:
    result = runner.invoke(app, ["workflow-profiles", "not-a-profile"])
    assert result.exit_code == 1
    assert "UNKNOWN_WORKFLOW_PROFILE" in result.output


# --------------------------- engagement subcommands ---------------------------


def test_engagement_init_and_refuse_overwrite(tmp_path: Path) -> None:
    out = tmp_path / "eng.yaml"
    _ok(runner.invoke(app, ["engagement", "init", "--output", str(out)]))
    assert out.is_file()
    again = runner.invoke(app, ["engagement", "init", "--output", str(out)])
    assert again.exit_code != 0
    invalid = runner.invoke(
        app, ["engagement", "init", "--output", str(tmp_path / "bad.yaml"), "--template", "bad"]
    )
    assert invalid.exit_code != 0


def test_engagement_validate(tmp_path: Path) -> None:
    out = tmp_path / "eng.yaml"
    _ok(runner.invoke(app, ["engagement", "init", "--output", str(out)]))
    result = runner.invoke(app, ["engagement", "validate", str(out)])
    _ok(result)
    assert "valid" in result.output.lower()


def test_engagement_validate_invalid(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("engagement_id: x\n", encoding="utf-8")
    result = runner.invoke(app, ["engagement", "validate", str(bad)])
    assert result.exit_code == 1
    assert "ENGAGEMENT_PLAN_INVALID" in result.output


def test_engagement_run(monkeypatch: Any, tmp_path: Path) -> None:
    out = tmp_path / "eng.yaml"
    _ok(runner.invoke(app, ["engagement", "init", "--output", str(out)]))
    import adaf_attack.core.engagement as eng

    monkeypatch.setattr(
        eng,
        "run_engagement",
        lambda plan, **k: {
            "engagement_id": "ENG-1",
            "capabilities": ["ldap-enum"],
            "finding_count": 4,
            "session_path": str(tmp_path),
        },
    )
    result = runner.invoke(
        app, ["engagement", "run", str(out), "--workspace", str(tmp_path / "ws")]
    )
    _ok(result)
    assert "Engagement complete" in result.output


def test_engagement_run_blocked(monkeypatch: Any, tmp_path: Path) -> None:
    out = tmp_path / "eng.yaml"
    _ok(runner.invoke(app, ["engagement", "init", "--output", str(out)]))
    import adaf_attack.core.engagement as eng

    def boom(plan: Any, **k: Any) -> Any:
        raise eng.EngagementError("nope")

    monkeypatch.setattr(eng, "run_engagement", boom)
    result = runner.invoke(app, ["engagement", "run", str(out)])
    assert result.exit_code == 1
    assert "ENGAGEMENT_RUN_BLOCKED" in result.output


def test_engagement_report_missing_session(tmp_path: Path) -> None:
    result = runner.invoke(app, ["engagement", "report", "--session", str(tmp_path / "nope")])
    assert result.exit_code == 1
    assert "SESSION_NOT_FOUND" in result.output


def test_engagement_report(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.core.reporting as reporting

    monkeypatch.setattr(
        reporting, "generate_report_bundle", lambda s, engagement_id: {"finding_count": 5}
    )
    result = runner.invoke(app, ["engagement", "report", "--session", str(tmp_path)])
    _ok(result)
    assert "Findings: 5" in result.output


def test_engagement_package(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.core.control_plane as cp

    monkeypatch.setattr(
        cp,
        "package_evidence",
        lambda s, o, profile: {"archive": str(o), "file_count": 3, "profile": profile},
    )
    result = runner.invoke(
        app,
        ["engagement", "package", "--session", str(tmp_path), "--output", str(tmp_path / "a.zip")],
    )
    _ok(result)
    assert "Files: 3" in result.output


def test_engagement_package_failure(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.core.control_plane as cp

    def boom(s: Any, o: Any, profile: str) -> Any:
        raise ValueError("bad profile")

    monkeypatch.setattr(cp, "package_evidence", boom)
    result = runner.invoke(app, ["engagement", "package", "--session", str(tmp_path)])
    assert result.exit_code == 1
    assert "ENGAGEMENT_PACKAGE_FAILED" in result.output


# --------------------------- forest + campaign ---------------------------


def test_forest_campaign(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.core.forest_campaign as fc

    monkeypatch.setattr(
        fc,
        "compose_forest_campaign",
        lambda s: {"domains": ["a"], "trust_transitions": []},
    )
    result = runner.invoke(app, ["forest-campaign", "--session", str(tmp_path)])
    _ok(result)
    assert "Domains: 1" in result.output


def test_forest_campaign_failure(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.core.forest_campaign as fc

    def boom(s: Any) -> Any:
        raise ValueError("bad")

    monkeypatch.setattr(fc, "compose_forest_campaign", boom)
    result = runner.invoke(app, ["forest-campaign", "--session", str(tmp_path)])
    assert result.exit_code == 1
    assert "FOREST_CAMPAIGN_FAILED" in result.output


def test_campaign_run(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.core.forest_campaign as fc

    campaign = tmp_path / "campaign.yaml"
    campaign.write_text("campaign_id: C1\n", encoding="utf-8")
    monkeypatch.setattr(
        fc,
        "run_campaign",
        lambda c, **k: {"campaign_id": "C1", "completed": ["ENG-1"], "stopped": False},
    )
    result = runner.invoke(app, ["campaign-run", "--campaign", str(campaign)])
    _ok(result)
    assert "Campaign: C1" in result.output


def test_campaign_run_bad_tokens(monkeypatch: Any, tmp_path: Path) -> None:
    campaign = tmp_path / "campaign.yaml"
    campaign.write_text("campaign_id: C1\n", encoding="utf-8")
    tokens = tmp_path / "tokens.json"
    tokens.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    result = runner.invoke(
        app, ["campaign-run", "--campaign", str(campaign), "--approval-tokens", str(tokens)]
    )
    assert result.exit_code == 1
    assert "CAMPAIGN_RUN_FAILED" in result.output


# --------------------------- start (TUI) ---------------------------


def test_start_blocked_non_interactive() -> None:
    result = runner.invoke(app, ["--non-interactive", "start"])
    assert result.exit_code == 1
    assert "INTERACTIVE_MODE_DISABLED" in result.output


def test_start_launches_tui(monkeypatch: Any) -> None:
    import adaf_attack.tui.app as tui_app

    called = {"ran": False}
    monkeypatch.setattr(
        tui_app, "run_tui", lambda workspace=None: called.update(ran=True, workspace=workspace)
    )
    result = runner.invoke(app, ["start"])
    _ok(result)
    assert called["ran"] is True


def test_invalid_format_rejected() -> None:
    result = runner.invoke(app, ["--format", "xml", "paths"])
    assert result.exit_code != 0
