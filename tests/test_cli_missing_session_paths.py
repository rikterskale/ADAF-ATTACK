"""Cover CLI ActionableError handlers when workflow inputs are missing."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import adaf_attack.cli as cli
from adaf_attack.cli import app
from typer.testing import CliRunner

runner = CliRunner()


def test_trust_correlation_missing_session(tmp_path: Path) -> None:
    result = runner.invoke(app, ["trust-correlation", "--session", str(tmp_path / "no")])
    assert result.exit_code == 1
    assert "SESSION_NOT_FOUND" in result.output


def test_delegation_validation_missing_session(tmp_path: Path) -> None:
    result = runner.invoke(app, ["delegation-validation", "--session", str(tmp_path / "no")])
    assert result.exit_code == 1


def test_adcs_validation_missing_session(tmp_path: Path) -> None:
    result = runner.invoke(app, ["adcs-validation", "--session", str(tmp_path / "no")])
    assert result.exit_code == 1


def test_gpo_impact_plan_missing_session(tmp_path: Path) -> None:
    result = runner.invoke(app, ["gpo-impact-plan", "--session", str(tmp_path / "no")])
    assert result.exit_code == 1


def test_campaign_compose_missing_session(tmp_path: Path) -> None:
    result = runner.invoke(app, ["campaign-compose", "--session", str(tmp_path / "no")])
    assert result.exit_code == 1


def test_forest_campaign_missing_session(tmp_path: Path) -> None:
    result = runner.invoke(app, ["forest-campaign", "--session", str(tmp_path / "no")])
    assert result.exit_code == 1


def test_purple_handoff_missing_session(tmp_path: Path) -> None:
    result = runner.invoke(app, ["purple-handoff", "--session", str(tmp_path / "no")])
    assert result.exit_code == 1


def test_bloodhound_reconcile_missing_session(tmp_path: Path) -> None:
    bh = tmp_path / "bh.json"
    bh.write_text("{}", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "bloodhound-reconcile",
            "--session",
            str(tmp_path / "no"),
            "--bloodhound",
            str(bh),
        ],
    )
    assert result.exit_code == 1


def test_sessions_skips_dirs_without_session_json(tmp_path: Path) -> None:
    # Directory without session.json → skipped
    (tmp_path / "junk").mkdir()
    result = runner.invoke(app, ["--format", "json", "sessions", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    import json as _json

    payload = _json.loads(result.output)
    assert payload["cleanup"]["session_count"] == 0


def test_run_attribute_and_sam_options(monkeypatch: Any, tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

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
            "cap",
            "--domain",
            "corp.test",
            "--dc-ip",
            "10.0.0.1",
            "--attribute",
            "sAMAccountName",
            "--sam",
            "svc",
        ],
    )
    assert result.exit_code == 0
    assert seen["attribute"] == "sAMAccountName"
    assert seen["sam"] == "svc"


def test_rank_paths_long_path_truncates(monkeypatch: Any, tmp_path: Path) -> None:
    """Cover the '→ …' truncation line."""

    class _G:
        def summary(self) -> dict[str, int]:
            return {"nodes": 1, "edges": 1}

        def rank_from_principals(self, starts: Any, **k: Any) -> list[dict[str, Any]]:
            return [
                {
                    "score": 5.0,
                    "length": 12,
                    "path": [f"USER@N{i}@CORP" for i in range(12)],
                }
            ]

        def rank_exploit_chains(self, starts: Any, **k: Any) -> list[Any]:
            return []

    graph = tmp_path / "g.json"
    graph.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cli.AttackGraph, "from_file", staticmethod(lambda p: _G()))
    result = runner.invoke(app, ["rank-paths", "--graph", str(graph)])
    assert result.exit_code == 0
