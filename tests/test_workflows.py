"""Offline workflow correlation tests."""

from __future__ import annotations

import json
from pathlib import Path

from adaf_attack.core.workflows import (
    bloodhound_reconcile,
    credential_exposure,
    validate_fixtures,
    validate_surface,
)


def _session(root: Path) -> Path:
    session = root / "session-a"
    session.mkdir()
    (session / "graph.json").write_text(
        json.dumps({"nodes": [{"id": "user-a"}], "edges": [{"source": "user-a", "target": "host-a", "kind": "AllowedToDelegate"}, {"source": "user-a", "target": "ca-a", "kind": "ESC1"}]}),
        encoding="utf-8",
    )
    (session / "ticket.ccache").write_text("not a real ticket", encoding="utf-8")
    (session / "adcs-enum.json").write_text("{}", encoding="utf-8")
    return session


def test_credential_exposure_redacts_values(tmp_path: Path) -> None:
    result = credential_exposure([_session(tmp_path)])

    assert result["count"] == 1
    assert result["exposures"][0]["artifact"] == "ticket.ccache"
    assert result["exposures"][0]["secret_value"] == "redacted"


def test_reconciliation_reports_graph_gaps(tmp_path: Path) -> None:
    session = _session(tmp_path)
    external = tmp_path / "bloodhound.json"
    external.write_text(json.dumps({"nodes": [{"id": "host-b"}]}), encoding="utf-8")

    result = bloodhound_reconcile(session, external)

    assert result["only_local"] == ["user-a"]
    assert result["only_bloodhound"] == ["host-b"]


def test_surface_validation_is_evidence_only(tmp_path: Path) -> None:
    result = validate_surface(_session(tmp_path), "delegation")

    assert result["validated"] is True
    assert result["findings"] == {"AllowedToDelegate": 1}
    assert "authorization" in result["next_step"]


def test_authorized_fixture_parser_is_offline(tmp_path: Path) -> None:
    (tmp_path / "fixture.json").write_text("{}", encoding="utf-8")

    result = validate_fixtures(tmp_path)

    assert result["valid"] is True
    assert result["fixtures"] == [{"fixture": "fixture.json", "valid_json": True}]
