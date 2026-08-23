"""Branch-closure tests for workflow, graph, vault, reporting, and probe paths."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from adaf_attack.cli import app

runner = CliRunner()


def _run(ws: Path, *args: str) -> Any:
    return runner.invoke(app, ["--format", "json", "workflow", *args, "--workspace", str(ws)])


def _json(result: Any) -> dict[str, Any]:
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


# --------------------------- cli_workflow_commands ---------------------------


def test_inject_without_explicit_id_generates_one(tmp_path: Path) -> None:
    _json(_run(tmp_path, "authorize"))
    _json(_run(tmp_path, "do", "run-discovery"))
    payload = _json(_run(tmp_path, "inject", "No explicit id", "--severity", "low"))
    assert payload["finding"]["id"]


def test_transition_artifact_evidence_without_sha_or_note(tmp_path: Path) -> None:
    _json(_run(tmp_path, "authorize"))
    _json(_run(tmp_path, "do", "run-discovery"))
    _json(_run(tmp_path, "inject", "Bare artifact", "--id", "F-BARE", "--severity", "low"))
    result = _run(
        tmp_path,
        "transition",
        "F-BARE",
        "validated",
        "--artifact",
        "evidence.json",
        "--pointer",
        "/status",
    )
    assert _json(result)["guidance"]["phase"] == "validation"


# --------------------------- workflow_engine ---------------------------


def test_complete_step_without_phase_and_open_retransition(tmp_path: Path) -> None:
    from adaf_attack.core.workflow_engine import WorkflowEngine

    engine = WorkflowEngine(tmp_path)
    engine.start()
    state = engine.complete_step("manual-recon")
    assert "manual-recon" in state.completed_steps
    engine.complete_action("authorize-scope")
    engine.ingest_finding({"id": "F-OPEN", "title": "Still open"})
    record = engine.transition_finding("F-OPEN", "open")
    assert record.status == "open"


# --------------------------- graph ---------------------------


def test_resolve_dn_edges_leaves_unknown_groupdn_targets(tmp_path: Path) -> None:
    from adaf_attack.core.graph import AttackGraph

    g = AttackGraph()
    g.add_node("u1", "User")
    g.add_node("g1", "Group", dn="CN=Known,DC=corp,DC=test")
    g.add_edge("u1", "GROUPDN@CN=KNOWN,DC=CORP,DC=TEST", "MemberOf")
    g.add_edge("u1", "GROUPDN@CN=Missing,DC=corp,DC=test", "MemberOf")
    resolved = g.resolve_dn_edges()
    assert resolved == 1
    targets = {e.target for e in g.edges}
    assert "g1" in targets
    assert "GROUPDN@CN=Missing,DC=corp,DC=test" in targets


def test_rank_from_principals_skips_unresolvable_starts() -> None:
    from adaf_attack.core.graph import AttackGraph

    g = AttackGraph()
    g.add_node("u1", "User")
    g.add_node("g1", "Group", sam="Domain Admins")
    g.add_edge("u1", "g1", "MemberOf")
    ranked = g.rank_from_principals(["u1", "nobody-here"])
    assert ranked


# --------------------------- vault ---------------------------


def test_vault_delete_and_purge_with_missing_blobs(tmp_path: Path) -> None:
    from cryptography.fernet import Fernet

    from adaf_attack.core.vault import SessionVault

    key = Fernet.generate_key().decode()
    v = SessionVault(tmp_path, key=key)
    v.put("gone", "ccache", {"p": 1}, secret=True)
    v.put("plain", "note", {"info": "ok"}, secret=False)
    (v.root / "gone.vault").unlink()

    assert v.delete("gone") is True

    v.put("also-gone", "ccache", {"p": 2}, secret=True)
    (v.root / "also-gone.vault").unlink()
    removed = v.purge_all()
    assert removed == 2
    assert v.list() == []


# --------------------------- ux_extra ---------------------------


def test_export_plan_markdown_prerequisite_variants() -> None:
    from adaf_attack.core.ux_extra import export_plan_markdown

    base = {
        "capability_id": "shadow-creds",
        "domain": "corp.lab",
        "dc_ip": "10.0.0.10",
        "risk": {"level": "high"},
        "checklist": {"opsec_hint": "Stay quiet"},
        "ready_command": "adaf-attack run shadow-creds",
    }
    without = export_plan_markdown(**base, prerequisites=None)
    assert "Prerequisites" not in without
    best_only = export_plan_markdown(
        **base, prerequisites={"best_run_after": ["ldap-enum"], "produces_artifacts_for": []}
    )
    assert "Best run after" in best_only
    assert "Produces artifacts" not in best_only


# --------------------------- keycred ---------------------------


def test_build_keycredential_blob_with_explicit_device_id() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    from adaf_attack.core.keycred import build_keycredential_blob

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    blob = build_keycredential_blob(key.public_key().public_numbers(), device_id=b"\x01" * 16)
    assert len(blob) > 20


# --------------------------- reporting ---------------------------


def test_report_bundle_without_pdf_backend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from adaf_attack.core import reporting

    monkeypatch.setattr(reporting, "_pdf", lambda *a: False)
    session = tmp_path / "session"
    shutil.copytree(Path(__file__).parent / "fixtures" / "demo-session", session)
    output = reporting.generate_report_bundle(session, engagement_id="NO-PDF")
    assert output["finding_count"] == 2
    for report in ("executive", "technical", "remediation"):
        assert f"{report}_pdf" not in output
        assert Path(str(output[f"{report}_html"])).is_file()
    manifest = json.loads((session / "reports" / "report-manifest.json").read_text())
    assert manifest == output


# --------------------------- rollback ---------------------------


def test_record_pre_state_minimal_without_extra(tmp_path: Path) -> None:
    from adaf_attack.core.rollback import list_pending, record_pre_state
    from adaf_attack.core.session import Session

    session = Session(tmp_path / "session")
    action = record_pre_state(session, kind="acl-write", target="CN=x,DC=corp,DC=test")
    assert action["status"] == "pending"
    assert "extra" not in json.dumps(action)
    assert list_pending(session.root)[0]["target"].endswith("DC=test")


# --------------------------- ldap_ops ---------------------------


def test_lookup_sam_continues_past_entries_without_dn() -> None:
    from adaf_attack.core.ldap_ops import lookup_sam
    from tests.test_ldap_ops_helpers import _Conn, _Entry

    conn = _Conn([_Entry(sAMAccountName="PC$")])
    assert lookup_sam(conn, "DC=corp,DC=test", "PC") is None


# --------------------------- acl ---------------------------


def test_mask_to_rights_control_access_with_unmapped_guid() -> None:
    from adaf_attack.core.acl import ADS_RIGHT_DS_CONTROL_ACCESS, _mask_to_rights

    assert (
        _mask_to_rights(ADS_RIGHT_DS_CONTROL_ACCESS, "00000000-0000-0000-0000-000000000000") == []
    )


# --------------------------- auth ---------------------------


def test_get_kerberos_tgt_without_ccache_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from adaf_attack.core.auth import get_kerberos_tgt
    from adaf_attack.core.target import Target

    monkeypatch.delenv("KRB5CCNAME", raising=False)

    captured: dict[str, Any] = {}

    def fake_tgt(principal: Any, *args: Any, **kwargs: Any) -> tuple[str, str, None, str]:
        captured["principal"] = principal
        return ("tgt", "cipher", None, "session")

    import impacket.krb5.kerberosv5 as kv5

    monkeypatch.setattr(kv5, "getKerberosTGT", fake_tgt)
    target = Target(domain="corp.test", dc_ip="10.0.0.1", username="alice", use_kerberos=True)
    tgt, cipher, _old, session_key = get_kerberos_tgt(target)
    assert tgt == "tgt" and cipher == "cipher" and session_key == "session"
    assert captured["principal"] is not None
