from __future__ import annotations

import json

import pytest
from cryptography.fernet import Fernet

from adaf_attack.capabilities.next_actions import NextActions
from adaf_attack.capabilities.ticket_lifecycle import TicketLifecycle
from adaf_attack.capabilities.workflow_wrappers import RbcdTicketWorkflow, ShadowPkinitWorkflow
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.redaction import redact
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def test_vault_encrypts_secret_and_keeps_metadata_redacted(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())
    session = Session(base_dir=tmp_path)
    session.vault().put("tgt", "ccache", {"ticket": "secret"}, secret=True, metadata={"ticket": "secret"})
    assert session.vault().get("tgt") == {"ticket": "secret"}
    index = json.loads((session.root / "vault" / "index.json").read_text(encoding="utf-8"))
    assert index["items"]["tgt"]["metadata"]["ticket"] == "[REDACTED]"


def test_client_redaction_profile_hides_identity() -> None:
    value = redact({"username": "alice", "password": "secret"}, profile="client")
    assert value == {"username": "[REDACTED]", "password": "[REDACTED]"}


def test_next_actions_recommends_shadow_workflow(tmp_path) -> None:
    session = Session(base_dir=tmp_path)
    graph = AttackGraph()
    graph.add_node("SID@S-1-5-21", "Base")
    graph.add_node("USER@ADMIN@CORP.LOCAL", "User")
    graph.add_edge("SID@S-1-5-21", "USER@ADMIN@CORP.LOCAL", "WriteKeyCredentialLink")
    target = Target(domain="corp.local", dc_ip="10.0.0.1")
    result = NextActions().run(target, session, graph)
    assert result["actions"][0]["capability"] == "shadow-pkinit-workflow"


def test_ticket_lifecycle_inventory(tmp_path) -> None:
    session = Session(base_dir=tmp_path)
    session.path("demo.ccache").write_bytes(b"ticket")
    result = TicketLifecycle().run(Target(domain="corp.local", dc_ip="10.0.0.1"), session, AttackGraph())
    assert result["artifacts"] == ["demo.ccache"]


@pytest.mark.parametrize("runner", [ShadowPkinitWorkflow(), RbcdTicketWorkflow()])
def test_workflow_wrappers_require_force(tmp_path, runner) -> None:
    with pytest.raises(RuntimeError):
        runner.run(Target(domain="corp.local", dc_ip="10.0.0.1"), Session(base_dir=tmp_path), AttackGraph())
