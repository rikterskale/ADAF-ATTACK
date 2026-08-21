"""Targeted branch coverage for the final capability error and edge paths.

These tests drive the last uncovered defensive branches (empty sAMAccountName
skips, vault-error handlers, malformed attribute values, and alternate
selection paths) so the full-source coverage gate stays at 100%.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

import adaf_attack.capabilities.credential_inventory as credential_inventory
import adaf_attack.capabilities.esc_chain as esc_chain
import adaf_attack.capabilities.gpo_abuse as gpo_abuse
import adaf_attack.capabilities.identity_bridge as identity_bridge
import adaf_attack.capabilities.ntlm_relay as ntlm_relay
import adaf_attack.capabilities.rbcd as rbcd
import adaf_attack.capabilities.rodc_delegation as rodc_delegation
import adaf_attack.capabilities.s4u_abuse as s4u_abuse
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value
        self.values = value if isinstance(value, list) else ([] if value is None else [value])

    def __bool__(self) -> bool:
        return self.value is not None

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **values: Any) -> None:
        self.values = {key: _Attr(value) for key, value in values.items()}

    def __getattr__(self, name: str) -> _Attr:
        return self.values.get(name, self.values.get(name.replace("-", "_"), _Attr()))

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _FilterConn:
    """LDAP connection stub that returns entries keyed by search filter."""

    def __init__(self, responses: dict[str, list[_Entry]]) -> None:
        self.responses = responses
        self.entries: list[_Entry] = []

    def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
        self.entries = self.responses.get(search_filter, [])

    def unbind(self) -> None:
        return None


def _target(**kwargs: Any) -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10", **kwargs)


# --------------------------------------------------------------------------- #
# Direct helper branches (_list_attr scalar / empty results)
# --------------------------------------------------------------------------- #


def test_list_attr_scalar_and_empty_branches() -> None:
    assert rbcd._list_attr(SimpleNamespace(example="scalar"), "example") == ["scalar"]
    assert identity_bridge._list_attr(SimpleNamespace(example="scalar"), "example") == ["scalar"]
    assert rodc_delegation._list_attr(SimpleNamespace(), "missing") == []
    assert rodc_delegation._list_attr(SimpleNamespace(example="scalar"), "example") == ["scalar"]


# --------------------------------------------------------------------------- #
# s4u-abuse: non-relation edge skip, graph.json reload, altservice edge
# --------------------------------------------------------------------------- #


def test_s4u_precondition_skips_non_delegation_edges() -> None:
    graph = AttackGraph()
    graph.add_edge("USER@A", "USER@A", "HasS4UTicket")
    assert s4u_abuse._precondition_evidence(graph, "alice")["evidence_count"] == 0


def test_s4u_loads_prior_graph_and_records_altservice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    examples = ModuleType("impacket.examples.getST")

    class GetST:
        def __init__(self, *args: Any) -> None:
            pass

        def run(self) -> None:
            pass

    examples.GETST = GetST  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "impacket.examples.getST", examples)
    monkeypatch.setattr(s4u_abuse, "require_impacket", lambda name: None)

    session = Session(base_dir=tmp_path)
    prior = AttackGraph()
    prior.add_edge("ACCOUNT@ALICE", "DOMAIN@CORP.TEST", "AllowedToDelegate")
    prior.save(session.path("graph.json"))

    result = s4u_abuse.S4uAbuse().run(
        _target(username="alice", password="secret"),
        session,
        AttackGraph(),
        impersonate="administrator",
        spn="cifs/dc",
        altservice="http/host",
    )
    assert result["altservice"] == "http/host"
    assert result["preconditions"]["has_constrained_signal"] is True


# --------------------------------------------------------------------------- #
# credential-inventory: scan dedup/dir skip, vault-error export & rotation,
# inventory display branches
# --------------------------------------------------------------------------- #


def test_scan_artifacts_skips_directories_and_deduplicates(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    session.root.mkdir(parents=True, exist_ok=True)
    (session.root / "imported-directory").mkdir()  # matches "imported-*" but is a dir
    (session.root / "exported.pem").write_text("x", encoding="utf-8")  # matches two globs
    scanned = credential_inventory._scan_artifacts(session)
    keys = [item["name"] for item in scanned]
    assert "imported-directory" not in keys
    assert keys.count("exported.pem") == 1


def test_export_and_rotation_report_vault_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cryptography.fernet import Fernet

    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())
    session = Session(base_dir=tmp_path)
    session.vault().put("secret", "password", "value", secret=True)
    monkeypatch.delenv("ADAF_SESSION_VAULT_KEY")

    exported = credential_inventory._export_items(session, names=["secret"], include_secrets=True)
    assert exported["errors"] and exported["errors"][0]["name"] == "secret"

    rotation = credential_inventory._mark_rotation(session, ["secret"])
    assert rotation["markers"][0]["ok"] is False


def test_inventory_run_display_branches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cryptography.fernet import Fernet

    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())

    # Inventory with artifact files present exercises the file-row rendering.
    populated = Session(base_dir=tmp_path / "populated")
    populated.root.mkdir(parents=True, exist_ok=True)
    populated.path("ticket.ccache").write_text("artifact", encoding="utf-8")
    result = credential_inventory.CredentialInventory().run(_target(), populated, AttackGraph())
    assert result["artifact_count"] >= 1

    # Export with no explicit names auto-populates from the inventory.
    exported = credential_inventory.CredentialInventory().run(
        _target(), populated, AttackGraph(), operation="export"
    )
    assert exported["exported"]

    # Empty session renders the "no credential material" branch.
    empty = Session(base_dir=tmp_path / "empty")
    empty_result = credential_inventory.CredentialInventory().run(_target(), empty, AttackGraph())
    assert empty_result["vault_count"] == 0 and empty_result["artifact_count"] == 0


# --------------------------------------------------------------------------- #
# esc-chain: CA auto-selection loop and unresolved template/CA error
# --------------------------------------------------------------------------- #


def _mock_cert_pkinit(monkeypatch: pytest.MonkeyPatch) -> None:
    class Cert:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, str]:
            return {"pfx": "issued.pfx"}

    class Pkinit:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, bool]:
            return {"ok": True}

    cert_module = ModuleType("adaf_attack.capabilities.cert_request")
    cert_module.CertRequest = Cert  # type: ignore[attr-defined]
    pkinit_module = ModuleType("adaf_attack.capabilities.pkinit_auth")
    pkinit_module.PkinitAuth = Pkinit  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "adaf_attack.capabilities.cert_request", cert_module)
    monkeypatch.setitem(sys.modules, "adaf_attack.capabilities.pkinit_auth", pkinit_module)


def test_esc_chain_auto_selects_ca_publishing_template(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_cert_pkinit(monkeypatch)
    prior = tmp_path / "adcs"
    prior.mkdir()
    (prior / "adcs-enum.json").write_text(
        json.dumps(
            {
                "templates": [{"esc_tags": ["ESC1"], "cn": "VulnTemplate"}],
                "cas": [{"cn": "CA-A", "templates": ["VulnTemplate"]}],
            }
        ),
        encoding="utf-8",
    )
    result = esc_chain.EscChain().run(
        _target(username="alice"),
        Session(base_dir=tmp_path / "s"),
        AttackGraph(),
        adcs_session=prior,
    )
    assert result["ca"] == "CA-A"


def test_esc_chain_errors_when_ca_cannot_be_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prior = tmp_path / "adcs"
    prior.mkdir()
    (prior / "adcs-enum.json").write_text(
        json.dumps({"templates": [{"esc_tags": ["ESC1"], "cn": "VulnTemplate"}]}),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="template \\+ CA"):
        esc_chain.EscChain().run(
            _target(username="alice"),
            Session(base_dir=tmp_path / "s"),
            AttackGraph(),
            adcs_session=prior,
        )


# --------------------------------------------------------------------------- #
# gpo-abuse: gPLink to unknown GPO skip + domain-linked marker
# --------------------------------------------------------------------------- #


def test_gpo_abuse_links_domain_and_skips_unknown_gpo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    known = "11111111-1111-1111-1111-111111111111"
    unknown = "99999999-9999-9999-9999-999999999999"
    responses = {
        "(objectClass=groupPolicyContainer)": [
            _Entry(
                cn="{" + known + "}",
                distinguishedName="CN={" + known + "},CN=Policies,DC=corp,DC=test",
            )
        ],
        "(|(objectClass=organizationalUnit)(objectClass=domainDNS))": [
            _Entry(
                distinguishedName="DC=corp,DC=test",
                name="corp",
                objectClass=["domainDNS"],
                gPLink="[LDAP://CN={" + known + "},CN=Policies,DC=corp,DC=test;0]",
            ),
            _Entry(
                distinguishedName="OU=Test,DC=corp,DC=test",
                name="Test",
                objectClass=["organizationalUnit"],
                gPLink="[LDAP://CN={" + unknown + "},CN=Policies,DC=corp,DC=test;0]",
            ),
        ],
    }
    conn = _FilterConn(responses)
    monkeypatch.setattr(gpo_abuse, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_abuse, "fetch_sd", lambda connection, dn: None)
    result = gpo_abuse.GpoAbuse().run(_target(), Session(base_dir=tmp_path), AttackGraph())
    gpo = result["gpos"][0]
    assert gpo["linked_to_domain"] is True
    assert gpo["link_count"] == 1


# --------------------------------------------------------------------------- #
# identity-bridge: empty sAMAccountName skip + Exchange recipient details
# --------------------------------------------------------------------------- #


def test_identity_bridge_handles_empty_sam_and_recipient_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entries = [
        _Entry(),  # empty sAMAccountName -> skipped
        _Entry(sAMAccountName="mbx1", msExchRecipientTypeDetails=8),  # valid int flag
        _Entry(sAMAccountName="mbx2", msExchRecipientTypeDetails="not-an-int"),  # parse failure
    ]

    class Conn:
        def __init__(self) -> None:
            self.entries = entries

        def search(self, *args: Any, **kwargs: Any) -> None:
            return None

        def unbind(self) -> None:
            return None

    monkeypatch.setattr(identity_bridge, "ldap_connect", lambda target: (Conn(), "DC=corp", None))
    result = identity_bridge.HybridSignals().run(
        _target(), Session(base_dir=tmp_path), AttackGraph()
    )
    signals = {row["signal"] for row in result["synced_sample"]}
    assert "ExchangeRecipientDetails" in signals


# --------------------------------------------------------------------------- #
# ntlm-relay: ingest error paths + vault-storage-failed notice
# --------------------------------------------------------------------------- #


def test_ntlm_ingest_handles_unreadable_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = Session(base_dir=tmp_path)
    locked = session.path("locked.txt")
    locked.write_text("noise", encoding="utf-8")

    original = Path.read_text

    def boom(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == "locked.txt":
            raise OSError("unreadable")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", boom)
    assert ntlm_relay._ingest_artifacts_to_vault(session, [str(locked)]) == []


def test_ntlm_ingest_records_vault_errors_without_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ADAF_SESSION_VAULT_KEY", raising=False)
    session = Session(base_dir=tmp_path)
    artifact = session.path("hashes.txt")
    artifact.write_text(
        "user::CORP:00000000000000000000000000000000:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "NTLMv2 challenge-response-body",
        encoding="utf-8",
    )
    stored = ntlm_relay._ingest_artifacts_to_vault(session, [str(artifact)])
    assert stored and all("error" in item for item in stored)


def test_ntlm_relay_run_warns_when_vault_storage_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ADAF_SESSION_VAULT_KEY", raising=False)
    session = Session(base_dir=tmp_path)
    binary = tmp_path / "relay.exe"
    binary.write_text("", encoding="utf-8")
    monkeypatch.setattr(ntlm_relay.shutil, "which", lambda name: str(binary))

    class Proc:
        pid = 1
        returncode = 0

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            out_dir = Path(kwargs["cwd"])
            (out_dir / "hashes.txt").write_text(
                "user::CORP:00000000000000000000000000000000:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                encoding="utf-8",
            )

        def wait(self, timeout: int) -> None:
            return None

    monkeypatch.setattr(ntlm_relay.subprocess, "Popen", Proc)
    result = ntlm_relay.NtlmRelay().run(
        _target(),
        session,
        AttackGraph(),
        force=True,
        relay_targets="server1",
        duration_seconds=1,
    )
    assert result["vault_stored"] == 0 and result["vault_items"]


# --------------------------------------------------------------------------- #
# rbcd: constrained delegation UAC parse guard + writable-computer ACL error
# --------------------------------------------------------------------------- #


def test_rbcd_enum_handles_bad_uac_and_acl_parse_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    responses = {
        f"(&(objectClass=computer)({rbcd.ATTR_RBCD}=*))": [],
        f"(&(|(objectClass=user)(objectClass=computer))({rbcd.ATTR_CONSTRAINED}=*))": [
            _Entry(
                sAMAccountName="SVC$",
                distinguishedName="CN=SVC,DC=corp,DC=test",
                userAccountControl="bad-value",
                **{rbcd.ATTR_CONSTRAINED: ["cifs/dc", "host/dc"]},
            )
        ],
        "(objectClass=computer)": [
            _Entry(sAMAccountName="WS$", distinguishedName="CN=WS,DC=corp,DC=test")
        ],
    }
    conn = _FilterConn(responses)
    monkeypatch.setattr(rbcd, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(rbcd, "fetch_sd", lambda connection, dn: b"descriptor")

    def _boom(_sd: Any) -> Any:
        raise ValueError("bad descriptor")

    monkeypatch.setattr(rbcd, "parse_interesting_aces", _boom)
    result = rbcd.Rbcd().run(_target(), Session(base_dir=tmp_path), AttackGraph())
    constrained = result["constrained_delegation"][0]
    assert constrained["spns"] == ["cifs/dc", "host/dc"]
    assert constrained["protocol_transition"] is False
    assert result["writable_computers"] == []


# --------------------------------------------------------------------------- #
# rodc-delegation: empty-sAMAccountName skips across all three passes and a
# delegation entry that carries no delegation signal
# --------------------------------------------------------------------------- #


def test_rodc_skips_empty_sam_and_non_delegating_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Conn:
        entries: list[_Entry] = []

        def search(self, base_dn: str, query: str, **kwargs: Any) -> None:
            if "67108864" in query:
                self.entries = [_Entry()]  # RODC computer without sAMAccountName
            elif "krbtgt_" in query:
                self.entries = [_Entry()]  # krbtgt account without sAMAccountName
            else:
                self.entries = [
                    _Entry(),  # delegation pass without sAMAccountName
                    _Entry(
                        sAMAccountName="PLAIN$",
                        distinguishedName="CN=PLAIN,DC=corp,DC=test",
                        userAccountControl=0,
                    ),  # no delegation signals -> skipped
                ]

        def unbind(self) -> None:
            return None

    conn = Conn()
    monkeypatch.setattr(
        rodc_delegation, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None)
    )
    result = rodc_delegation.RodcDelegation().run(
        _target(), Session(base_dir=tmp_path), AttackGraph()
    )
    assert result["count"] == 0
    assert result["delegation"] == []


def test_completion_helper_failure_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    from adaf_attack.core import completions
    from adaf_attack.core.registry import capability_registry

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(capability_registry, "ids", boom)
    monkeypatch.setattr("adaf_attack.core.profiles.list_profiles", boom)
    assert completions._capability_ids() == []
    assert completions._profile_names() == []

    monkeypatch.setattr("adaf_attack.core.paths.default_workspace_dir", boom)
    assert completions._session_ids() == []

    from pathlib import Path as _Path

    monkeypatch.setattr(
        "adaf_attack.core.paths.default_workspace_dir", lambda: _Path("/nonexistent-adaf-ws")
    )
    assert completions._session_ids() == []

    script = completions.generate_completion("fish")
    assert "complete -c adaf-attack" in script


def test_fish_completion_lists_sessions(monkeypatch: pytest.MonkeyPatch) -> None:
    from adaf_attack.core import completions

    monkeypatch.setattr(completions, "_session_ids", lambda: ["sess-1", "sess-2"])
    script = completions.generate_completion("fish")
    assert "-a 'sess-1'" in script
    assert "-a 'sess-2'" in script
