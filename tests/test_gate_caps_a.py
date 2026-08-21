"""Branch-closure gate tests, part A: acl_primitives through computer_takeover."""

from __future__ import annotations

import json
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

from gate_helpers import (
    Conn,
    Entry,
    FailModifyConn,
    patch_ldap,
    sid_entry,
    target,
)

import adaf_attack.capabilities.acl_primitives as acl_primitives
import adaf_attack.capabilities.adcs_enum as adcs_enum
import adaf_attack.capabilities.adcs_esc as adcs_esc
import adaf_attack.capabilities.adcs_policy_probe as adcs_policy_probe
import adaf_attack.capabilities.attack_paths as attack_paths
import adaf_attack.capabilities.bloodhound_export as bloodhound_export
import adaf_attack.capabilities.campaign_analysis as campaign_analysis
import adaf_attack.capabilities.cert_request as cert_request
import adaf_attack.capabilities.coerce as coerce
import adaf_attack.capabilities.computer_takeover as computer_takeover
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.rbcd_sd import build_allowed_to_act_sd
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


# --------------------------- acl_primitives ok=False branches ---------------------------
def test_acl_primitives_failure_branches(monkeypatch: Any, tmp_path: Any) -> None:
    group = sid_entry("Domain Admins", "CN=Domain Admins,DC=corp,DC=test")
    user = sid_entry("alice", "CN=Alice,DC=corp,DC=test")
    bob = sid_entry("bob", "CN=Bob,DC=corp,DC=test")
    conn = FailModifyConn(
        {"Domain Admins": [group], "alice": [user], "bob": [bob], "ALICE": [user]}
    )
    patch_ldap(monkeypatch, acl_primitives, conn)
    monkeypatch.setattr(
        acl_primitives, "fetch_sd", lambda *_a, **_k: build_allowed_to_act_sd("S-1-5-21-1-2-3-9")
    )
    session = Session(tmp_path)
    graph = AttackGraph()

    add_member = acl_primitives.AddMember().run(
        target(), session, graph, force=True, group="Domain Admins", member="alice"
    )
    assert add_member["ok"] is False

    add_self = acl_primitives.AddSelf().run(
        target(), session, graph, force=True, group="Domain Admins"
    )
    assert add_self["ok"] is False

    pwd = acl_primitives.ForceChangePassword().run(
        target(), session, graph, force=True, sam="bob", new_password="N3w!"
    )
    assert pwd["ok"] is False and "password" not in pwd

    spn = acl_primitives.WriteSpn().run(
        target(), session, graph, force=True, sam="bob", spn="HTTP/app"
    )
    assert spn["ok"] is False

    abuse = acl_primitives.AclAbuse().run(
        target(),
        session,
        graph,
        force=True,
        sam="bob",
        rights="GenericAll",
        principal_sid="S-1-5-21-1-2-3-4",
    )
    assert abuse["ok"] is False

    holder = acl_primitives.AdminSdHolderPersist().run(
        target(), session, graph, force=True, principal_sid="S-1-5-21-1-2-3-4"
    )
    assert holder["ok"] is False

    sidhist = acl_primitives.SidHistoryInject().run(
        target(), session, graph, force=True, sam="bob", sid="S-1-5-21-99"
    )
    assert sidhist["ok"] is False


def test_force_change_password_without_secrets(monkeypatch: Any, tmp_path: Any) -> None:
    bob = sid_entry("bob", "CN=Bob,DC=corp,DC=test")
    conn = Conn({"bob": [bob]})
    patch_ldap(monkeypatch, acl_primitives, conn)
    result = acl_primitives.ForceChangePassword().run(
        target(), Session(tmp_path), AttackGraph(), force=True, sam="bob", new_password="N3w!"
    )
    assert result["ok"] is True and "password" not in result


# --------------------------- adcs_enum non-web enrollment server ---------------------------
def test_adcs_enum_skips_non_web_enrollment_servers(monkeypatch: Any, tmp_path: Any) -> None:
    ca = SimpleNamespace(entry_dn="CN=CorpCA,DC=corp,DC=test")
    template = SimpleNamespace()

    class _C:
        def __init__(self) -> None:
            self.entries: list[Any] = []
            self.unbound = False

        def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
            if search_filter == "(objectClass=pKIEnrollmentService)":
                self.entries = [ca]
            elif search_filter == "(objectClass=pKICertificateTemplate)":
                self.entries = [template]
            else:
                self.entries = []

        def unbind(self) -> None:
            self.unbound = True

    conn = _C()
    monkeypatch.setattr(
        adcs_enum, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", "CN=Configuration")
    )
    monkeypatch.setattr(
        adcs_enum,
        "_analyze_template",
        lambda entry: {"cn": "T", "dn": "CN=T", "esc_tags": []},
    )
    monkeypatch.setattr(adcs_enum, "fetch_sd", lambda connection, dn: None)
    monkeypatch.setattr(adcs_enum, "probe_esc6", lambda t, ca_hostnames: {})
    monkeypatch.setattr(
        adcs_enum,
        "_list_attr",
        lambda entry, name: {
            "certificateTemplates": ["T"],
            "msPKI-Enrollment-Servers": [
                "https://ca.corp.test/certsrv/certfnsh.asp",
                "ldap://ca.corp.test",
            ],
            "msPKI-RA-Policies": [],
        }.get(name, []),
    )
    monkeypatch.setattr(adcs_enum, "_int_attr", lambda entry, name: 0)
    ca.cn = "CorpCA"
    ca.dNSHostName = "ca.corp.test"
    ca.cACertificateDN = "CN=CorpCA"
    session = Session(tmp_path)
    cap = adcs_enum.AdcsEnum()
    out = cap.run(target(), session, AttackGraph())
    servers = out["cas"][0]["enrollment_servers"]
    assert "ldap://ca.corp.test" in servers
    assert out["esc8_web_enrollment"]


# --------------------------- adcs_esc argv / coerce-skip branches ---------------------------
def test_adcs_esc_enroll_without_password_hashes_and_ca(monkeypatch: Any, tmp_path: Any) -> None:
    captured: dict[str, Any] = {}

    def _fake_run(argv: list[str], session: Session) -> dict[str, Any]:
        captured["argv"] = argv
        return {"ok": True, "method": "certipy", "returncode": 0}

    monkeypatch.setattr(adcs_esc, "_run_certipy", _fake_run)
    result = adcs_esc.Esc9().run(
        target(password=None, hashes=None),
        Session(tmp_path),
        AttackGraph(),
        force=True,
        template="T",
    )
    assert result["ok"] is True
    assert "-hashes" not in captured["argv"]
    assert "-ca" not in captured["argv"]
    assert "-upn" not in captured["argv"]


def test_golden_cert_without_subject(monkeypatch: Any, tmp_path: Any) -> None:
    captured: dict[str, Any] = {}

    def _fake_run(argv: list[str], session: Session) -> dict[str, Any]:
        captured["argv"] = argv
        return {"ok": True, "method": "certipy", "returncode": 0}

    monkeypatch.setattr(adcs_esc, "_run_certipy", _fake_run)
    result = adcs_esc.GoldenCert().run(
        target(), Session(tmp_path), AttackGraph(), force=True, ca_pfx="ca.pfx", upn="a@corp.test"
    )
    assert result["ok"] is True
    assert "-subject" not in captured["argv"]


def test_esc8_relay_workflow_without_coerce_host(monkeypatch: Any, tmp_path: Any) -> None:
    class _Relay:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"return_code": 0}

    monkeypatch.setattr(adcs_esc, "NtlmRelay", _Relay)
    result = adcs_esc.Esc8RelayWorkflow().run(
        target(), Session(tmp_path), AttackGraph(), force=True, ca="ca.corp.test"
    )
    assert result["ok"] is True
    assert result["coerce"] == {"skipped": "no_host"}


# --------------------------- adcs_policy_probe out-of-set candidate ---------------------------
def test_adcs_policy_probe_ignores_out_of_set_candidates(monkeypatch: Any, tmp_path: Any) -> None:
    artifact = tmp_path / "policy.json"
    artifact.write_text(json.dumps({"weak_certificate_mapping": True}), encoding="utf-8")
    monkeypatch.setattr(
        adcs_policy_probe,
        "classify_modern_esc",
        lambda *, policy=None, **_k: {
            "candidates": {"ESC99": {"reason": "r", "confidence": "low"}}
        },
    )
    result = adcs_policy_probe.AdcsPolicyProbe().run(
        target(),
        Session(tmp_path),
        AttackGraph(),
        artifact=str(artifact),
    )
    assert result["esc10_candidates"] == ["dc-policy"]


# --------------------------- attack_paths preloaded graph + short commands ---------------------------
def test_attack_paths_with_prepopulated_graph_and_short_chain(
    monkeypatch: Any, tmp_path: Any
) -> None:
    monkeypatch.setattr(
        attack_paths,
        "build_exploit_commands",
        lambda chain, target, operator_user=None: [{"command": "adaf-attack kerberoast"}],
    )
    graph = AttackGraph()
    graph.add_node("USER@ALICE@CORP.TEST", "User", sam="alice")
    graph.add_node("GROUP@DOMAIN ADMINS@CORP.TEST", "Group", sam="Domain Admins")
    graph.add_edge("USER@ALICE@CORP.TEST", "GROUP@DOMAIN ADMINS@CORP.TEST", "GenericAll")
    session = Session(tmp_path / "sessions")

    result = attack_paths.AttackPaths().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"),
        session,
        graph,
        start="alice",
    )
    assert result["loaded_from"] is None
    assert result["count"] >= 1


# --------------------------- bloodhound_export with preloaded graph ---------------------------
def test_bloodhound_export_with_preloaded_graph(tmp_path: Any) -> None:
    graph = AttackGraph()
    graph.add_node("USER@ALICE@CORP.TEST", "User", sam="alice")
    session = Session(tmp_path)
    result = bloodhound_export.BloodhoundExport().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"), session, graph
    )
    assert result["summary"]["nodes"] >= 1
    assert session.path("bloodhound.json").exists()


# --------------------------- campaign_analysis branches ---------------------------
def test_blast_radius_self_loop_and_depth_cap(tmp_path: Any) -> None:
    graph = AttackGraph()
    graph.add_node("USER@ALICE@CORP.LOCAL", "User")
    graph.add_node("GROUP@DOMAIN ADMINS@CORP.LOCAL", "Group", admin_count=True)
    graph.add_edge("USER@ALICE@CORP.LOCAL", "USER@ALICE@CORP.LOCAL", "SelfRef")
    graph.add_edge("USER@ALICE@CORP.LOCAL", "GROUP@DOMAIN ADMINS@CORP.LOCAL", "MemberOf")
    result = campaign_analysis.BlastRadius().run(
        Target(domain="corp.local", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path),
        graph,
        start="alice",
        max_depth=1,
    )
    assert result["reachable_nodes"] >= 1


def test_purple_feedback_without_events_file(tmp_path: Any) -> None:
    session = Session(base_dir=tmp_path)
    result = campaign_analysis.PurpleFeedback().run(
        Target(domain="corp.local", dc_ip="10.0.0.1"), session, AttackGraph()
    )
    assert result["count"] == 0 and result["timeline"] == []


# --------------------------- cert_request seeding branches ---------------------------
def test_cert_request_seeding_empty_candidates_and_cas(monkeypatch: Any, tmp_path: Any) -> None:
    session = Session(tmp_path)
    session.path("adcs-enum.json").write_text(
        json.dumps({"esc1_candidates": [], "cas": []}), encoding="utf-8"
    )

    def _fail(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError("certipy")

    monkeypatch.setattr(cert_request.subprocess, "run", _fail)
    result = cert_request.CertRequest().run(
        target(password=None, hashes=None),
        session,
        AttackGraph(),
        force=True,
        template="Manual",
    )
    assert result["template"] == "Manual" and result["ca"] is None
    assert result["method"] == "playbook-only"


def test_cert_request_ca_entry_without_names(monkeypatch: Any, tmp_path: Any) -> None:
    session = Session(tmp_path)
    session.path("adcs-enum.json").write_text(
        json.dumps({"esc1_candidates": [], "cas": [{}]}), encoding="utf-8"
    )

    def _fail(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError("certipy")

    monkeypatch.setattr(cert_request.subprocess, "run", _fail)
    result = cert_request.CertRequest().run(
        target(password=None, hashes=None), session, AttackGraph(), force=True, template="T"
    )
    assert result["ca"] is None


# --------------------------- coerce allowlist parsing branches ---------------------------
def test_coerce_allowlist_from_missing_session_file(tmp_path: Any) -> None:
    hosts = coerce._load_allowlist({"coercion_session": str(tmp_path)}, None)
    assert hosts == []


def test_coerce_allowlist_row_without_host(tmp_path: Any) -> None:
    map_file = tmp_path / "coercion-map.json"
    map_file.write_text(
        json.dumps({"hosts": [{"spooler": True}, {"spooler": True, "host": "dc1.corp.test"}]}),
        encoding="utf-8",
    )
    hosts = coerce._load_allowlist({"coercion_session": str(tmp_path)}, None)
    assert hosts == ["dc1.corp.test"]


def test_coerce_trigger_transport_without_set_credentials(
    monkeypatch: Any,
) -> None:
    rpcrt = ModuleType("impacket.dcerpc.v5.rpcrt")
    transport = ModuleType("impacket.dcerpc.v5.transport")

    class _Dce:
        def connect(self) -> None:
            return None

        def bind(self, _uuid: Any) -> None:
            return None

        def request(self, _request: Any) -> None:
            return None

        def disconnect(self) -> None:
            return None

    class _RpcTransport:
        def get_dce_rpc(self) -> _Dce:
            return _Dce()

    transport.DCERPCTransportFactory = lambda binding: _RpcTransport()
    rpcrt.uuidtup_to_bin = lambda value: b"uuid"
    import impacket.dcerpc.v5 as _v5

    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rpcrt", rpcrt)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.transport", transport)
    monkeypatch.setattr(_v5, "rpcrt", rpcrt, raising=False)
    monkeypatch.setattr(_v5, "transport", transport, raising=False)
    monkeypatch.setattr(coerce, "_build_coercion_request", lambda method, listener: {})
    outcome = coerce._trigger(target(use_kerberos=False), "dc1", "listener", "printerbug")
    assert outcome["ok"] is True


# --------------------------- computer_takeover branches ---------------------------
def test_computer_takeover_enum_and_failed_change(monkeypatch: Any, tmp_path: Any) -> None:
    computer = Entry(sAMAccountName="WS01$", distinguishedName="CN=WS01,DC=corp,DC=test")
    bare = Entry(sAMAccountName="BARE$", distinguishedName="CN=BARE,DC=corp,DC=test")

    class _C:
        def __init__(self) -> None:
            self.entries: list[Any] = [bare, computer]
            self.unbound = False

        def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
            if "sAMAccountName" in str(search_filter):
                self.entries = [computer]
            else:
                self.entries = [bare, computer]

        def modify(self, dn: str, changes: Any) -> bool:
            return False

        def unbind(self) -> None:
            self.unbound = True

    conn = _C()
    monkeypatch.setattr(
        computer_takeover, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None)
    )
    monkeypatch.setattr(
        computer_takeover,
        "fetch_sd",
        lambda c, dn: None if "BARE" in str(dn) else b"sd",
    )
    monkeypatch.setattr(
        computer_takeover,
        "parse_interesting_aces",
        lambda sd: [
            InterestingAce("S-1-5-21-1", "Enroll"),
            InterestingAce("S-1-5-21-2", "GenericAll"),
        ],
    )
    session = Session(base_dir=tmp_path)
    graph = AttackGraph()
    plain = computer_takeover.ComputerTakeover().run(target(), session, graph)
    assert plain["count"] == 1 and plain["change"] is None

    failed = computer_takeover.ComputerTakeover().run(
        target(),
        session,
        graph,
        force=True,
        write_target="WS01$",
        attribute="dNSHostName",
        value="ws01.evil.test",
    )
    assert failed["change"]["ok"] is False
