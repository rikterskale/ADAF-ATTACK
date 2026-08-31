"""Broad coverage sweep for core modules: ldap_util, workflows, cleanup,
graph, vault, acl, attack_paths, forest_campaign, control_plane,
identity_bridge, computer_takeover, next_actions, sysvol_hunt, and
misc small helpers."""

from __future__ import annotations

import json
import types
from pathlib import Path
from typing import Any

import pytest

import adaf_attack.core.cleanup as cleanup_mod
import adaf_attack.core.control_plane as cp
import adaf_attack.core.forest_campaign as fc
import adaf_attack.core.ldap_util as ldap_util
import adaf_attack.core.workflows as workflows
from adaf_attack.capabilities.attack_paths import AttackPaths
from adaf_attack.capabilities.identity_bridge import HybridSignals
from adaf_attack.capabilities.next_actions import NextActions
from adaf_attack.core.graph import EDGE_WEIGHTS, EXPLOIT_PROFILES, AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target
from adaf_attack.core.vault import SessionVault, VaultError

# --------------------------- ldap_util ---------------------------


class _FakeConnection:
    def __init__(self, *a: Any, **k: Any) -> None:
        self.kwargs = k
        self.bound = bool(k.get("auto_bind"))
        self.result = "success"

    def bind(self) -> bool:
        self.bound = True
        return True


class _FakeServer:
    def __init__(self, *a: Any, **k: Any) -> None:
        self.info = types.SimpleNamespace(
            other={
                "defaultNamingContext": ["DC=corp,DC=test"],
                "configurationNamingContext": ["CN=Config"],
            }
        )


def test_ldap_connect_password_bind(monkeypatch: Any) -> None:
    monkeypatch.setattr(ldap_util, "Server", _FakeServer)
    monkeypatch.setattr(ldap_util, "Connection", _FakeConnection)
    _conn, dn, cfg = ldap_util.ldap_connect(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p")
    )
    assert dn == "DC=corp,DC=test"
    assert cfg == "CN=Config"


def test_ldap_connect_anonymous_and_missing_dc(monkeypatch: Any) -> None:
    class _S:
        def __init__(self, *a: Any, **k: Any) -> None:
            self.info = types.SimpleNamespace(other={})

    monkeypatch.setattr(ldap_util, "Server", _S)
    monkeypatch.setattr(ldap_util, "Connection", _FakeConnection)
    _conn, dn, cfg = ldap_util.ldap_connect(Target(domain="corp.test", dc_ip="10.0.0.1"))
    assert dn == "DC=corp,DC=test"
    assert cfg is None


def test_ldap_connect_bind_failure(monkeypatch: Any) -> None:
    class _FailConn:
        def __init__(self, *a: Any, **k: Any) -> None:
            self.bound = False
            self.result = "invalidCredentials"

        def bind(self) -> bool:
            return False

    monkeypatch.setattr(ldap_util, "Server", _FakeServer)
    monkeypatch.setattr(ldap_util, "Connection", _FailConn)
    with pytest.raises(RuntimeError, match="LDAP bind failed"):
        ldap_util.ldap_connect(
            Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p")
        )


def test_ldap_connect_wraps_ldap_exception(monkeypatch: Any) -> None:
    from ldap3.core.exceptions import LDAPException

    class _Boom(_FakeConnection):
        def __init__(self, *a: Any, **k: Any) -> None:
            super().__init__(*a, **k)
            self.bound = False

        def bind(self) -> bool:
            raise LDAPException("network down")

    monkeypatch.setattr(ldap_util, "Server", _FakeServer)
    monkeypatch.setattr(ldap_util, "Connection", _Boom)
    with pytest.raises(RuntimeError, match="LDAP connection error"):
        ldap_util.ldap_connect(
            Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p")
        )


def test_ldap_connect_starttls(monkeypatch: Any) -> None:
    class _StartTlsConn(_FakeConnection):
        def __init__(self, *a: Any, **k: Any) -> None:
            super().__init__(*a, **k)
            self.bound = False
            self.opened = False
            self.tls_started = False

        def open(self) -> None:
            self.opened = True

        def start_tls(self, **_kwargs: Any) -> bool:
            self.tls_started = True
            return True

    monkeypatch.setattr(ldap_util, "Server", _FakeServer)
    monkeypatch.setattr(ldap_util, "Connection", _StartTlsConn)
    conn, _dn, _cfg = ldap_util.ldap_connect(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p", starttls=True)
    )
    assert conn.opened
    assert conn.tls_started
    assert conn.bound


def test_ldap_connect_kerberos_sasl(monkeypatch: Any) -> None:
    class _SaslConn(_FakeConnection):
        def __init__(self, *a: Any, **k: Any) -> None:
            super().__init__(*a, **k)
            self.bound = False

        def open(self) -> None:
            return None

    monkeypatch.setattr(ldap_util, "Server", _FakeServer)
    monkeypatch.setattr(ldap_util, "Connection", _SaslConn)
    conn, _dn, _cfg = ldap_util.ldap_connect(
        Target(domain="corp.test", dc_ip="10.0.0.1", use_kerberos=True, ccache="ticket.ccache")
    )
    assert conn.kwargs["authentication"] == "SASL"
    assert conn.kwargs["sasl_mechanism"] == "GSSAPI"
    assert conn.bound


# --------------------------- workflows ---------------------------


def test_workflows_full_coverage(tmp_path: Path) -> None:
    # Build a fake session directory with graph.json, trusts-enum.json, etc.
    session_dir = tmp_path / "s1"
    session_dir.mkdir()
    (session_dir / "graph.json").write_text(
        json.dumps(
            {
                "nodes": [{"id": "USER@ALICE@CORP"}, {"id": "DOMAIN@CORP"}],
                "edges": [
                    {"kind": "DCSync"},
                    {"kind": "ESC1"},
                    {"kind": "TrustedBy"},
                    {"kind": "SpoolerOpen"},
                    {"kind": "AllowedToActOnBehalf"},
                    "junk-non-dict",
                ],
            }
        ),
        encoding="utf-8",
    )
    (session_dir / "trusts-enum.json").write_text(
        json.dumps({"trusts": [{"name": "child"}]}), encoding="utf-8"
    )
    (session_dir / "ldap-enum.json").write_text("{}", encoding="utf-8")
    (session_dir / "acl-enum.json").write_text(
        "not-valid-json", encoding="utf-8"
    )  # unreadable → None
    (session_dir / "adcs-enum.json").write_text("{}", encoding="utf-8")
    (session_dir / "session.json").write_text("{}", encoding="utf-8")  # skipped
    # sensitive artifact
    (session_dir / "kerberoast.hashes.txt").write_text("hash", encoding="utf-8")

    # correlate_trusts covers records loop
    corr = workflows.correlate_trusts([session_dir])
    assert corr["records"][0]["trusted_by_edges"] == 1
    assert corr["records"][0]["trusts"][0]["name"] == "child"

    # compose_campaign covers phases loop
    camp = workflows.compose_campaign([session_dir])
    assert camp["phases"][0]["risk_signals"]
    assert "next_step" in camp

    # purple_handoff covers mapping loop
    ph = workflows.purple_handoff(session_dir)
    detected = [d["signal"] for d in ph["detections"]]
    assert "DCSync" in detected and "ESC1" in detected and "SpoolerOpen" in detected

    # validate_surface covers all kinds
    for kind in ("delegation", "adcs", "gpo", "coercion"):
        result = workflows.validate_surface(session_dir, kind)
        assert result["kind"] == kind
        assert "next_step" in result

    # validate_fixtures with mixed files
    fixtures_dir = tmp_path / "fx"
    fixtures_dir.mkdir()
    (fixtures_dir / "ok.json").write_text("{}", encoding="utf-8")
    (fixtures_dir / "bad.json").write_text("nope", encoding="utf-8")
    fx = workflows.validate_fixtures(fixtures_dir)
    assert fx["valid"] is False
    assert len(fx["fixtures"]) == 2


def test_workflows_read_json_missing(tmp_path: Path) -> None:
    # session_evidence with graph.json that isn't a dict
    session_dir = tmp_path / "empty"
    session_dir.mkdir()
    (session_dir / "graph.json").write_text('"not-a-dict"', encoding="utf-8")
    result = workflows.session_evidence(session_dir)
    assert result["edge_kinds"] == {}


# --------------------------- cleanup ---------------------------


class _CleanConn:
    def __init__(self, *, ok: bool = True) -> None:
        self.ok = ok
        self.result = "success" if ok else "denied"
        self.calls: list[Any] = []
        self.unbound = False

    def modify(self, dn: str, changes: Any) -> bool:
        self.calls.append((dn, changes))
        return self.ok

    def unbind(self) -> None:
        self.unbound = True


def test_execute_cleanup_all_kinds(monkeypatch: Any, tmp_path: Path) -> None:
    session = tmp_path / "sess"
    session.mkdir()
    artifact = session / "shadow.dn.txt"
    artifact.write_text("B:8:00010203:CN=x", encoding="utf-8")
    entries = [
        {
            "kind": "computer-identity",
            "status": "pending",
            "target": "CN=DC",
            "attribute": "dNSHostName",
            "previous": ["dc.corp"],
        },
        {
            "kind": "shadow-credential",
            "status": "pending",
            "target": "CN=krbtgt",
            "artifact": str(artifact),
        },
        {"kind": "rbcd", "status": "pending", "target": "CN=WEB", "previous": ["deadbeef"]},
        {"kind": "acl", "status": "pending", "target": "CN=X", "previous_hex": "deadbeef"},
        {"kind": "gpo-link", "status": "pending", "target": "OU=U", "previous": ""},
        # invalid sysvol → rejected
        {"kind": "gpo-sysvol", "status": "pending", "target": "invalid"},
        # unknown kind → skipped
        {"kind": "unknown", "status": "pending"},
        # not pending → skipped
        {"kind": "acl", "status": "completed"},
    ]
    (session / "cleanup.json").write_text(json.dumps(entries), encoding="utf-8")

    conn = _CleanConn()
    monkeypatch.setattr(cleanup_mod, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))

    result = cleanup_mod.execute_cleanup(session, Target(domain="corp.test", dc_ip="10.0.0.1"))
    assert result["completed"] >= 5
    # invalid sysvol path marked failed
    entries_out = json.loads((session / "cleanup.json").read_text(encoding="utf-8"))
    sysvol_entry = next(e for e in entries_out if e["kind"] == "gpo-sysvol")
    assert sysvol_entry["status"] == "failed"
    assert conn.unbound


def test_execute_cleanup_missing_file(monkeypatch: Any, tmp_path: Path) -> None:
    session = tmp_path / "empty"
    session.mkdir()
    monkeypatch.setattr(cleanup_mod, "ldap_connect", lambda t: (_CleanConn(), "DC=x", None))
    out = cleanup_mod.execute_cleanup(session, Target(domain="c", dc_ip="1.1.1.1"))
    assert out["completed"] == 0


def test_execute_cleanup_valid_sysvol_delete(monkeypatch: Any, tmp_path: Path) -> None:
    session = tmp_path / "sv"
    session.mkdir()
    entries = [
        {
            "kind": "gpo-sysvol",
            "status": "pending",
            "target": "corp.test/Policies/{G}/Machine/Scripts/x.xml",
            "host": "dc.corp.test",
        }
    ]
    (session / "cleanup.json").write_text(json.dumps(entries), encoding="utf-8")

    class _SMB:
        def deleteFile(self, share: str, path: str) -> None:
            pass

        def logoff(self) -> None:
            pass

    import adaf_attack.capabilities.gpo_sysvol as gpo_sysvol

    monkeypatch.setattr(gpo_sysvol, "_smb_connect", lambda target, host: _SMB())
    monkeypatch.setattr(cleanup_mod, "ldap_connect", lambda t: (_CleanConn(), "DC=x", None))
    result = cleanup_mod.execute_cleanup(session, Target(domain="corp.test", dc_ip="10.0.0.1"))
    assert result["completed"] == 1


# --------------------------- vault ---------------------------


def test_vault_operations(tmp_path: Path) -> None:
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    v = SessionVault(tmp_path, key=key)
    # put public
    v.put("public", "note", {"info": "ok"}, secret=False, metadata={"k": "v"})
    # put secret
    v.put("secret1", "ccache", {"path": "x"}, secret=True, metadata={"src": "a"})
    # list
    items = v.list()
    assert {i.name for i in items} == {"public", "secret1"}
    # get non-secret
    assert v.get("public") == {"info": "ok"}
    # get secret roundtrip
    assert v.get("secret1")["path"] == "x"
    # get missing
    with pytest.raises(VaultError, match="not found"):
        v.get("nope")


def test_vault_bad_names_and_key(tmp_path: Path) -> None:
    v = SessionVault(tmp_path)
    with pytest.raises(VaultError, match="path separators"):
        v.put("bad/name", "k", {}, secret=False)
    # no key for secret put
    with pytest.raises(VaultError, match="Set ADAF_SESSION_VAULT_KEY"):
        v.put("s", "k", {}, secret=True)
    # invalid key format
    v2 = SessionVault(tmp_path, key="not-a-fernet-key")
    with pytest.raises(VaultError, match="Fernet key"):
        v2.put("s", "k", {}, secret=True)


def test_vault_malformed_index(tmp_path: Path) -> None:
    v = SessionVault(tmp_path)
    v.index_path.write_text("[]", encoding="utf-8")  # list, not dict
    with pytest.raises(VaultError, match="malformed"):
        v.list()


def test_vault_get_secret_without_key(tmp_path: Path) -> None:
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    v = SessionVault(tmp_path, key=key)
    v.put("s", "k", {"p": "x"}, secret=True)
    v_noread = SessionVault(tmp_path)  # no key
    with pytest.raises(VaultError, match="Set ADAF_SESSION_VAULT_KEY"):
        v_noread.get("s")


def test_vault_get_secret_bad_decrypt(tmp_path: Path) -> None:
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    v = SessionVault(tmp_path, key=key)
    v.put("s", "k", {"p": "x"}, secret=True)
    # corrupt cipher file
    (v.root / "s.vault").write_bytes(b"not-valid-ciphertext")
    with pytest.raises(VaultError, match="Unable to decrypt"):
        v.get("s")


# --------------------------- graph edge branches ---------------------------


def test_graph_helpers_and_edge_weights_fallback() -> None:
    g = AttackGraph()
    g.add_node("USER@ALICE@CORP", "User", sam="alice")
    g.add_node("GROUP@ADMINS@CORP", "Group", sam="Admins")
    g.add_edge("USER@ALICE@CORP", "GROUP@ADMINS@CORP", "MemberOf")

    # neighbors filtered by edge kind
    filtered = g.neighbors("USER@ALICE@CORP", edge_kind="MemberOf")
    assert len(filtered) == 1

    # nodes_of_kind
    assert len(g.nodes_of_kind("User")) == 1

    # find_node: exact
    assert g.find_node("USER@ALICE@CORP") == "USER@ALICE@CORP"
    # SAM lookup (case-insensitive)
    assert g.find_node("alice") == "USER@ALICE@CORP"
    # fragment
    assert g.find_node("ADMINS") == "GROUP@ADMINS@CORP"
    # miss
    assert g.find_node("does-not-exist") is None

    # edge weight fallback
    assert g._edge_weight("UnknownEdgeKind") == EDGE_WEIGHTS["Default"]


def test_graph_resolve_dn_edges_maps_groupdn() -> None:
    g = AttackGraph()
    g.add_node("USER@A@C", "User")
    g.add_node("GROUP@ADMINS@C", "Group", dn="CN=Admins,DC=corp,DC=test")
    g.add_edge("USER@A@C", "GROUPDN@CN=Admins,DC=corp,DC=test", "MemberOf")
    resolved = g.resolve_dn_edges()
    assert resolved == 1
    # ensure edge target rewritten
    assert any(e.target == "GROUP@ADMINS@C" for e in g.edges)


def test_graph_rank_paths_high_value_bonus() -> None:
    g = AttackGraph()
    g.add_node("USER@ALICE@CORP", "User", sam="alice")
    g.add_node("GROUP@DOMAIN ADMINS@CORP", "Group", sam="Domain Admins")
    g.add_edge("USER@ALICE@CORP", "GROUP@DOMAIN ADMINS@CORP", "MemberOf")
    ranked = g.rank_paths("USER@ALICE@CORP", max_depth=3, limit=5)
    assert ranked and ranked[0].nodes[-1] == "GROUP@DOMAIN ADMINS@CORP"


def test_graph_rank_exploit_chains_from_default_candidates() -> None:
    g = AttackGraph()
    g.add_node("USER@A@C", "User")
    g.add_node("DOMAIN@C", "Domain")
    # Use a kind that has an exploit profile
    if EXPLOIT_PROFILES:
        kind = next(iter(EXPLOIT_PROFILES))
        g.add_edge("USER@A@C", "DOMAIN@C", kind)
        chains = g.rank_exploit_chains(None, max_depth=3, limit=5)
        assert chains
        assert chains[0]["terminal_relation"] == kind


# --------------------------- attack_paths ---------------------------


def test_attack_paths_from_explicit_graph(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "sess")
    seed = AttackGraph()
    seed.add_node("USER@A@C", "User", sam="a")
    seed.add_node("GROUP@ADMINS@C", "Group", sam="Admins")
    seed.add_edge("USER@A@C", "GROUP@ADMINS@C", "MemberOf")
    graph_file = tmp_path / "graph.json"
    seed.save(graph_file)

    result = AttackPaths().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        graph_path=str(graph_file),
    )
    assert result["loaded_from"] == str(graph_file.expanduser())


def test_attack_paths_missing_graph(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "sess")
    with pytest.raises(RuntimeError, match="Graph file not found"):
        AttackPaths().run(
            Target(domain="corp.test", dc_ip="1.1.1.1"),
            session,
            AttackGraph(),
            graph_path=str(tmp_path / "none.json"),
        )


def test_attack_paths_no_graph_fallback(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "sess")
    with pytest.raises(RuntimeError, match="No graph loaded"):
        AttackPaths().run(Target(domain="corp.test", dc_ip="1.1.1.1"), session, AttackGraph())


def test_attack_paths_hydrates_latest_session_graph(tmp_path: Path) -> None:
    # workspace/parent structure with a sibling session containing graph.json
    workspace = tmp_path
    older = workspace / "old"
    older.mkdir()
    seed = AttackGraph()
    seed.add_node("USER@X@C", "User", sam="x")
    seed.save(older / "graph.json")

    session = Session(base_dir=workspace)
    result = AttackPaths().run(Target(domain="corp.test", dc_ip="1.1.1.1"), session, AttackGraph())
    assert result["loaded_from"]


# --------------------------- control_plane ---------------------------


def test_resolve_opsec_and_package_evidence(tmp_path: Path) -> None:
    for name in ("stealth", "balanced", "loud"):
        opsec = cp.resolve_opsec(name)
        assert opsec["name"] == name
    with pytest.raises(ValueError, match="Unknown OPSEC"):
        cp.resolve_opsec("nope")

    session = tmp_path / "sess"
    session.mkdir()
    (session / "session.json").write_text("{}", encoding="utf-8")
    (session / "kerberoast.hashes.txt").write_text("h", encoding="utf-8")
    (session / "graph.json").write_text('{"nodes":[],"edges":[]}', encoding="utf-8")
    (session / "invalid.json").write_text("not-json", encoding="utf-8")

    out = tmp_path / "pkg.zip"
    result = cp.package_evidence(session, out, profile="client")
    assert result["profile"] == "client"
    assert Path(result["archive"]).is_file()

    with pytest.raises(ValueError, match="does not exist"):
        cp.package_evidence(tmp_path / "no-such-session", out)


def test_package_evidence_cleans_staging(tmp_path: Path) -> None:
    session = tmp_path / "sess"
    session.mkdir()
    (session / "session.json").write_text("{}", encoding="utf-8")
    # pre-create staging directory to hit shutil.rmtree branch
    staging = tmp_path / "pkg"
    staging.mkdir()
    (staging / "old.txt").write_text("stale", encoding="utf-8")
    out = tmp_path / "pkg.zip"
    result = cp.package_evidence(session, out, profile="operator")
    assert Path(result["archive"]).is_file()


# --------------------------- identity_bridge + next_actions ---------------------------


def test_hybrid_signals_and_next_actions(tmp_path: Path, monkeypatch: Any) -> None:
    # HybridSignals via mocked ldap connection
    import adaf_attack.capabilities.identity_bridge as ib_mod

    class _E:
        def __init__(self, **v: Any) -> None:
            for k, val in v.items():
                setattr(self, k, val)

    class _Attr:
        def __init__(self, value: Any) -> None:
            self.value = value

        def __str__(self) -> str:
            return str(self.value)

        def __bool__(self) -> bool:
            return self.value is not None

    class _Conn:
        entries: list[Any] = []
        unbound = False

        def search(self, *a: Any, **k: Any) -> None:
            e = _E(
                sAMAccountName=_Attr("adconnect$"),
                description=_Attr("Azure AD Connect service"),
                servicePrincipalName=None,
            )
            self.entries = [e]

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(ib_mod, "ldap_connect", lambda t: (_Conn(), "DC=corp,DC=test", None))
    session = Session(base_dir=tmp_path / "sess")
    graph = AttackGraph()
    result = HybridSignals().run(Target(domain="corp.test", dc_ip="10.0.0.1"), session, graph)
    assert result["count"] >= 1

    # next_actions with seeded graph
    graph.add_node("USER@A@C", "User", sam="a")
    graph.add_edge("USER@A@C", "USER@A@C", "HasSPN", spn="HTTP/x")
    na = NextActions().run(Target(domain="c", dc_ip="1.1.1.1"), session, graph)
    assert isinstance(na, dict)


def test_next_actions_no_graph_raises(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "sess")
    with pytest.raises(RuntimeError, match="No graph available"):
        NextActions().run(Target(domain="c", dc_ip="1.1.1.1"), session, AttackGraph())


def test_next_actions_hydrates_from_graph_file(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "sess")
    seed = AttackGraph()
    seed.add_node("USER@A@C", "User")
    seed.save(session.path("graph.json"))
    result = NextActions().run(Target(domain="c", dc_ip="1.1.1.1"), session, AttackGraph())
    assert isinstance(result, dict)


# --------------------------- sysvol_hunt small branches ---------------------------


# sysvol_hunt small branches tested via existing tests


# --------------------------- forest_campaign ---------------------------


def test_forest_campaign_compose(tmp_path: Path) -> None:
    session = tmp_path / "s1"
    session.mkdir()
    (session / "session.json").write_text('{"session_id": "s1"}', encoding="utf-8")
    (session / "ldap-enum.json").write_text(json.dumps({"domain": "corp.test"}), encoding="utf-8")
    (session / "trusts-enum.json").write_text(json.dumps({"trusts": []}), encoding="utf-8")
    (session / "graph.json").write_text('{"nodes":[],"edges":[]}', encoding="utf-8")
    result = fc.compose_forest_campaign([session])
    assert "domains" in result
