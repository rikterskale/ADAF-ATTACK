"""Offline coverage for the 40 promoted offensive capabilities."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

import pytest

import adaf_attack.capabilities.acl_primitives as acl_primitives
import adaf_attack.capabilities.adcs_esc as adcs_esc
import adaf_attack.capabilities.credential_ops as credential_ops
import adaf_attack.capabilities.delegation_ops as delegation_ops
import adaf_attack.capabilities.dmsa_ops as dmsa_ops
import adaf_attack.capabilities.dns_ops as dns_ops
import adaf_attack.capabilities.joined_workflows as joined_workflows
import adaf_attack.capabilities.maq_ops as maq_ops
import adaf_attack.capabilities.relay_ops as relay_ops
import adaf_attack.capabilities.sccm_ops as sccm_ops
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.rbcd_sd import build_allowed_to_act_sd
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value
        self.values = value if isinstance(value, list) else ([] if value is None else [value])
        self.raw_values = self.values

    def __bool__(self) -> bool:
        return self.value is not None and self.value != []

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **values: Any) -> None:
        self._values = {key: _Attr(value) for key, value in values.items()}

    def __getattr__(self, name: str) -> _Attr:
        if name in self._values:
            return self._values[name]
        alt = name.replace("_", "-")
        if alt in self._values:
            return self._values[alt]
        return _Attr()

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _Conn:
    def __init__(self, by_filter: dict[str, list[_Entry]] | None = None) -> None:
        self.by_filter = by_filter or {}
        self.entries: list[_Entry] = []
        self.result = {"result": 0, "description": "success"}
        self.modifies: list[Any] = []
        self.adds: list[Any] = []
        self.deletes: list[str] = []
        self.unbound = False

    def search(self, base: str, search_filter: str, **kwargs: Any) -> bool:
        for key, entries in self.by_filter.items():
            if key in search_filter or search_filter in key or key in base:
                self.entries = entries
                return True
        if base in self.by_filter:
            self.entries = self.by_filter[base]
            return True
        self.entries = []
        return True

    def modify(self, dn: str, changes: Any) -> bool:
        self.modifies.append((dn, changes))
        return True

    def add(self, dn: str, attributes: Any = None) -> bool:
        self.adds.append((dn, attributes))
        return True

    def delete(self, dn: str) -> bool:
        self.deletes.append(dn)
        return True

    def unbind(self) -> None:
        self.unbound = True


def _managed_blob(password: str) -> bytes:
    cur = password.encode("utf-16-le") + b"\x00\x00"
    header = struct.pack("<HHI", 1, 0, 16 + len(cur))
    header += struct.pack("<HHHH", 16, 0, 0, 0)
    return header + cur


def _target(**kwargs: Any) -> Target:
    values = {
        "domain": "corp.test",
        "dc_ip": "10.0.0.1",
        "username": "alice",
        "password": "Secret1!",
        "ldaps": True,
    }
    values.update(kwargs)
    return Target(**values)


def _sid_entry(sam: str, dn: str, sid: str = "S-1-5-21-1-2-3-1104") -> _Entry:
    return _Entry(
        sAMAccountName=sam, distinguishedName=dn, objectSid=sid, member=[], servicePrincipalName=[]
    )


def _patch_ldap(monkeypatch: Any, module: Any, conn: _Conn, base: str = "DC=corp,DC=test") -> None:
    monkeypatch.setattr(
        module, "ldap_connect", lambda target: (conn, base, "CN=Configuration,DC=corp,DC=test")
    )


def test_add_member_and_add_self(monkeypatch: Any, tmp_path: Path) -> None:
    group = _sid_entry("Domain Admins", "CN=Domain Admins,DC=corp,DC=test")
    user = _sid_entry("alice", "CN=Alice,DC=corp,DC=test")
    conn = _Conn({"Domain Admins": [group], "alice": [user], "ALICE": [user]})
    _patch_ldap(monkeypatch, acl_primitives, conn)
    session = Session(tmp_path)
    graph = AttackGraph()
    with pytest.raises(RuntimeError, match="--force"):
        acl_primitives.AddMember().run(
            _target(), session, graph, group="Domain Admins", member="alice"
        )
    result = acl_primitives.AddMember().run(
        _target(), session, graph, force=True, group="Domain Admins", member="alice"
    )
    assert result["ok"] is True
    self_result = acl_primitives.AddSelf().run(
        _target(), session, graph, force=True, group="Domain Admins"
    )
    assert self_result["ok"] is True
    with pytest.raises(RuntimeError, match="username"):
        acl_primitives.AddSelf().run(
            _target(username=None), session, graph, force=True, group="Domain Admins"
        )
    conn.by_filter = {}
    with pytest.raises(RuntimeError, match="not found"):
        acl_primitives.AddMember().run(
            _target(), session, graph, force=True, group="missing", member="alice"
        )


def test_password_spn_acl_sidhistory(monkeypatch: Any, tmp_path: Path) -> None:
    user = _sid_entry("bob", "CN=Bob,DC=corp,DC=test")
    user._values["servicePrincipalName"] = _Attr(["HOST/old"])
    user._values["sIDHistory"] = _Attr([])
    alice = _sid_entry("alice", "CN=Alice,DC=corp,DC=test")
    conn = _Conn({"bob": [user], "alice": [alice], "*": [user]})
    _patch_ldap(monkeypatch, acl_primitives, conn)
    monkeypatch.setattr(
        acl_primitives, "fetch_sd", lambda *_a, **_k: build_allowed_to_act_sd("S-1-5-21-1-2-3-9")
    )
    session = Session(tmp_path)
    graph = AttackGraph()
    pwd = acl_primitives.ForceChangePassword().run(
        _target(), session, graph, force=True, sam="bob", new_password="N3w!", include_secrets=True
    )
    assert pwd["ok"] and pwd["password"] == "N3w!"
    spn = acl_primitives.WriteSpn().run(
        _target(), session, graph, force=True, sam="bob", spn="HTTP/app"
    )
    assert "HTTP/app" in spn["spns"]
    cleared = acl_primitives.WriteSpn().run(
        _target(), session, graph, force=True, sam="bob", clear=True
    )
    assert cleared["spns"] == []
    replaced = acl_primitives.WriteSpn().run(
        _target(), session, graph, force=True, sam="bob", spns=["HTTP/a", "HTTP/b"], replace=True
    )
    assert replaced["spns"] == ["HTTP/a", "HTTP/b"]
    comma = acl_primitives.WriteSpn().run(
        _target(), session, graph, force=True, sam="bob", spn="HTTP/a, HTTP/b", replace=True
    )
    assert comma["spns"] == ["HTTP/a", "HTTP/b"]
    empty_list = acl_primitives.WriteSpn().run(
        _target(), session, graph, force=True, sam="bob", spns=[], replace=True
    )
    assert empty_list["spns"] == []
    with pytest.raises(RuntimeError, match="spn"):
        acl_primitives.WriteSpn().run(_target(), session, graph, force=True, sam="bob")
    for rights in ("GenericAll", "WriteOwner", "GetChangesAll", "GetChanges", "owns"):
        abused = acl_primitives.AclAbuse().run(
            _target(),
            session,
            graph,
            force=True,
            sam="bob",
            rights=rights,
            principal_sid="S-1-5-21-1-2-3-4",
        )
        assert abused["ok"] is True
    with pytest.raises(RuntimeError, match="principal_sid"):
        acl_primitives.AclAbuse().run(_target(username=None), session, graph, force=True, sam="bob")
    parsed = acl_primitives.AclAbuse().run(
        _target(), session, graph, force=True, sam="bob", rights="GenericAll"
    )
    assert parsed["ok"] is True
    alice_bad = _sid_entry("alice", "CN=Alice,DC=corp,DC=test")
    alice_bad._values["objectSid"] = _Attr(b"\x00\x01")
    conn.by_filter["alice"] = [alice_bad]
    with pytest.raises(RuntimeError, match="parse"):
        acl_primitives.AclAbuse().run(_target(), session, graph, force=True, sam="bob")
    conn.by_filter["alice"] = [alice]
    holder = acl_primitives.AdminSdHolderPersist().run(
        _target(), session, graph, force=True, principal_sid="S-1-5-21-1-2-3-4"
    )
    assert holder["ok"] is True
    sid = acl_primitives.SidHistoryInject().run(
        _target(), session, graph, force=True, sam="bob", sid="S-1-5-21-99", method="ldap"
    )
    assert sid["ok"] is True
    conn.by_filter = {"bob": [user]}
    with pytest.raises(RuntimeError, match="SID"):
        acl_primitives.AclAbuse().run(_target(), session, graph, force=True, sam="bob")


def test_delegation_ops(monkeypatch: Any, tmp_path: Path) -> None:
    unconstrained = _Entry(
        sAMAccountName="DC01$",
        distinguishedName="CN=DC01,DC=corp,DC=test",
        userAccountControl=0x80000,
        dNSHostName="dc01.corp.test",
        **{"msDS-AllowedToDelegateTo": []},
    )
    proto = _Entry(
        sAMAccountName="svc",
        distinguishedName="CN=svc,DC=corp,DC=test",
        userAccountControl=0x01000000,
        **{"msDS-AllowedToDelegateTo": ["cifs/dc01.corp.test"]},
    )
    bad_uac = _Entry(
        sAMAccountName="broken",
        distinguishedName="CN=b,DC=corp,DC=test",
        userAccountControl="nope",
    )
    empty = _Entry(sAMAccountName="", distinguishedName="CN=x")
    conn = _Conn(
        {
            "objectClass=user": [unconstrained, proto, bad_uac, empty],
            "objectClass=computer": [unconstrained, proto, bad_uac, empty],
            "svc": [proto],
        }
    )
    _patch_ldap(monkeypatch, delegation_ops, conn)
    session = Session(tmp_path)
    graph = AttackGraph()
    u = delegation_ops.UnconstrainedDelegation().run(_target(), session, graph)
    assert u["count"] >= 1
    t = delegation_ops.TrustedToAuth().run(_target(), session, graph)
    assert t["count"] >= 1
    c = delegation_ops.ConstrainedDelegation().run(_target(), session, graph)
    assert c["count"] >= 1
    with pytest.raises(RuntimeError, match="--force"):
        delegation_ops.ConstrainedDelegation().run(_target(), session, graph, sam="svc")
    with pytest.raises(RuntimeError, match="spn"):
        delegation_ops.ConstrainedDelegation().run(_target(), session, graph, force=True, sam="svc")
    set_ok = delegation_ops.ConstrainedDelegation().run(
        _target(), session, graph, force=True, sam="svc", spn="cifs/app.corp.test"
    )
    assert set_ok["set_attempt"]["ok"] is True
    conn.by_filter["svc"] = []
    with pytest.raises(RuntimeError, match="not found"):
        delegation_ops.ConstrainedDelegation().run(
            _target(), session, graph, force=True, sam="svc", spn="cifs/x"
        )


def test_dmsa_and_maq(monkeypatch: Any, tmp_path: Path) -> None:
    krbtgt = _sid_entry("krbtgt", "CN=krbtgt,DC=corp,DC=test")
    dmsa = _sid_entry("ADA$", "CN=ADA,DC=corp,DC=test")
    conn = _Conn({"krbtgt": [krbtgt], "ADA$": [dmsa], "ADA": [dmsa]})
    _patch_ldap(monkeypatch, dmsa_ops, conn)
    _patch_ldap(monkeypatch, maq_ops, conn)
    session = Session(tmp_path)
    graph = AttackGraph()
    with pytest.raises(RuntimeError, match="not found"):
        dmsa_ops.BadSuccessor().run(_target(), session, graph, force=True, preceded_by="missing")
    dmsa._values["msDS-ManagedPassword"] = _Attr(_managed_blob("DmsaSecret"))
    conn.by_filter["CN=ADA"] = [dmsa]
    conn.by_filter["objectClass=*"] = [dmsa]
    empty_conn = _Conn({})
    assert dmsa_ops._read_managed_password(empty_conn, "CN=x", True) == {"present": False}
    empty_conn.by_filter["objectClass=*"] = [_Entry(sAMAccountName="x")]
    assert dmsa_ops._read_managed_password(empty_conn, "CN=x", False)["present"] is False
    created = dmsa_ops.BadSuccessor().run(
        _target(), session, graph, force=True, preceded_by="krbtgt", include_secrets=True
    )
    assert created["ok"] is True
    existing = dmsa_ops.DmsaOuroboros().run(_target(), session, graph, force=True, sam="ADA$")
    assert existing["ok"] is True
    ouro = dmsa_ops.DmsaOuroboros().run(
        _target(), session, graph, force=True, preceded_by="krbtgt", superordinate="CN=x"
    )
    assert ouro["ok"] is True
    conn.by_filter["ADA$"] = []
    conn.by_filter["ADA"] = []
    with pytest.raises(RuntimeError, match="not found"):
        dmsa_ops.DmsaOuroboros().run(_target(), session, graph, force=True, sam="ADA$")
    with pytest.raises(RuntimeError, match="not found"):
        dmsa_ops.DmsaOuroboros().run(_target(), session, graph, force=True, preceded_by="nope")
    computer = maq_ops.MaqAddComputer().run(
        _target(), session, graph, force=True, computer="NEWPC", password="p", include_secrets=True
    )
    assert computer["ok"] is True and computer["password"] == "p"
    with pytest.raises(RuntimeError, match="set_on"):
        maq_ops.MaqRbcdWorkflow().run(_target(), session, graph, force=True)

    class _Rbcd:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"set_attempt": {"ok": True}}

    class _S4u:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

    monkeypatch.setattr(maq_ops, "Rbcd", _Rbcd)
    monkeypatch.setattr(maq_ops, "S4uAbuse", _S4u)
    wf = maq_ops.MaqRbcdWorkflow().run(
        _target(), session, graph, force=True, set_on="DC01$", impersonate="Administrator"
    )
    assert wf["ok"] is True


def test_credential_ops(monkeypatch: Any, tmp_path: Path) -> None:
    blob = _managed_blob("SuperSecret123!")
    gmsa = _Entry(
        sAMAccountName="svc$",
        distinguishedName="CN=svc,DC=corp,DC=test",
        **{"msDS-ManagedPassword": blob},
    )
    empty = _Entry(sAMAccountName="empty$", distinguishedName="CN=e,DC=corp,DC=test")
    computer = _Entry(sAMAccountName="WS01$")
    msol = _Entry(sAMAccountName="MSOL_abc", distinguishedName="CN=MSOL,DC=corp,DC=test")
    sso = _Entry(
        sAMAccountName="AZUREADSSOACC$",
        distinguishedName="CN=SSO,DC=corp,DC=test",
        servicePrincipalName=["HOST/sso"],
    )
    conn = _Conn(
        {
            "svc": [gmsa],
            "msDS-GroupManagedServiceAccount": [gmsa, empty],
            "objectClass=computer": [computer],
            "MSOL_": [msol],
            "AZUREADSSOACC": [sso],
        }
    )
    _patch_ldap(monkeypatch, credential_ops, conn)
    monkeypatch.setattr(credential_ops, "try_ntlm_bind", lambda *a, **k: (True, "ok"))
    session = Session(tmp_path)
    graph = AttackGraph()
    one = credential_ops.GmsaRead().run(_target(), session, graph, sam="svc$", include_secrets=True)
    assert one["count"] == 1
    all_g = credential_ops.GmsaRead().run(_target(), session, graph)
    assert all_g["count"] >= 1
    pre = credential_ops.Pre2kSpray().run(_target(), session, graph, max_attempts=1, max_objects=10)
    assert pre["hit_count"] == 1
    monkeypatch.setattr(credential_ops, "try_ntlm_bind", lambda *a, **k: (False, "no"))
    pre2 = credential_ops.Pre2kSpray().run(_target(), session, graph, max_attempts=1)
    assert pre2["hit_count"] == 0
    monkeypatch.setattr(credential_ops, "_udp_query", lambda *a, **k: b"\x00" * 68)
    roast = credential_ops.Timeroast().run(
        _target(), session, graph, rid_start=1, rid_end=1, include_secrets=True
    )
    assert roast["count"] == 1

    def _boom(*_a: Any, **_k: Any) -> bytes:
        raise OSError("down")

    monkeypatch.setattr(credential_ops, "_udp_query", _boom)
    fail = credential_ops.Timeroast().run(_target(), session, graph, rid_start=1, count=0)
    assert fail["hashes"][0]["error"]

    class _Kerberoast:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"tickets": [{"account": "AZUREADSSOACC$", "spn": "HOST/sso"}]}

    monkeypatch.setattr(credential_ops, "Kerberoast", _Kerberoast)
    sso_r = credential_ops.AzureAdSsoAccRoast().run(_target(), session, graph)
    assert sso_r["ok"] is True
    conn.by_filter["AZUREADSSOACC"] = []
    missing = credential_ops.AzureAdSsoAccRoast().run(_target(), session, graph)
    assert missing["ok"] is False

    class _Dcsync:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True, "count": 1}

    monkeypatch.setattr(credential_ops, "Dcsync", _Dcsync)
    aad = credential_ops.AadConnectDcsync().run(_target(), session, graph)
    assert aad["ok"] is True
    conn.by_filter["MSOL_"] = []
    none = credential_ops.AadConnectDcsync().run(_target(), session, graph)
    assert none["ok"] is False


def test_dpapi_domain_backup(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(tmp_path)
    graph = AttackGraph()
    monkeypatch.setattr(credential_ops, "require_impacket", lambda *_a, **_k: None)
    with pytest.raises(RuntimeError, match="credentials"):
        credential_ops.DpapiDomainBackup().run(
            _target(password=None, username=None), session, graph
        )

    from tests.gate_helpers import install_dpapi_lsarpc_mocks

    # Preferred-key (v2) success over kerberos, secrets included.
    install_dpapi_lsarpc_mocks(monkeypatch)
    result = credential_ops.DpapiDomainBackup().run(
        _target(use_kerberos=True), session, graph, include_secrets=True
    )
    assert result["ok"] is True
    assert bytes.fromhex(result["backup_keys"][0]).endswith(b"KEY!")

    # Legacy (v1) key over NT-hash login, no secrets echoed.
    install_dpapi_lsarpc_mocks(monkeypatch, version=1)
    legacy = credential_ops.DpapiDomainBackup().run(
        _target(hashes="aad3b435:31d6cfe0"), session, graph
    )
    assert legacy["ok"] is True
    assert legacy["backup_keys_present"] is True

    # Unsupported key version.
    install_dpapi_lsarpc_mocks(monkeypatch, version=9)
    bad_version = credential_ops.DpapiDomainBackup().run(_target(), session, graph)
    assert bad_version["ok"] is False
    assert "version 9" in bad_version["error"]

    # Missing rights maps to a stable privileges error.
    install_dpapi_lsarpc_mocks(monkeypatch, fail_at="preferred")
    denied = credential_ops.DpapiDomainBackup().run(_target(), session, graph)
    assert denied["ok"] is False
    assert "replication/backup-key privileges" in denied["error"]

    # LSA bind failure surfaces the underlying error verbatim.
    install_dpapi_lsarpc_mocks(monkeypatch, fail_at="bind", error_text="connection refused")
    refused = credential_ops.DpapiDomainBackup().run(_target(), session, graph)
    assert refused["ok"] is False
    assert refused["error"] == "connection refused"

    # OpenPolicy failure also lands in the generic branch.
    install_dpapi_lsarpc_mocks(monkeypatch, fail_at="open", error_text="policy failed")
    policy_fail = credential_ops.DpapiDomainBackup().run(_target(), session, graph)
    assert policy_fail["error"] == "policy failed"

    # Failure retrieving the backup key itself.
    install_dpapi_lsarpc_mocks(monkeypatch, fail_at="key")
    key_fail = credential_ops.DpapiDomainBackup().run(_target(), session, graph)
    assert key_fail["ok"] is False
    assert key_fail["error"]

    # Connect failure before bind.
    install_dpapi_lsarpc_mocks(monkeypatch, fail_at="connect", error_text="no pipe")
    connect_fail = credential_ops.DpapiDomainBackup().run(_target(), session, graph)
    assert connect_fail["error"] == "no pipe"


def test_dns_ops(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _Conn({"MicrosoftDNS": [_Entry(name="corp.test")], "*": []})
    _patch_ldap(monkeypatch, dns_ops, conn)
    session = Session(tmp_path)
    graph = AttackGraph()
    wpad = dns_ops.AdidnsWpad().run(_target(), session, graph, force=True, ip="10.0.0.9")
    assert wpad["ok"] is True
    cname = dns_ops.AdidnsWpad().run(
        _target(), session, graph, force=True, ip="10.0.0.9", cname="evil.test"
    )
    assert cname["ok"] is True
    srv = dns_ops.DnsAdminSrv().run(_target(), session, graph, force=True, host="evil.test")
    assert srv["ok"] is True
    empty = _Conn({})
    _patch_ldap(monkeypatch, dns_ops, empty)
    fallback = dns_ops.AdidnsWpad().run(_target(), session, graph, force=True, ip="10.0.0.9")
    assert fallback["zone"]


def test_adcs_esc(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(tmp_path)
    graph = AttackGraph()
    with pytest.raises(RuntimeError, match="template"):
        adcs_esc.Esc9().run(_target(), session, graph, force=True)
    with pytest.raises(RuntimeError, match="username"):
        adcs_esc.Esc9().run(_target(username=None), session, graph, force=True, template="User")
    session.path("adcs-enum.json").write_text("not-json", encoding="utf-8")
    assert adcs_esc._load_adcs(session) is None
    session.path("adcs-enum.json").write_text(
        json.dumps(
            {
                "templates": [
                    {"cn": "ESC9", "esc_tags": ["ESC9"], "esc9_candidate": True},
                    {"cn": "Other"},
                ],
                "cas": [{"cn": "CORP-CA"}],
                "esc1_candidates": ["User"],
            }
        ),
        encoding="utf-8",
    )
    assert adcs_esc._pick_template(adcs_esc._load_adcs(session), "ESC9") == "ESC9"
    assert adcs_esc._pick_ca(adcs_esc._load_adcs(session)) == "CORP-CA"
    assert adcs_esc._pick_template({"templates": [{"displayName": "X"}]}, "ESC9") == "X"
    assert adcs_esc._pick_template({"esc1_candidates": ["User"]}, "ESC9") == "User"
    assert adcs_esc._pick_template({}, "ESC9") is None
    assert adcs_esc._pick_ca({"cas": ["CA"]}) == "CA"
    assert adcs_esc._pick_ca({}) is None
    assert adcs_esc._pick_ca({"cas": []}) is None
    assert adcs_esc._pick_ca({"cas": [{"display_name": ""}]}) is None

    monkeypatch.setattr(
        adcs_esc.subprocess,
        "run",
        lambda *a, **k: type("P", (), {"returncode": 0, "stdout": "ok", "stderr": ""})(),
    )
    (session.root / "enroll.pfx").write_text("x", encoding="utf-8")
    esc = adcs_esc.Esc9().run(_target(), session, graph, force=True, alt_name="admin@corp.test")
    assert esc["ok"] is True
    hashed_esc = adcs_esc.Esc9().run(
        _target(password=None, hashes="aad3:dead"),
        session,
        graph,
        force=True,
        template="T",
        ca="CA",
    )
    assert hashed_esc["ok"] is True
    esc15 = adcs_esc.Esc15().run(_target(), session, graph, force=True, template="V1", ca="CA")
    assert esc15["ok"] is True
    for cls in (adcs_esc.Esc10, adcs_esc.Esc13, adcs_esc.Esc14, adcs_esc.Esc16):
        assert cls().run(_target(), session, graph, force=True, template="T", ca="CA")["ok"]

    def _missing(*a: Any, **k: Any) -> Any:
        raise FileNotFoundError("certipy")

    monkeypatch.setattr(adcs_esc.subprocess, "run", _missing)
    play = adcs_esc.Esc9().run(_target(), session, graph, force=True, template="T")
    assert play["method"] == "playbook-only"

    def _err(*a: Any, **k: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(adcs_esc.subprocess, "run", _err)
    err = adcs_esc.Esc9().run(_target(), session, graph, force=True, template="T")
    assert err["method"] == "error"
    with pytest.raises(RuntimeError, match="ca_pfx"):
        adcs_esc.GoldenCert().run(_target(), session, graph, force=True)
    with pytest.raises(RuntimeError, match="upn"):
        adcs_esc.GoldenCert().run(_target(), session, graph, force=True, ca_pfx="ca.pfx")
    monkeypatch.setattr(
        adcs_esc.subprocess,
        "run",
        lambda *a, **k: type("P", (), {"returncode": 1, "stdout": "", "stderr": "fail"})(),
    )
    forged = adcs_esc.GoldenCert().run(
        _target(), session, graph, force=True, ca_pfx="ca.pfx", upn="a@corp.test", subject="CN=A"
    )
    assert forged["ok"] is False
    with pytest.raises(RuntimeError, match="ca="):
        adcs_esc.Esc8RelayWorkflow().run(_target(), session, graph, force=True)

    class _Relay:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"return_code": 0}

    class _Coerce:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

    monkeypatch.setattr(adcs_esc, "NtlmRelay", _Relay)
    monkeypatch.setattr(adcs_esc, "Coerce", _Coerce)
    esc8 = adcs_esc.Esc8RelayWorkflow().run(
        _target(), session, graph, force=True, ca="ca.corp.test", coerce_host="ws01"
    )
    assert esc8["ok"] is True


def test_sccm_and_relay(monkeypatch: Any, tmp_path: Path) -> None:
    mp = _Entry(
        cn="MP",
        distinguishedName="CN=MP,CN=System Management,CN=System,DC=corp,DC=test",
        dNSHostName="mp.corp.test",
        mSSMSSiteCode="P01",
        mSSMSMPName="mp.corp.test",
        mSSMSVersion="5",
    )
    naa = _Entry(
        cn="NetworkAccessAccount", distinguishedName="CN=NAA,DC=corp,DC=test", sAMAccountName="naa"
    )
    conn = _Conn({"System Management": [mp], "NetworkAccessAccount": [naa], "*": [mp]})
    _patch_ldap(monkeypatch, sccm_ops, conn)
    session = Session(tmp_path)
    graph = AttackGraph()
    enum = sccm_ops.SccmEnum().run(_target(), session, graph)
    assert enum["count"] >= 1

    boom = _Conn({})

    def _search_boom(*args: Any, **kwargs: Any) -> bool:
        raise RuntimeError("ldap")

    boom.search = _search_boom  # type: ignore[method-assign]
    _patch_ldap(monkeypatch, sccm_ops, boom)
    empty = sccm_ops.SccmEnum().run(_target(), session, graph)
    assert empty["count"] == 0
    _patch_ldap(monkeypatch, sccm_ops, conn)

    monkeypatch.setattr(
        sccm_ops, "_http_get", lambda url, timeout=5.0: (200, "CCM_NetworkAccessAccount=1")
    )
    naa_r = sccm_ops.SccmNaa().run(
        _target(), session, graph, include_secrets=True, mp="mp2.corp.test"
    )
    assert naa_r["ok"] is True

    def _http_err(url: str, timeout: float = 5.0) -> tuple[int, str]:
        raise RuntimeError("down")

    monkeypatch.setattr(sccm_ops, "_http_get", _http_err)
    naa_err = sccm_ops.SccmNaa().run(_target(), session, graph)
    assert naa_err["http_hits"]

    class _Relay:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"return_code": 0}

    monkeypatch.setattr(sccm_ops, "NtlmRelay", _Relay)
    take = sccm_ops.SccmTakeover().run(_target(), session, graph, force=True, site_db="sql01")
    assert take["ok"] is True
    push = sccm_ops.SccmClientPush().run(_target(), session, graph, force=True, host="ws01")
    assert push["ok"] is False and push["requested"] is False
    assert (session.path("sccm-client-push.playbook.txt")).exists()

    _patch_ldap(monkeypatch, relay_ops, conn)
    with pytest.raises(RuntimeError, match="relay_targets"):
        relay_ops.KrbRelay().run(_target(), session, graph, force=True)
    monkeypatch.setattr(relay_ops.shutil, "which", lambda *_a, **_k: None)
    with pytest.raises(RuntimeError, match="krbrelayx"):
        relay_ops.KrbRelay().run(_target(), session, graph, force=True, relay_targets="ldap://dc")
    monkeypatch.setattr(relay_ops.shutil, "which", lambda *_a, **_k: "/bin/krbrelayx")

    class _Proc:
        def __init__(self) -> None:
            self.returncode = None

        def wait(self, timeout: int | None = None) -> int:
            raise relay_ops.subprocess.TimeoutExpired(cmd="x", timeout=1)

        def terminate(self) -> None:
            return None

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(relay_ops.subprocess, "Popen", lambda *a, **k: _Proc())
    krb = relay_ops.KrbRelay().run(
        _target(),
        session,
        graph,
        force=True,
        relay_targets="ldap://dc,http://ca",
        duration_seconds=1,
    )
    assert krb["truncated"] is True

    class _ProcOk(_Proc):
        def wait(self, timeout: int | None = None) -> int:
            self.returncode = 0
            return 0

    monkeypatch.setattr(relay_ops.subprocess, "Popen", lambda *a, **k: _ProcOk())
    krb_ok = relay_ops.KrbRelay().run(
        _target(), session, graph, force=True, relay_targets=["ldap://dc"]
    )
    assert krb_ok["ok"] is True

    dc = _sid_entry("ROGUE$", "CN=ROGUE,DC=corp,DC=test")
    dc._values["dNSHostName"] = _Attr("rogue.corp.test")
    conn.by_filter["ROGUE"] = [dc]
    shadow = relay_ops.DcShadow().run(_target(), session, graph, force=True, computer="ROGUE$")
    assert shadow["ok"] is True
    assert shadow["replication_push"]["performed"] is False
    assert (session.path("dcshadow-push.playbook.txt")).exists()
    conn.by_filter["ROGUE"] = []
    with pytest.raises(RuntimeError, match="not found"):
        relay_ops.DcShadow().run(_target(), session, graph, force=True, computer="ROGUE$")


def test_joined_workflows(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(tmp_path)
    graph = AttackGraph()

    class _Write:
        def __init__(self, ok: bool = True) -> None:
            self.ok = ok
            self.calls = 0

        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            self.calls += 1
            if kwargs.get("clear") or kwargs.get("spns"):
                return {"ok": True, "previous": ["HOST/old"]}
            return {"ok": self.ok, "previous": ["HOST/old"]}

    class _Roast:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"tickets": []}

    monkeypatch.setattr(joined_workflows, "WriteSpn", lambda: _Write(False))
    fail = joined_workflows.TargetedKerberoast().run(
        _target(), session, graph, force=True, sam="bob"
    )
    assert fail["ok"] is False
    monkeypatch.setattr(joined_workflows, "WriteSpn", lambda: _Write(True))
    monkeypatch.setattr(joined_workflows, "Kerberoast", _Roast)
    ok = joined_workflows.TargetedKerberoast().run(_target(), session, graph, force=True, sam="bob")
    assert ok["ok"] is True

    user = _sid_entry("alice", "CN=Alice,DC=corp,DC=test")
    conn = _Conn({"alice": [user], "*": [user]})
    _patch_ldap(monkeypatch, joined_workflows, conn)
    monkeypatch.setattr(
        joined_workflows, "fetch_sd", lambda *_a, **_k: build_allowed_to_act_sd("S-1-5-21-1-2-3-9")
    )

    class _Dcsync:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

    monkeypatch.setattr(joined_workflows, "Dcsync", _Dcsync)
    grant = joined_workflows.DcsyncGrantWorkflow().run(_target(), session, graph, force=True)
    assert grant["ok"] is True
    grant_sid = joined_workflows.DcsyncGrantWorkflow().run(
        _target(), session, graph, force=True, principal_sid="S-1-5-21-1-2-3-4"
    )
    assert grant_sid["ok"] is True
    with pytest.raises(RuntimeError, match="principal_sid"):
        joined_workflows.DcsyncGrantWorkflow().run(
            _target(username=None), session, graph, force=True
        )
    conn.by_filter = {}
    with pytest.raises(RuntimeError, match="Unable to resolve"):
        joined_workflows.DcsyncGrantWorkflow().run(_target(), session, graph, force=True)
    conn.by_filter = {
        "alice": [_Entry(sAMAccountName="alice", distinguishedName="CN=A", objectSid=None)]
    }
    with pytest.raises(RuntimeError, match="parse"):
        joined_workflows.DcsyncGrantWorkflow().run(_target(), session, graph, force=True)

    class _Maq:
        def __init__(self, ok: bool = True) -> None:
            self._ok = ok

        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": self._ok, "sam": "NEW$", "dn": "CN=NEW,DC=corp,DC=test"}

    monkeypatch.setattr(joined_workflows, "MaqAddComputer", lambda: _Maq(False))
    nopac_fail = joined_workflows.NopacWorkflow().run(
        _target(), session, graph, force=True, dc="DC01$"
    )
    assert nopac_fail["ok"] is False
    monkeypatch.setattr(joined_workflows, "MaqAddComputer", lambda: _Maq(True))
    conn.by_filter = {
        "NEW$": [_sid_entry("NEW$", "CN=NEW,DC=corp,DC=test")],
        "DC01": [_sid_entry("DC01$", "CN=DC01,DC=corp,DC=test")],
        "DC01$": [_sid_entry("DC01$", "CN=DC01,DC=corp,DC=test")],
    }
    _patch_ldap(monkeypatch, joined_workflows, conn)
    nopac = joined_workflows.NopacWorkflow().run(_target(), session, graph, force=True, dc="DC01$")
    assert nopac["rename"]["ok"] is True
    conn.by_filter = {"NEW$": [], "DC01$": []}
    with pytest.raises(RuntimeError, match="lookup failed"):
        joined_workflows.NopacWorkflow().run(_target(), session, graph, force=True, dc="DC01$")

    class _Hunt:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "count": 1,
                "principals": [{"unconstrained": True, "dns": "dc01.corp.test", "sam": "DC01$"}],
            }

    class _Coerce:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

    monkeypatch.setattr(joined_workflows, "UnconstrainedDelegation", _Hunt)
    monkeypatch.setattr(joined_workflows, "Coerce", _Coerce)
    dump = joined_workflows.UnconstTgtDumpWorkflow().run(_target(), session, graph, force=True)
    assert dump["ok"] is True

    class _HuntEmpty:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"count": 0, "principals": []}

    monkeypatch.setattr(joined_workflows, "UnconstrainedDelegation", _HuntEmpty)
    empty = joined_workflows.UnconstTgtDumpWorkflow().run(_target(), session, graph, force=True)
    assert empty["coerce"]["skipped"]


def test_http_get_and_udp(monkeypatch: Any) -> None:
    class _Resp:
        status_code = 200
        text = "hello"

    monkeypatch.setattr(sccm_ops.httpx, "get", lambda *a, **k: _Resp())
    status, body = sccm_ops._http_get("http://x")
    assert status == 200 and body == "hello"

    class _Sock:
        def settimeout(self, t: float) -> None:
            return None

        def sendto(self, payload: bytes, addr: Any) -> None:
            self.payload = payload

        def recvfrom(self, n: int) -> tuple[bytes, Any]:
            return (b"\x00" * 68, ("10.0.0.1", 123))

        def close(self) -> None:
            return None

    monkeypatch.setattr(credential_ops.socket, "socket", lambda *a, **k: _Sock())
    data = credential_ops._udp_query("10.0.0.1", b"x")
    assert len(data) == 68
