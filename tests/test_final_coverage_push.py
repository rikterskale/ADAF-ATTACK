"""Final coverage push: gpo_abuse, esc6 branches, runner/engagement/forest edges,
shadow_creds finalization, cert_request, acl_enum branches, ldap_enum, rbcd
final branches, adcs_enum branches, and misc single-line coverage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import adaf_attack.capabilities.gpo_abuse as gpo_abuse
import adaf_attack.core.esc6_probe as esc6
import pytest
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

# --------------------------- gpo_abuse ---------------------------


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def __bool__(self) -> bool:
        return self.value is not None

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **v: Any) -> None:
        self._v = {k: _Attr(val) for k, val in v.items()}

    def __getattr__(self, name: str) -> _Attr:
        return self._v.get(name, self._v.get(name.replace("-", "_"), _Attr()))

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _Conn:
    def __init__(self, gpo_entries: list[_Entry], link_entries: list[_Entry]) -> None:
        self._gpo = gpo_entries
        self._links = link_entries
        self.entries: list[_Entry] = []
        self.unbound = False

    def search(self, base_dn: str, filt: str, **kwargs: Any) -> None:
        if "groupPolicyContainer" in filt:
            self.entries = self._gpo
        elif "organizationalUnit" in filt:
            self.entries = self._links
        else:
            self.entries = []

    def unbind(self) -> None:
        self.unbound = True


def test_gpo_abuse_writable_and_links(monkeypatch: Any, tmp_path: Path) -> None:
    gpo = _Entry(
        cn="{GPO-1}",
        displayName="Baseline",
        distinguishedName="CN={GPO-1},DC=corp,DC=test",
        gPCFileSysPath=r"\\corp.test\SYSVOL\corp.test\Policies\{GPO-1}",
        flags=0,
        versionNumber=12,
    )
    empty_gpo = _Entry(cn=None)  # skipped
    link = _Entry(
        distinguishedName="OU=Servers,DC=corp,DC=test",
        gPLink="[LDAP://CN={GPO-1},CN=Policies,CN=System,DC=corp,DC=test;0]",
        name="Servers",
    )
    no_link = _Entry(distinguishedName="OU=Empty,DC=corp,DC=test", gPLink=None)
    conn = _Conn([gpo, empty_gpo], [link, no_link])
    monkeypatch.setattr(gpo_abuse, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_abuse, "fetch_sd", lambda c, dn: b"sd")
    monkeypatch.setattr(
        gpo_abuse,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-100", "WriteDacl")],
    )
    session = Session(base_dir=tmp_path / "s")
    graph = AttackGraph()
    result = gpo_abuse.GpoAbuse().run(Target(domain="corp.test", dc_ip="10.0.0.1"), session, graph)
    assert result["gpos"][0]["writers"][0]["right"] == "WriteDacl"
    assert result["writable_gpos"]
    assert result["links"][0]["container"] == "OU=Servers,DC=corp,DC=test"
    assert any(edge.kind == "GPLink" for edge in graph.edges)


def test_gpo_abuse_link_search_error(monkeypatch: Any, tmp_path: Path) -> None:
    gpo = _Entry(
        cn="{G}",
        displayName="G",
        distinguishedName="CN={G},DC=corp,DC=test",
        gPCFileSysPath=None,
        flags=None,
        versionNumber=None,
    )
    calls = {"n": 0}

    class _C:
        entries: list[Any] = []
        unbound = False

        def search(self, *a: Any, **k: Any) -> None:
            calls["n"] += 1
            if calls["n"] == 1:
                self.entries = [gpo]
            else:
                raise RuntimeError("link search failed")

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(gpo_abuse, "ldap_connect", lambda t: (_C(), "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_abuse, "fetch_sd", lambda c, dn: None)
    result = gpo_abuse.GpoAbuse().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path / "s2"),
        AttackGraph(),
    )
    assert result["links"] == []


def test_gpo_abuse_ace_parse_swallows(monkeypatch: Any, tmp_path: Path) -> None:
    gpo = _Entry(
        cn="{G}",
        displayName="G",
        distinguishedName="CN={G},DC=corp,DC=test",
        gPCFileSysPath=None,
        flags=None,
        versionNumber=None,
    )
    conn = _Conn([gpo], [])
    monkeypatch.setattr(gpo_abuse, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_abuse, "fetch_sd", lambda c, dn: b"sd")

    def boom(sd: Any) -> Any:
        raise ValueError("parse fail")

    monkeypatch.setattr(gpo_abuse, "parse_interesting_aces", boom)
    result = gpo_abuse.GpoAbuse().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path / "s3"),
        AttackGraph(),
    )
    # parse failure swallowed; no writers
    assert result["gpos"][0]["writers"] == []


# --------------------------- esc6 remaining ---------------------------


def test_esc6_parse_edit_flags_no_match() -> None:
    assert esc6._parse_editflags("blank") is None


def test_esc6_probe_certutil_missing_binary(monkeypatch: Any) -> None:
    monkeypatch.setattr(esc6.shutil, "which", lambda n: None)
    r = esc6.probe_certutil()
    assert r["available"] is False


def test_esc6_probe_rrp_open_key_failure(monkeypatch: Any) -> None:
    import sys
    import types

    class _SMB:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        def login(self, *a: Any, **k: Any) -> None:
            pass

    class _DCE:
        def connect(self) -> None:
            pass

        def bind(self, _u: Any) -> None:
            pass

        def disconnect(self) -> None:
            pass

    class _T:
        def set_smb_connection(self, _s: Any) -> None:
            pass

        def get_dce_rpc(self) -> _DCE:
            return _DCE()

    rrp = types.ModuleType("impacket.dcerpc.v5.rrp")
    rrp.MSRPC_UUID_RRP = object()
    rrp.hOpenLocalMachine = lambda dce: {"phKey": "r"}

    def _open(*a: Any, **k: Any) -> Any:
        raise RuntimeError("access denied")

    rrp.hBaseRegOpenKey = _open
    transport = types.ModuleType("impacket.dcerpc.v5.transport")
    transport.DCERPCTransportFactory = lambda b: _T()
    smb_mod = types.ModuleType("impacket.smbconnection")
    smb_mod.SMBConnection = _SMB
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rrp", rrp)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.transport", transport)
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", smb_mod)

    r = esc6.probe_impacket_rrp(Target(domain="c", dc_ip="1.1.1.1", username="a", password="p"))
    assert r["ok"] is False
    assert "Open CertSvc" in r.get("error", "") or "note" in r


def test_esc6_probe_rrp_ca_key_read_failure(monkeypatch: Any) -> None:
    import sys
    import types

    class _SMB:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        def login(self, *a: Any, **k: Any) -> None:
            pass

    class _DCE:
        def connect(self) -> None:
            pass

        def bind(self, u: Any) -> None:
            pass

        def disconnect(self) -> None:
            pass

    class _T:
        def set_smb_connection(self, s: Any) -> None:
            pass

        def get_dce_rpc(self) -> _DCE:
            return _DCE()

    rrp = types.ModuleType("impacket.dcerpc.v5.rrp")
    rrp.MSRPC_UUID_RRP = object()
    rrp.hOpenLocalMachine = lambda dce: {"phKey": "r"}
    call_counter = {"n": 0}

    def _open(dce: Any, handle: Any, path: str) -> Any:
        call_counter["n"] += 1
        if call_counter["n"] == 1:  # first call for CertSvc Configuration - ok
            return {"phkResult": "cfg"}
        raise RuntimeError("policy path missing")

    rrp.hBaseRegOpenKey = _open

    def _enum(dce: Any, h: Any, i: int) -> Any:
        if i == 0:
            return {"lpNameOut": "CA1"}
        raise RuntimeError("no more")

    rrp.hBaseRegEnumKey = _enum
    rrp.hBaseRegQueryValue = lambda dce, h, name: (None, b"\x00" * 4)

    transport = types.ModuleType("impacket.dcerpc.v5.transport")
    transport.DCERPCTransportFactory = lambda b: _T()
    smb_mod = types.ModuleType("impacket.smbconnection")
    smb_mod.SMBConnection = _SMB
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rrp", rrp)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.transport", transport)
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", smb_mod)

    r = esc6.probe_impacket_rrp(Target(domain="c", dc_ip="1.1.1.1", username="a", password="p"))
    # ca_names enumerated, but policy open fails → per-CA error, still ok=True
    assert r["ok"] is True
    assert r["cas"][0].get("error") == "policy path missing"


def test_esc6_probe_rrp_query_returns_int_and_str(monkeypatch: Any) -> None:
    import sys
    import types

    class _SMB:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        def login(self, *a: Any, **k: Any) -> None:
            pass

    class _DCE:
        def connect(self) -> None:
            pass

        def bind(self, u: Any) -> None:
            pass

        def disconnect(self) -> None:
            pass

    class _T:
        def set_smb_connection(self, s: Any) -> None:
            pass

        def get_dce_rpc(self) -> _DCE:
            return _DCE()

    rrp = types.ModuleType("impacket.dcerpc.v5.rrp")
    rrp.MSRPC_UUID_RRP = object()
    rrp.hOpenLocalMachine = lambda dce: {"phKey": "r"}
    rrp.hBaseRegOpenKey = lambda dce, h, path: {"phkResult": path}

    def _enum(dce: Any, h: Any, i: int) -> Any:
        if i < 2:
            return {"lpNameOut": f"CA{i}"}
        raise RuntimeError("done")

    rrp.hBaseRegEnumKey = _enum
    # First: int flag; second: bare string (falls into int(data) branch → treats as string coerce fail)
    responses = [(None, 0x40000), (None, "262144")]

    def _query(dce: Any, h: Any, name: str) -> Any:
        return responses.pop(0)

    rrp.hBaseRegQueryValue = _query

    transport = types.ModuleType("impacket.dcerpc.v5.transport")
    transport.DCERPCTransportFactory = lambda b: _T()
    smb_mod = types.ModuleType("impacket.smbconnection")
    smb_mod.SMBConnection = _SMB
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rrp", rrp)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.transport", transport)
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", smb_mod)

    r = esc6.probe_impacket_rrp(Target(domain="c", dc_ip="1.1.1.1", username="a", password="p"))
    assert r["ok"] is True
    kinds = [c.get("edit_flags") for c in r["cas"] if "edit_flags" in c]
    assert 0x40000 in kinds
    assert 262144 in kinds


def test_esc6_probe_rrp_outer_exception(monkeypatch: Any) -> None:
    import sys
    import types

    class _SMB:
        def __init__(self, *a: Any, **k: Any) -> None:
            raise RuntimeError("SMB connect failed")

    transport = types.ModuleType("impacket.dcerpc.v5.transport")
    transport.DCERPCTransportFactory = lambda b: None
    rrp = types.ModuleType("impacket.dcerpc.v5.rrp")
    rrp.MSRPC_UUID_RRP = object()
    smb_mod = types.ModuleType("impacket.smbconnection")
    smb_mod.SMBConnection = _SMB
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rrp", rrp)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.transport", transport)
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", smb_mod)

    r = esc6.probe_impacket_rrp(Target(domain="c", dc_ip="1.1.1.1", username="a", password="p"))
    assert r["ok"] is False
    assert "SMB connect failed" in r["error"]


# --------------------------- runner + engagement small branches ---------------------------


def test_runner_execute_log_lambda(monkeypatch: Any, tmp_path: Path) -> None:
    """Cover the log lambda path in _resolve_target when creds_file loads."""
    import adaf_attack.core.runner as runner_mod

    creds = tmp_path / "c.json"
    creds.write_text(json.dumps([{"username": "a", "password": "p"}]), encoding="utf-8")
    monkeypatch.setattr(runner_mod, "_probe_ldap", lambda t: True)
    logs: list[str] = []
    chosen, _ = runner_mod._resolve_target(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        creds_file=creds,
        log=logs.append,
    )
    assert logs and any("Loaded 1 credential" in line for line in logs)


def test_engagement_load_plan_opsec_resolves(tmp_path: Path) -> None:
    from adaf_attack.core.engagement import load_plan

    plan = tmp_path / "e.yaml"
    plan.write_text(
        json.dumps(
            {
                "engagement_id": "E1",
                "target": {"domain": "corp.test", "dc_ip": "10.0.0.1"},
                "allowed_capabilities": ["ldap-enum"],
                "phases": [],
                "opsec_profile": "stealth",
            }
        ),
        encoding="utf-8",
    )
    p = load_plan(plan)
    assert p.opsec_profile == "stealth"


# --------------------------- shadow_creds attribute variants ---------------------------


def test_shadow_creds_list_attr_variants() -> None:
    import adaf_attack.capabilities.shadow_creds as sc

    class _A:
        def __init__(self, value: Any) -> None:
            self.value = value

    class _E:
        pass

    # No attribute
    assert sc._list_attr(_E(), "missing") == []
    # value is None
    e2 = _E()
    e2.k = _A(None)
    assert sc._list_attr(e2, "k") == []
    # list
    e3 = _E()
    e3.k = _A([1, 2])
    assert sc._list_attr(e3, "k") == [1, 2]
    # scalar
    e4 = _E()
    e4.k = _A("scalar")
    assert sc._list_attr(e4, "k") == ["scalar"]


# --------------------------- pkinit_auth exception path ---------------------------


def test_pkinit_auth_playbook_write_exception(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.capabilities.pkinit_auth as pkinit

    session = Session(base_dir=tmp_path / "p")
    # Set up existing pfx
    pfx = session.path("shadow-alice.pfx")
    pfx.write_bytes(b"pfx")

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(returncode=1, stdout="", stderr="err")

    monkeypatch.setattr(pkinit.subprocess, "run", fake_run)

    # Make session.path raise inside the try/except by monkey-patching path writes
    real_write = Path.write_text

    def flaky_write(self: Path, *a: Any, **k: Any) -> Any:
        if self.name == "pkinit.playbook.txt":
            raise OSError("disk full")
        return real_write(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", flaky_write)
    result = pkinit.PkinitAuth().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        force=True,
        sam="alice",
        pfx=str(pfx),
    )
    assert result["ok"] is False


# --------------------------- ticket_lifecycle vault-secret paths ---------------------------


def test_ticket_lifecycle_export_missing_source(monkeypatch: Any, tmp_path: Path) -> None:
    from adaf_attack.capabilities.ticket_lifecycle import TicketLifecycle
    from cryptography.fernet import Fernet

    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())
    session = Session(base_dir=tmp_path / "t")
    # put a vault entry pointing to a non-existing file
    session.vault().put("tgt", "ccache", {"path": "/no/such/file"}, secret=True)
    session.vault().put("certificate", "pfx", {"path": "/no/such/file"}, secret=True)
    with pytest.raises(RuntimeError, match="does not reference an available ccache"):
        TicketLifecycle().run(
            Target(domain="c", dc_ip="1.1.1.1"),
            session,
            AttackGraph(),
            operation="export-ccache",
        )
    with pytest.raises(RuntimeError, match="does not reference an available PFX"):
        TicketLifecycle().run(
            Target(domain="c", dc_ip="1.1.1.1"),
            session,
            AttackGraph(),
            operation="export-pfx",
        )


def test_ticket_lifecycle_pfx_to_pem_incomplete(monkeypatch: Any, tmp_path: Path) -> None:
    from adaf_attack.capabilities.ticket_lifecycle import TicketLifecycle

    pfx = tmp_path / "bad.pfx"
    pfx.write_bytes(b"not-a-real-pfx")
    session = Session(base_dir=tmp_path / "t2")

    # Force pkcs12 to return incomplete key/cert
    from cryptography.hazmat.primitives.serialization import pkcs12

    monkeypatch.setattr(pkcs12, "load_key_and_certificates", lambda data, pw: (None, None, []))
    with pytest.raises(RuntimeError, match="private key and certificate"):
        TicketLifecycle().run(
            Target(domain="c", dc_ip="1.1.1.1"),
            session,
            AttackGraph(),
            operation="pfx-to-pem",
            artifact=str(pfx),
        )


# --------------------------- forest_campaign handoff success ---------------------------


def test_forest_campaign_handoff_success(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.core.forest_campaign as fc
    from cryptography.fernet import Fernet

    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())
    session_dir = tmp_path / "prev"
    session_dir.mkdir()
    (session_dir / "session.json").write_text("{}", encoding="utf-8")
    from adaf_attack.core.vault import SessionVault

    ccache_file = session_dir / "tgt.ccache"
    ccache_file.write_bytes(b"tk")
    SessionVault(session_dir).put("tgt", "ccache", {"path": str(ccache_file)}, secret=True)

    manifest = tmp_path / "campaign.yaml"
    manifest.write_text("dummy", encoding="utf-8")
    ccache, info = fc._handoff_ccache(
        {"credential_handoff": {"allow": True, "from_session": "prev", "item": "tgt"}},
        manifest,
    )
    assert ccache == str(ccache_file)
    assert info["kind"] == "ccache"


def test_forest_campaign_handoff_missing_ccache(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.core.forest_campaign as fc
    from cryptography.fernet import Fernet

    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())
    session_dir = tmp_path / "prev2"
    session_dir.mkdir()
    from adaf_attack.core.vault import SessionVault

    SessionVault(session_dir).put("tgt", "ccache", {"path": "/nonexistent"}, secret=True)
    manifest = tmp_path / "m2.yaml"
    manifest.write_text("dummy", encoding="utf-8")
    with pytest.raises(fc.CampaignError, match="does not reference"):
        fc._handoff_ccache(
            {"credential_handoff": {"allow": True, "from_session": "prev2", "item": "tgt"}},
            manifest,
        )


def test_forest_campaign_handoff_vault_error(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.core.forest_campaign as fc

    session_dir = tmp_path / "prev3"
    session_dir.mkdir()
    manifest = tmp_path / "m3.yaml"
    manifest.write_text("dummy", encoding="utf-8")
    # No vault, no key set → VaultError bubbling
    monkeypatch.delenv("ADAF_SESSION_VAULT_KEY", raising=False)
    with pytest.raises(fc.CampaignError, match="Unable to load credential"):
        fc._handoff_ccache(
            {"credential_handoff": {"allow": True, "from_session": "prev3", "item": "tgt"}},
            manifest,
        )


# --------------------------- ldap_enum + acl_enum + rbcd remaining ---------------------------


def test_ldap_enum_skips_missing_attrs(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.capabilities.ldap_enum as le

    class _Attr2:
        def __init__(self, value: Any = None) -> None:
            self.value = value

        def __bool__(self) -> bool:
            return self.value is not None

        def __iter__(self) -> Any:
            return iter(self.value if isinstance(self.value, list) else [])

        def __str__(self) -> str:
            return str(self.value)

    class _E:
        def __init__(self, **kwargs: Any) -> None:
            self._v = {k: _Attr2(val) for k, val in kwargs.items()}

        def __getattr__(self, name: str) -> _Attr2:
            return self._v.get(name, self._v.get(name.replace("-", "_"), _Attr2()))

        def __getitem__(self, name: str) -> _Attr2:
            return self.__getattr__(name)

    # Entries with missing sAMAccountName → skipped
    skip_user = _E(sAMAccountName=None, distinguishedName="CN=X,DC=corp,DC=test")
    ok_user = _E(
        sAMAccountName="alice",
        distinguishedName="CN=Alice,DC=corp,DC=test",
        userAccountControl=0,
    )
    computer_skip = _E(sAMAccountName=None, distinguishedName="CN=X,DC=corp,DC=test")
    group_skip = _E(sAMAccountName=None, distinguishedName="CN=X,DC=corp,DC=test")
    gpo_skip = _E(cn=None)

    class _C:
        def __init__(self) -> None:
            self.entries: list[_E] = []
            self.unbound = False

        def search(self, base_dn: str, filt: str, **kwargs: Any) -> None:
            if filt == le.USER_FILTER:
                self.entries = [skip_user, ok_user]
            elif filt == le.COMPUTER_FILTER:
                self.entries = [computer_skip]
            elif filt == le.GROUP_FILTER:
                self.entries = [group_skip]
            elif filt == le.TRUST_FILTER:
                self.entries = []
            elif filt == le.GPO_FILTER:
                self.entries = [gpo_skip]
            else:
                self.entries = []

        def unbind(self) -> None:
            self.unbound = True

    conn = _C()
    monkeypatch.setattr(le, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    result = le.LdapEnum().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path / "le"),
        AttackGraph(),
    )
    assert len(result["users"]) == 1
    assert result["computers"] == []
