"""Final final coverage push: gpo_sysvol write branches, acl_enum sid map hits,
gmsa/laps string branches, rbcd _parse_security_descriptor_sids branches,
adcs_enum remaining, shadow_creds attribute path."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import adaf_attack.capabilities.acl_enum as acl_enum
import adaf_attack.capabilities.gmsa_laps_enum as gmsa
import adaf_attack.capabilities.gpo_sysvol as gpo_sysvol
import adaf_attack.capabilities.rbcd as rbcd_cap
import adaf_attack.capabilities.shadow_creds as shadow
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

# --------------------------- rbcd _parse_security_descriptor_sids ---------------------------


def test_parse_security_descriptor_sids_variants() -> None:
    assert rbcd_cap._parse_security_descriptor_sids(None) == []
    # bytes → decode + regex
    assert rbcd_cap._parse_security_descriptor_sids(b"S-1-5-21-1-2-3") == ["S-1-5-21-1-2-3"]
    # string
    assert rbcd_cap._parse_security_descriptor_sids("S-1-5-21-1 S-1-5-21-2") == [
        "S-1-5-21-1",
        "S-1-5-21-2",
    ]
    # dedupe
    assert rbcd_cap._parse_security_descriptor_sids("S-1-5-21-1 S-1-5-21-1") == ["S-1-5-21-1"]


# --------------------------- rbcd remaining branches ---------------------------


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


class _RbcdConn:
    def __init__(self, configured: list[_Entry], writable: list[_Entry]) -> None:
        self._configured = configured
        self._writable = writable
        self.entries: list[_Entry] = []
        self.unbound = False

    def search(self, base_dn: str, filt: str, **kwargs: Any) -> None:
        if "AllowedToActOnBehalfOfOtherIdentity=*" in filt:
            self.entries = self._configured
        else:
            self.entries = self._writable

    def unbind(self) -> None:
        self.unbound = True


def test_rbcd_skips_computers_without_sam(monkeypatch: Any, tmp_path: Path) -> None:
    """Cover: configured entry without SAM, writable entry without SAM, writable without SD."""
    configured_no_sam = _Entry(sAMAccountName=None)
    writable_no_sam = _Entry(sAMAccountName=None, distinguishedName="CN=X,DC=corp,DC=test")
    writable_no_sd = _Entry(
        sAMAccountName="WEB01$",
        distinguishedName="CN=WEB01,DC=corp,DC=test",
    )
    conn = _RbcdConn([configured_no_sam], [writable_no_sam, writable_no_sd])
    monkeypatch.setattr(rbcd_cap, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(rbcd_cap, "fetch_sd", lambda c, dn: None)  # no SD
    result = rbcd_cap.Rbcd().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path / "r"),
        AttackGraph(),
    )
    assert result["rbcd_configured"] == []
    assert result["writable_computers"] == []


# --------------------------- acl_enum sid_map + kind_specific branches ---------------------------


def test_acl_enum_writes_group_computer_user_node_ids(monkeypatch: Any, tmp_path: Path) -> None:
    conn = SimpleNamespace(unbind=lambda: setattr(conn, "unbound", True))
    monkeypatch.setattr(acl_enum, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(
        acl_enum,
        "_sid_index",
        lambda c, base_dn: {
            "S-1-5-21-100": {"sam": "GroupA", "kind": "Group", "dn": "CN=GroupA,DC=corp"},
            "S-1-5-21-200": {"sam": "DC01$", "kind": "Computer", "dn": "CN=DC01,DC=corp"},
            "S-1-5-21-300": {"sam": "alice", "kind": "User", "dn": "CN=Alice,DC=corp"},
        },
    )
    monkeypatch.setattr(
        acl_enum,
        "_high_value_targets",
        lambda c, dn, dom: [("GROUP@DA@CORP.TEST", "CN=DA,DC=corp,DC=test", "Group")],
    )
    monkeypatch.setattr(acl_enum, "fetch_sd", lambda c, dn: b"sd")
    # Include ACEs mapping to each kind + one unknown SID
    monkeypatch.setattr(
        acl_enum,
        "parse_interesting_aces",
        lambda sd: [
            InterestingAce("S-1-5-21-100", "WriteDacl"),  # Group src
            InterestingAce("S-1-5-21-200", "WriteDacl"),  # Computer src
            InterestingAce("S-1-5-21-300", "WriteDacl"),  # User src
            InterestingAce("S-1-5-99-999", "WriteDacl"),  # Unknown SID
        ],
    )
    session = Session(base_dir=tmp_path / "acl")
    graph = AttackGraph()
    result = acl_enum.AclEnum().run(Target(domain="corp.test", dc_ip="10.0.0.1"), session, graph)
    # Ensure all kinds got mapped
    srcs = {e["source_id"] for e in result["edges"]}
    assert any(s.startswith("GROUP@") for s in srcs)
    assert any(s.startswith("COMPUTER@") for s in srcs)
    assert any(s.startswith("USER@") for s in srcs)
    assert any(s.startswith("SID@") for s in srcs)


def test_acl_enum_domain_scope_and_many_interesting(monkeypatch: Any, tmp_path: Path) -> None:
    """Cover: scope==domain branch and >15 interesting-edge trailer."""
    conn = SimpleNamespace(unbind=lambda: None)
    monkeypatch.setattr(acl_enum, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(acl_enum, "_sid_index", lambda c, base_dn: {})
    # Return 20 targets so ACEs > 15 to hit the "…more" branch
    monkeypatch.setattr(
        acl_enum,
        "_domain_targets",
        lambda c, dn, dom, limit: [
            (f"USER@N{i}@CORP.TEST", f"CN=N{i},DC=corp,DC=test", "User") for i in range(20)
        ],
    )
    monkeypatch.setattr(acl_enum, "fetch_sd", lambda c, dn: b"sd")
    monkeypatch.setattr(
        acl_enum,
        "parse_interesting_aces",
        lambda sd: [InterestingAce(f"S-1-5-21-{i}", "GenericAll") for i in range(1)],
    )
    session = Session(base_dir=tmp_path / "acldom")
    result = acl_enum.AclEnum().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        scope="domain",
        max_objects=50,
    )
    # 20 * 1 = 20 interesting edges → more-than-15 branch hits
    assert result["interesting_edge_count"] == 20


# --------------------------- gmsa/laps small branches ---------------------------


class _GmsaConn2:
    def __init__(self, gmsa_entries: list[_Entry], laps_entries: list[_Entry]) -> None:
        self._g = gmsa_entries
        self._l = laps_entries
        self.entries: list[_Entry] = []
        self.unbound = False

    def search(self, base_dn: str, filt: str, **kwargs: Any) -> None:
        if filt == gmsa.GMSA_FILTER:
            self.entries = self._g
        else:
            self.entries = self._l

    def unbind(self) -> None:
        self.unbound = True


def test_gmsa_laps_skip_no_sam_and_str_managed_password(monkeypatch: Any, tmp_path: Path) -> None:
    """gMSA with str-typed msDS-ManagedPassword; LAPS entry without SAM (skipped)."""
    # gMSA: no SAM → skipped
    no_sam_g = _Entry(sAMAccountName=None)
    # gMSA with str mp → hits raw = str().encode() branch
    ok_g = _Entry(
        sAMAccountName="svc$",
        distinguishedName="CN=svc,DC=corp",
        msDS_ManagedPasswordInterval=30,
        msDS_ManagedPassword="opaque-string-value",  # str, not bytes
    )
    # LAPS: no SAM → skipped
    no_sam_l = _Entry(sAMAccountName=None)
    conn = _GmsaConn2([no_sam_g, ok_g], [no_sam_l])
    monkeypatch.setattr(gmsa, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gmsa, "fetch_sd", lambda c, dn: None)
    result = gmsa.GmsaLapsEnum().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path / "gmsa"),
        AttackGraph(),
        include_secrets=True,
    )
    assert result["gmsa_count"] == 1
    assert result["laps_computer_count"] == 0


# --------------------------- shadow_creds _list_attr branches ---------------------------


def test_shadow_creds_list_attr_no_value_attr() -> None:
    """Hit line 80: raw without .value attribute (already bare)."""
    from adaf_attack.capabilities.shadow_creds import _list_attr as sc_list_attr

    # Instead of _Attr, pass a value directly
    class _E:
        k = [b"raw"]

    assert sc_list_attr(_E(), "k") == [b"raw"]


def test_shadow_creds_write_target_without_matching_class(monkeypatch: Any, tmp_path: Path) -> None:
    """Cover line 112 (kind computation for user class default)."""

    class _E:
        def __init__(self, sam: str, oc_values: list[str]) -> None:
            self.sAMAccountName = _Attr(sam)
            self.distinguishedName = _Attr(f"CN={sam},DC=corp,DC=test")
            self.objectClass = SimpleNamespace(values=oc_values)
            self._kc = SimpleNamespace(values=[b"kc-data"])

        def __getitem__(self, name: str) -> Any:
            if name == "msDS-KeyCredentialLink":
                return _Attr([b"kc"])
            return _Attr()

        def __getattr__(self, name: str) -> Any:
            # objectClass returns SimpleNamespace
            return _Attr()

    class _C:
        entries: list[Any] = []
        unbound = False

        def search(self, base_dn: str, filt: str, **kwargs: Any) -> None:
            if "KeyCredentialLink=*" in filt:
                # User (no "computer" class → falls into User kind)
                self.entries = [_E("bob", ["top", "person"])]
            else:
                self.entries = []

        def unbind(self) -> None:
            self.unbound = True

    conn = _C()
    monkeypatch.setattr(shadow, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(shadow, "fetch_sd", lambda c, dn: None)
    result = shadow.ShadowCreds().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path / "shadow"),
        AttackGraph(),
    )
    # Should have processed the User-kind account
    assert any(a["kind"] == "User" for a in result["accounts_with_keycred"])


# --------------------------- gpo_sysvol SMB write branch (force + matching gpo) ---------------------------


class _WriteSmb:
    def __init__(self, *, write_ok: bool = True) -> None:
        self.write_ok = write_ok
        self.calls: list[str] = []

    def connectTree(self, share: str) -> int:  # noqa: N802
        return 7

    def listPath(self, share: str, path: str) -> list[Any]:  # noqa: N802
        return []

    def createFile(self, tid: int, path: str) -> int:  # noqa: N802
        self.calls.append(f"create:{path}")
        if not self.write_ok:
            raise RuntimeError("write denied")
        return 8

    def writeFile(self, tid: int, fid: int, data: bytes) -> None:  # noqa: N802
        self.calls.append("write")

    def closeFile(self, tid: int, fid: int) -> None:  # noqa: N802
        pass

    def deleteFile(self, share: str, path: str) -> None:  # noqa: N802
        self.calls.append(f"delete:{path}")

    def disconnectTree(self, tid: int) -> None:  # noqa: N802
        pass

    def logoff(self) -> None:
        pass


def test_gpo_sysvol_write_probe_succeeds(monkeypatch: Any, tmp_path: Path) -> None:
    class _Conn:
        entries: list[Any] = []
        unbound = False

        def search(self, *a: Any, **k: Any) -> None:
            self.entries = [
                SimpleNamespace(
                    cn="{GPO-1}",
                    displayName="Baseline",
                    gPCFileSysPath="\\\\corp.test\\SYSVOL\\corp.test\\Policies\\{GPO-1}",
                    distinguishedName="CN={GPO-1},DC=corp,DC=test",
                )
            ]

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(gpo_sysvol, "ldap_connect", lambda t: (_Conn(), "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_sysvol, "fetch_sd", lambda c, dn: None)
    smb = _WriteSmb()
    monkeypatch.setattr(gpo_sysvol, "_smb_connect", lambda target, host: smb)
    # Mock _stage_task to return None (we don't need stage) - actually we do need force+gpo for the write probe
    monkeypatch.setattr(
        gpo_sysvol.GpoSysvol,
        "_stage_task",
        lambda self, target, gpos, stage_gpo, payload, session: {
            "ok": True,
            "path": "p",
            "gpo": "{GPO-1}",
        },
    )
    result = gpo_sysvol.GpoSysvol().run(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p"),
        Session(base_dir=tmp_path / "gs"),
        AttackGraph(),
        force=True,
        gpo="{GPO-1}",
        payload="<Tasks/>",
    )
    assert result["writable_sysvol_count"] == 1


def test_gpo_sysvol_write_probe_fails(monkeypatch: Any, tmp_path: Path) -> None:
    class _Conn:
        entries: list[Any] = []
        unbound = False

        def search(self, *a: Any, **k: Any) -> None:
            self.entries = [
                SimpleNamespace(
                    cn="{GPO-1}",
                    displayName="Baseline",
                    gPCFileSysPath="\\\\corp.test\\SYSVOL\\corp.test\\Policies\\{GPO-1}",
                    distinguishedName="CN={GPO-1},DC=corp,DC=test",
                )
            ]

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(gpo_sysvol, "ldap_connect", lambda t: (_Conn(), "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_sysvol, "fetch_sd", lambda c, dn: None)
    smb = _WriteSmb(write_ok=False)
    monkeypatch.setattr(gpo_sysvol, "_smb_connect", lambda target, host: smb)
    monkeypatch.setattr(
        gpo_sysvol.GpoSysvol,
        "_stage_task",
        lambda self, target, gpos, stage_gpo, payload, session: {"ok": False},
    )
    result = gpo_sysvol.GpoSysvol().run(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p"),
        Session(base_dir=tmp_path / "gsf"),
        AttackGraph(),
        force=True,
        gpo="{GPO-1}",
        payload="<Tasks/>",
    )
    assert result["gpos"][0]["sysvol_writable"] is False


def test_gpo_sysvol_skip_gpo_without_cn_or_unc(monkeypatch: Any, tmp_path: Path) -> None:
    """Hit line 110: skip when cn or unc missing."""

    class _Conn:
        entries: list[Any] = []
        unbound = False

        def search(self, *a: Any, **k: Any) -> None:
            self.entries = [
                SimpleNamespace(
                    cn=None,
                    displayName=None,
                    gPCFileSysPath=None,
                    distinguishedName="CN=X,DC=corp,DC=test",
                )
            ]

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(gpo_sysvol, "ldap_connect", lambda t: (_Conn(), "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_sysvol, "fetch_sd", lambda c, dn: None)
    result = gpo_sysvol.GpoSysvol().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path / "sk"),
        AttackGraph(),
    )
    assert result["gpo_count"] == 0


# --------------------------- adcs_enum small branches ---------------------------


def test_adcs_enum_esc1_candidate_without_enroll(monkeypatch: Any, tmp_path: Path) -> None:
    """Cover line 369 (ESC1 candidate without enroll principals) and 398 (no-tags branch)."""
    import adaf_attack.capabilities.adcs_enum as adcs_enum

    ca = SimpleNamespace(
        entry_dn="CN=CA,DC=corp,DC=test",
        cn="CA",
        dNSHostName="ca.corp.test",
        cACertificateDN="CN=CA",
    )
    tmpls = [
        SimpleNamespace(),  # for ESC1 candidate without enroll
        SimpleNamespace(),  # for no-tags case
    ]

    def _fake_analyze(entry: Any) -> dict[str, Any]:
        # Return alternate templates via idx counter
        _fake_analyze.calls = getattr(_fake_analyze, "calls", 0) + 1  # type: ignore[attr-defined]
        if _fake_analyze.calls == 1:  # type: ignore[attr-defined]
            return {
                "cn": "T1",
                "dn": "CN=T1,CN=Certificate Templates,DC=corp,DC=test",
                "esc1_candidate": True,
                "esc2_candidate": False,
                "esc3_agent_template": False,
                "esc3_requires_ra": False,
                "no_security_extension": False,
                "client_auth_eku": False,
                "enrollee_supplies_subject": False,
                "esc_tags": ["ESC1"],
            }
        return {
            "cn": "T2",
            "dn": "CN=T2,CN=Certificate Templates,DC=corp,DC=test",
            "esc1_candidate": False,
            "esc2_candidate": False,
            "esc3_agent_template": False,
            "esc3_requires_ra": False,
            "no_security_extension": False,
            "client_auth_eku": False,
            "enrollee_supplies_subject": False,
            "esc_tags": [],
        }

    class _Conn:
        def __init__(self) -> None:
            self.entries: list[Any] = []
            self.calls = 0
            self.unbound = False

        def search(self, base_dn: str, filt: str, **kwargs: Any) -> None:
            if filt == "(objectClass=pKIEnrollmentService)":
                self.entries = [ca]
            elif filt == "(objectClass=pKICertificateTemplate)":
                self.entries = tmpls
            else:
                self.entries = []

        def unbind(self) -> None:
            self.unbound = True

    conn = _Conn()
    monkeypatch.setattr(adcs_enum, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", "CN=Config"))
    monkeypatch.setattr(adcs_enum, "_analyze_template", _fake_analyze)
    monkeypatch.setattr(adcs_enum, "fetch_sd", lambda c, dn: None)  # no enroll principals
    monkeypatch.setattr(adcs_enum, "_list_attr", lambda e, n: [])
    monkeypatch.setattr(adcs_enum, "_int_attr", lambda e, n: 0)
    monkeypatch.setattr(
        adcs_enum,
        "probe_esc6",
        lambda t, ca_hostnames: {"resolved": True, "esc6": False},
    )
    session = Session(base_dir=tmp_path / "adcs")
    result = adcs_enum.AdcsEnum().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"), session, AttackGraph()
    )
    # T1 is ESC1 candidate without enroll principals → yellow console path
    assert "T1" in result["esc1_candidates"]
