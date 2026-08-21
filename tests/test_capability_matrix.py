"""Execute all 40 catalog capabilities' run() against mocked harnesses.

Each catalog capability is driven through its registered runner with the
same mock patterns used by the per-capability offline suites, proving that
every catalog entry is functionally operational end to end.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

import pytest

import adaf_attack.capabilities.acl_primitives as acl_primitives
import adaf_attack.capabilities.adcs_esc as adcs_esc
import adaf_attack.capabilities.capability_catalog as capability_catalog
import adaf_attack.capabilities.credential_ops as credential_ops
import adaf_attack.capabilities.delegation_ops as delegation_ops
import adaf_attack.capabilities.dmsa_ops as dmsa_ops
import adaf_attack.capabilities.dns_ops as dns_ops
import adaf_attack.capabilities.joined_workflows as joined_workflows
import adaf_attack.capabilities.maq_ops as maq_ops
import adaf_attack.capabilities.relay_ops as relay_ops
import adaf_attack.capabilities.sccm_ops as sccm_ops
from adaf_attack.capabilities.capability_catalog import (
    catalog_destructive_ids,
    catalog_entry,
    catalog_ids,
)
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.rbcd_sd import build_allowed_to_act_sd
from adaf_attack.core.registry import capability_registry
from adaf_attack.core.session import Session
from tests.gate_helpers import Conn, Entry, install_drsuapi_mocks, patch_ldap, sid_entry, target
from tests.gate_helpers import session as make_session


def _managed_blob(password: str) -> bytes:
    cur = password.encode("utf-16-le") + b"\x00\x00"
    header = struct.pack("<HHI", 1, 0, 16 + len(cur))
    header += struct.pack("<HHHH", 16, 0, 0, 0)
    return header + cur


def _acl_conn() -> tuple[Conn, Entry]:
    group = sid_entry("Domain Admins", "CN=Domain Admins,DC=corp,DC=test")
    user = Entry(
        sAMAccountName="alice",
        distinguishedName="CN=Alice,DC=corp,DC=test",
        objectSid="S-1-5-21-1-2-3-1104",
        member=[],
        servicePrincipalName=[],
        sIDHistory=[],
    )
    bob = Entry(
        sAMAccountName="bob",
        distinguishedName="CN=Bob,DC=corp,DC=test",
        objectSid="S-1-5-21-1-2-3-1105",
        member=[],
        servicePrincipalName=["HOST/old"],
        sIDHistory=[],
    )
    conn = Conn({"Domain Admins": [group], "alice": [user], "bob": [bob], "*": [bob]})
    return conn, user


def _delegation_conn() -> Conn:
    unconstrained = Entry(
        sAMAccountName="DC01$",
        distinguishedName="CN=DC01,DC=corp,DC=test",
        userAccountControl=0x80000,
        dNSHostName="dc01.corp.test",
        **{"msDS-AllowedToDelegateTo": ["cifs/dc01.corp.test"]},
    )
    proto = Entry(
        sAMAccountName="svc",
        distinguishedName="CN=svc,DC=corp,DC=test",
        userAccountControl=0x01000000,
        **{"msDS-AllowedToDelegateTo": ["cifs/dc01.corp.test"]},
    )
    return Conn(
        {"objectClass=user": [unconstrained, proto], "objectClass=computer": [unconstrained]}
    )


def _dmsa_conn() -> Conn:
    krbtgt = sid_entry("krbtgt", "CN=krbtgt,DC=corp,DC=test")
    dmsa = sid_entry("ADA$", "CN=ADA,DC=corp,DC=test")
    dmsa._values["msDS-ManagedPassword"] = _managed_blob("DmsaSecret")
    return Conn({"krbtgt": [krbtgt], "ADA$": [dmsa], "ADA": [dmsa], "objectClass=*": [dmsa]})


def _credential_conn() -> Conn:
    blob = _managed_blob("SuperSecret123!")
    gmsa = Entry(
        sAMAccountName="svc$",
        distinguishedName="CN=svc,DC=corp,DC=test",
        **{"msDS-ManagedPassword": blob},
    )
    computer = Entry(sAMAccountName="WS01$")
    msol = Entry(sAMAccountName="MSOL_abc", distinguishedName="CN=MSOL,DC=corp,DC=test")
    sso = Entry(
        sAMAccountName="AZUREADSSOACC$",
        distinguishedName="CN=SSO,DC=corp,DC=test",
        servicePrincipalName=["HOST/sso"],
    )
    return Conn(
        {
            "svc": [gmsa],
            "msDS-GroupManagedServiceAccount": [gmsa],
            "objectClass=computer": [computer],
            "MSOL_": [msol],
            "AZUREADSSOACC": [sso],
        }
    )


def _adcs_session(session: Session) -> None:
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


class _ProcOk:
    def __init__(self) -> None:
        self.returncode = 0

    def wait(self, timeout: int | None = None) -> int:
        return 0

    def terminate(self) -> None:
        return None

    def kill(self) -> None:
        self.returncode = -9


# Per-capability setup returning kwargs for run(). Each setup installs mocks.
SETUP: dict[str, Any] = {}


def _setup(cap_id: str) -> Any:
    def deco(fn: Any) -> Any:
        SETUP[cap_id] = fn
        return fn

    return deco


@_setup("add-member")
def _(mr: Any) -> dict[str, Any]:
    conn, _user = _acl_conn()
    patch_ldap(mr.monkeypatch, acl_primitives, conn)
    return {"group": "Domain Admins", "member": "alice"}


@_setup("add-self")
def _(mr: Any) -> dict[str, Any]:
    conn, _user = _acl_conn()
    patch_ldap(mr.monkeypatch, acl_primitives, conn)
    return {"group": "Domain Admins"}


@_setup("force-change-password")
def _(mr: Any) -> dict[str, Any]:
    conn, _user = _acl_conn()
    patch_ldap(mr.monkeypatch, acl_primitives, conn)
    return {"sam": "bob", "new_password": "N3w!"}


@_setup("write-spn")
def _(mr: Any) -> dict[str, Any]:
    conn, _user = _acl_conn()
    patch_ldap(mr.monkeypatch, acl_primitives, conn)
    return {"sam": "bob", "spn": "HTTP/app"}


@_setup("acl-abuse")
def _(mr: Any) -> dict[str, Any]:
    conn, _user = _acl_conn()
    patch_ldap(mr.monkeypatch, acl_primitives, conn)
    mr.monkeypatch.setattr(
        acl_primitives, "fetch_sd", lambda *_a, **_k: build_allowed_to_act_sd("S-1-5-21-1-2-3-9")
    )
    return {"sam": "bob", "rights": "GenericAll", "principal_sid": "S-1-5-21-1-2-3-4"}


@_setup("adminsdholder-persist")
def _(mr: Any) -> dict[str, Any]:
    conn, _user = _acl_conn()
    patch_ldap(mr.monkeypatch, acl_primitives, conn)
    mr.monkeypatch.setattr(
        acl_primitives, "fetch_sd", lambda *_a, **_k: build_allowed_to_act_sd("S-1-5-21-1-2-3-4")
    )
    return {"principal_sid": "S-1-5-21-1-2-3-4"}


@_setup("sidhistory-inject")
def _(mr: Any) -> dict[str, Any]:
    conn, _user = _acl_conn()
    patch_ldap(mr.monkeypatch, acl_primitives, conn)
    install_drsuapi_mocks(mr.monkeypatch)
    return {"sam": "bob", "sid": "S-1-5-21-99"}


@_setup("unconstrained-delegation")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, delegation_ops, _delegation_conn())
    return {}


@_setup("trustedtoauth")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, delegation_ops, _delegation_conn())
    return {}


@_setup("constrained-delegation")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, delegation_ops, _delegation_conn())
    return {}


@_setup("badsuccessor")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, dmsa_ops, _dmsa_conn())
    return {"preceded_by": "krbtgt"}


@_setup("dmsa-ouroboros")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, dmsa_ops, _dmsa_conn())
    return {"sam": "ADA$"}


@_setup("esc9")
def _(mr: Any) -> dict[str, Any]:
    _mock_certipy_ok(mr)
    return {"template": "ESC9", "ca": "CORP-CA"}


@_setup("esc10")
def _(mr: Any) -> dict[str, Any]:
    _mock_certipy_ok(mr)
    return {"template": "T", "ca": "CA"}


@_setup("esc13")
def _(mr: Any) -> dict[str, Any]:
    _mock_certipy_ok(mr)
    return {"template": "T", "ca": "CA"}


@_setup("esc14")
def _(mr: Any) -> dict[str, Any]:
    _mock_certipy_ok(mr)
    return {"template": "T", "ca": "CA"}


@_setup("esc15")
def _(mr: Any) -> dict[str, Any]:
    _mock_certipy_ok(mr)
    return {"template": "V1", "ca": "CA"}


@_setup("esc16")
def _(mr: Any) -> dict[str, Any]:
    _mock_certipy_ok(mr)
    return {"template": "T", "ca": "CA"}


@_setup("golden-cert")
def _(mr: Any) -> dict[str, Any]:
    _mock_certipy_ok(mr)
    return {"ca_pfx": "ca.pfx", "upn": "admin@corp.test"}


def _mock_certipy_ok(mr: Any) -> None:
    mr.monkeypatch.setattr(
        adcs_esc.subprocess,
        "run",
        lambda *a, **k: type("P", (), {"returncode": 0, "stdout": "ok", "stderr": ""})(),
    )
    (mr.session.root / "enroll.pfx").write_text("x", encoding="utf-8")


@_setup("krb-relay")
def _(mr: Any) -> dict[str, Any]:
    mr.monkeypatch.setattr(relay_ops.shutil, "which", lambda *_a, **_k: "/bin/krbrelayx")
    mr.monkeypatch.setattr(relay_ops.subprocess, "Popen", lambda *a, **k: _ProcOk())
    return {"relay_targets": "ldap://dc01.corp.test", "duration_seconds": 1}


@_setup("dcshadow")
def _(mr: Any) -> dict[str, Any]:
    dc = sid_entry("ROGUE$", "CN=ROGUE,DC=corp,DC=test")
    dc._values["dNSHostName"] = "rogue.corp.test"
    conn = Conn({"ROGUE": [dc], "*": [dc]})
    patch_ldap(mr.monkeypatch, relay_ops, conn)
    return {"computer": "ROGUE$"}


@_setup("dpapi-domain-backup")
def _(mr: Any) -> dict[str, Any]:
    mr.monkeypatch.setattr(credential_ops, "require_impacket", lambda *_a, **_k: None)
    from tests.gate_helpers import install_dpapi_lsarpc_mocks

    install_dpapi_lsarpc_mocks(mr.monkeypatch)
    return {}


@_setup("maq-rbcd-workflow")
def _(mr: Any) -> dict[str, Any]:
    conn, _user = _acl_conn()
    patch_ldap(mr.monkeypatch, maq_ops, conn)

    class _Rbcd:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"set_attempt": {"ok": True}}

    class _S4u:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

    mr.monkeypatch.setattr(maq_ops, "Rbcd", _Rbcd)
    mr.monkeypatch.setattr(maq_ops, "S4uAbuse", _S4u)
    return {"set_on": "DC01$", "impersonate": "Administrator"}


@_setup("nopac-workflow")
def _(mr: Any) -> dict[str, Any]:
    conn, _user = _acl_conn()

    class _Maq:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True, "sam": "NEW$", "dn": "CN=NEW,DC=corp,DC=test"}

    mr.monkeypatch.setattr(joined_workflows, "MaqAddComputer", lambda: _Maq())
    newpc = sid_entry("NEW$", "CN=NEW,DC=corp,DC=test")
    dc01 = sid_entry("DC01$", "CN=DC01,DC=corp,DC=test")
    conn.by_filter.update({"NEW$": [newpc], "DC01": [dc01], "DC01$": [dc01]})
    patch_ldap(mr.monkeypatch, joined_workflows, conn)
    return {"dc": "DC01$"}


@_setup("targeted-kerberoast")
def _(mr: Any) -> dict[str, Any]:
    class _Write:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            if kwargs.get("clear") or kwargs.get("spns"):
                return {"ok": True, "previous": ["HOST/old"]}
            return {"ok": True, "previous": ["HOST/old"]}

    class _Roast:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"tickets": []}

    mr.monkeypatch.setattr(joined_workflows, "WriteSpn", lambda: _Write())
    mr.monkeypatch.setattr(joined_workflows, "Kerberoast", lambda: _Roast())
    return {"sam": "bob"}


@_setup("dcsync-grant-workflow")
def _(mr: Any) -> dict[str, Any]:
    conn, _user = _acl_conn()
    patch_ldap(mr.monkeypatch, joined_workflows, conn)
    mr.monkeypatch.setattr(
        joined_workflows, "fetch_sd", lambda *_a, **_k: build_allowed_to_act_sd("S-1-5-21-1-2-3-9")
    )

    class _Dcsync:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

    mr.monkeypatch.setattr(joined_workflows, "Dcsync", _Dcsync)
    return {"principal_sid": "S-1-5-21-1-2-3-4"}


@_setup("esc8-relay-workflow")
def _(mr: Any) -> dict[str, Any]:
    class _Relay:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"return_code": 0}

    class _Coerce:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

    mr.monkeypatch.setattr(adcs_esc, "NtlmRelay", _Relay)
    mr.monkeypatch.setattr(adcs_esc, "Coerce", _Coerce)
    return {"ca": "ca.corp.test", "coerce_host": "ws01"}


@_setup("unconst-tgtdump-workflow")
def _(mr: Any) -> dict[str, Any]:
    class _Hunt:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "count": 1,
                "principals": [{"unconstrained": True, "dns": "dc01.corp.test", "sam": "DC01$"}],
            }

    class _Coerce:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

    mr.monkeypatch.setattr(joined_workflows, "UnconstrainedDelegation", _Hunt)
    mr.monkeypatch.setattr(joined_workflows, "Coerce", _Coerce)
    return {}


@_setup("maq-add-computer")
def _(mr: Any) -> dict[str, Any]:
    conn, _user = _acl_conn()
    patch_ldap(mr.monkeypatch, maq_ops, conn)
    return {"computer": "NEWPC", "password": "p"}


@_setup("pre2k-spray")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, credential_ops, _credential_conn())
    mr.monkeypatch.setattr(credential_ops, "try_ntlm_bind", lambda *a, **k: (True, "ok"))
    return {"max_objects": 10, "max_attempts": 1}


@_setup("timeroast")
def _(mr: Any) -> dict[str, Any]:
    mr.monkeypatch.setattr(credential_ops, "_udp_query", lambda *a, **k: b"\x00" * 68)
    return {"rid_start": 1000, "rid_end": 1001}


@_setup("gmsa-read")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, credential_ops, _credential_conn())
    return {"sam": "svc$"}


@_setup("azureadssoacc-roast")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, credential_ops, _credential_conn())

    class _Kerberoast:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"tickets": [{"account": "AZUREADSSOACC$", "spn": "HOST/sso"}]}

    mr.monkeypatch.setattr(credential_ops, "Kerberoast", _Kerberoast)
    return {}


@_setup("aadconnect-dcsync")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, credential_ops, _credential_conn())

    class _Dcsync:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True, "count": 1}

    mr.monkeypatch.setattr(credential_ops, "Dcsync", _Dcsync)
    return {}


@_setup("adidns-wpad")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, dns_ops, Conn({"MicrosoftDNS": [Entry(name="corp.test")]}))
    return {"ip": "10.0.0.9"}


@_setup("dnsadmin-srv")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, dns_ops, Conn({"MicrosoftDNS": [Entry(name="corp.test")]}))
    return {"host": "evil.test"}


@_setup("sccm-enum")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, sccm_ops, _sccm_conn())
    return {}


def _sccm_conn() -> Conn:
    mp = Entry(
        cn="MP",
        distinguishedName="CN=MP,CN=System Management,CN=System,DC=corp,DC=test",
        dNSHostName="mp.corp.test",
        mSSMSSiteCode="P01",
        mSSMSMPName="mp.corp.test",
        mSSMSVersion="5",
    )
    naa = Entry(
        cn="NetworkAccessAccount", distinguishedName="CN=NAA,DC=corp,DC=test", sAMAccountName="naa"
    )
    return Conn({"System Management": [mp], "NetworkAccessAccount": [naa]})


@_setup("sccm-naa")
def _(mr: Any) -> dict[str, Any]:
    patch_ldap(mr.monkeypatch, sccm_ops, _sccm_conn())
    mr.monkeypatch.setattr(
        sccm_ops, "_http_get", lambda url, timeout=5.0: (200, "CCM_NetworkAccessAccount=1")
    )
    return {"mp": "mp.corp.test"}


@_setup("sccm-takeover")
def _(mr: Any) -> dict[str, Any]:
    class _Relay:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"return_code": 0}

    mr.monkeypatch.setattr(sccm_ops, "NtlmRelay", _Relay)
    return {"site_db": "sql01.corp.test"}


@_setup("sccm-client-push")
def _(mr: Any) -> dict[str, Any]:
    return {"host": "ws01.corp.test"}


ALL_IDS = catalog_ids()


@pytest.mark.parametrize("cap_id", ALL_IDS)
def test_catalog_capability_runs(cap_id: str, monkeypatch: Any, tmp_path: Path) -> None:
    cap = capability_registry.get(cap_id)
    assert cap is not None and cap.runner is not None, cap_id
    setup = SETUP.get(cap_id)
    assert setup is not None, f"no mock setup registered for {cap_id}"

    class _MR:
        pass

    mr = _MR()
    mr.monkeypatch = monkeypatch
    mr.session = make_session(tmp_path / cap_id.replace("-", "_"))
    kwargs = setup(mr)
    result = cap.runner.run(
        target(), mr.session, AttackGraph(), include_secrets=False, force=True, **kwargs
    )
    assert isinstance(result, dict), cap_id
    # Read-only enumerators report a count instead of an explicit ok flag.
    # sccm-client-push honestly reports it did not execute the push (ok=False).
    expected_ok = cap_id != "sccm-client-push"
    assert result.get("ok", "count" in result) is expected_ok, f"{cap_id} failed: {result}"
    if cap_id == "sccm-client-push":
        assert result["requested"] is False
        assert (mr.session.path("sccm-client-push.playbook.txt")).exists()
    if cap_id.startswith("esc") and cap_id[3:].isdigit():
        assert result["conditions"] == adcs_esc.ESC_CONDITIONS[cap_id]
        assert mr.session.path(f"{cap_id}.conditions.txt").is_file()
    assert not any(k in result for k in ("password",)), f"{cap_id} leaked secrets"


@pytest.mark.parametrize("cap_id", catalog_destructive_ids())
def test_destructive_capabilities_are_force_gated(
    cap_id: str, monkeypatch: Any, tmp_path: Path
) -> None:
    """Destructive ids must refuse to run without force even before touching LDAP."""
    cap = capability_registry.get(cap_id)
    assert cap is not None and cap.runner is not None
    setup = SETUP.get(cap_id)
    assert setup is not None

    class _MR:
        pass

    mr = _MR()
    mr.monkeypatch = monkeypatch
    mr.session = make_session(tmp_path / "gate")
    kwargs = dict(setup(mr))
    if cap_id == "constrained-delegation":
        # Only the set path is force-gated; enumeration alone is read-only.
        kwargs.update({"sam": "svc", "spn": "cifs/app.corp.test"})
    with pytest.raises(RuntimeError, match="--force"):
        cap.runner.run(
            target(), mr.session, AttackGraph(), include_secrets=False, force=False, **kwargs
        )


def test_catalog_has_forty_entries_with_setups() -> None:
    assert len(catalog_ids()) == 40
    missing = set(catalog_ids()) - set(SETUP)
    assert not missing, sorted(missing)


def test_catalog_entry_lookup_roundtrip() -> None:
    for cap_id in catalog_ids():
        entry = catalog_entry(cap_id)
        assert entry[0] == cap_id
        assert capability_catalog.CAPABILITY_CATALOG is not None
