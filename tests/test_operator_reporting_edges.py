"""Additional offline coverage for operator-facing capability adapters.

These tests exercise deterministic parsing, policy, redaction, and orchestration
paths while keeping all network and destructive operations mocked.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

import adaf_attack.capabilities.ad_cve_scan as ad_cve_scan
import adaf_attack.capabilities.asreq_userhunt as asreq_userhunt
import adaf_attack.capabilities.coerce as coerce
import adaf_attack.capabilities.dcsync as dcsync
import adaf_attack.capabilities.gpp_cpassword as gpp_cpassword
import adaf_attack.capabilities.impacket_exec as impacket_exec
import adaf_attack.capabilities.password_spray as password_spray
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.reporting import _finding_html, _pdf
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any) -> None:
        self.value = value

    def __bool__(self) -> bool:
        return self.value is not None

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **values: Any) -> None:
        self._values = {key: _Attr(value) for key, value in values.items()}
        for key, value in values.items():
            setattr(self, key, value)

    def __getitem__(self, key: str) -> _Attr:
        return self._values[key]


class _CveConnection:
    def __init__(self) -> None:
        self.entries: list[_Entry] = []
        self.unbound = False

    def search(self, _base: str, search_filter: str, **_kwargs: Any) -> None:
        self.entries = {
            "(objectClass=pKICertificateTemplate)": [
                _Entry(cn="WeakTemplate", **{"msPKI-Certificate-Name-Flag": 1}),
                _Entry(cn="StrongTemplate", **{"msPKI-Certificate-Name-Flag": 0}),
            ],
            "(sAMAccountName=krbtgt)": [_Entry(**{"msDS-KeyVersionNumber": 2})],
            "(objectClass=domainDNS)": [_Entry(**{"msDS-Behavior-Version": 7})],
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)": [
                _Entry(sAMAccountName="des-user")
            ],
            "(!(msDS-SupportedEncryptionTypes=*))": [
                _Entry(sAMAccountName="no-etype", objectClass=SimpleNamespace(values=["user"]))
            ],
        }.get(search_filter, [])

    def unbind(self) -> None:
        self.unbound = True


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10")


def test_ad_cve_scan_helpers_and_run(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _CveConnection()
    monkeypatch.setattr(ad_cve_scan, "_check_smb_signing", lambda _ip: {"signing_required": True})
    monkeypatch.setattr(
        ad_cve_scan, "ldap_connect", lambda _target: (conn, "DC=corp,DC=test", "CN=Config")
    )

    assert ad_cve_scan._check_ldap_signing(conn, "DC=corp,DC=test")["ok"] is True
    assert ad_cve_scan._check_certifried_templates(conn, "CN=Config")["count"] == 1
    assert ad_cve_scan._check_noPAC(conn, "DC=corp,DC=test")["krbtgt_kvno"] == 2
    assert (
        ad_cve_scan._check_functional_level(conn, "DC=corp,DC=test")["domain_functional_level"] == 7
    )
    ntlm = ad_cve_scan._check_ntlm_and_rc4(conn, "DC=corp,DC=test")
    assert ntlm["des_users"] == ["des-user"] and ntlm["accounts_without_supported_etypes"] == 1

    session = Session(tmp_path / "session")
    result = ad_cve_scan.AdCveScan().run(_target(), session, AttackGraph())
    assert result["summary"]["vulnerable_cert_templates"] == 1
    assert conn.unbound and session.path("ad-cve-scan.json").is_file()


def test_ad_cve_scan_error_guards() -> None:
    class Broken:
        entries: list[Any] = []

        def search(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("offline")

    broken = Broken()
    assert "error" in ad_cve_scan._check_ldap_signing(broken, "DC=x")
    assert "error" in ad_cve_scan._check_certifried_templates(broken, "CN=x")
    assert "error" in ad_cve_scan._check_noPAC(broken, "DC=x")
    assert "error" in ad_cve_scan._check_functional_level(broken, "DC=x")
    assert "error" in ad_cve_scan._check_ntlm_and_rc4(broken, "DC=x")


@pytest.mark.parametrize(
    "code",
    [
        "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        "KDC_ERR_PREAUTH_REQUIRED",
        "KDC_ERR_PREAUTH_FAILED",
        "KDC_ERR_CLIENT_REVOKED",
        "KDC_ERR_ETYPE_NOSUPP",
        "KDC_ERR_WRONG_REALM",
    ],
)
def test_asreq_error_classification(code: str) -> None:
    state, valid, found = asreq_userhunt._classify_kdc_error(code)
    assert found == code and valid is (state != "unknown")


def test_asreq_probe_and_run(monkeypatch: Any, tmp_path: Path) -> None:
    import impacket.krb5.kerberosv5 as kerberosv5

    monkeypatch.setattr(kerberosv5, "getKerberosTGT", lambda *args: (b"ticket", None, None, None))
    success = asreq_userhunt._probe_user("alice", "corp.test", "192.0.2.10")
    assert success["as_rep_bytes"] == 6 and success["no_preauth"] is True
    monkeypatch.setattr(
        kerberosv5,
        "getKerberosTGT",
        lambda *args: (_ for _ in ()).throw(RuntimeError("KDC_ERR_WRONG_REALM")),
    )
    failure = asreq_userhunt._probe_user("bob", "corp.test", "192.0.2.10")
    assert failure["valid"] is True and failure["state"] == "valid"

    monkeypatch.setattr(asreq_userhunt, "require_impacket", lambda _name: None)
    monkeypatch.setattr(
        asreq_userhunt,
        "_probe_user",
        lambda user, _domain, _dc: {"user": user, "valid": user == "alice", "state": "valid"},
    )
    users = tmp_path / "users.txt"
    users.write_text("alice\n\nunknown\n", encoding="utf-8")
    graph = AttackGraph()
    result = asreq_userhunt.AsreqUserhunt().run(
        _target(), Session(tmp_path / "session"), graph, users=users
    )
    assert result["count"] == 2 and result["valid"] == 1
    assert graph.nodes


def test_coercion_request_builders_and_run(monkeypatch: Any, tmp_path: Path) -> None:
    class _Request(dict[str, Any]):
        pass

    class _NdrCall(_Request):
        pass

    fake_efsr = ModuleType("impacket.dcerpc.v5.efsr")
    fake_efsr.EfsRpcOpenFileRaw = _Request  # type: ignore[attr-defined]
    fake_rprn = ModuleType("impacket.dcerpc.v5.rprn")
    fake_rprn.RpcRemoteFindFirstPrinterChangeNotificationEx = _Request  # type: ignore[attr-defined]
    fake_dtypes = ModuleType("impacket.dcerpc.v5.dtypes")
    fake_dtypes.ULONG = int  # type: ignore[attr-defined]
    fake_dtypes.WSTR = str  # type: ignore[attr-defined]
    fake_ndr = ModuleType("impacket.dcerpc.v5.ndr")
    fake_ndr.NDRCALL = _NdrCall  # type: ignore[attr-defined]
    fake_rpcrt = ModuleType("impacket.dcerpc.v5.rpcrt")
    fake_rpcrt.DCERPCException = RuntimeError  # type: ignore[attr-defined]
    fake_even6 = ModuleType("impacket.dcerpc.v5.even6")
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.efsr", fake_efsr)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rprn", fake_rprn)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.dtypes", fake_dtypes)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.ndr", fake_ndr)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rpcrt", fake_rpcrt)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.even6", fake_even6)
    listener = r"\\listener\pwn\x"
    for method in coerce.METHODS:
        request = coerce._build_coercion_request(method, listener)
        assert request is not None
    with pytest.raises(ValueError, match="unknown method"):
        coerce._build_coercion_request("unknown", listener)

    monkeypatch.setattr(coerce, "require_impacket", lambda _name: None)
    monkeypatch.setattr(
        coerce,
        "_trigger",
        lambda _target, _host, _listener, method: {"method": method, "ok": method == "petitpotam"},
    )
    session = Session(tmp_path / "session")
    result = coerce.Coerce().run(
        _target(),
        session,
        AttackGraph(),
        listener="listener",
        methods="petitpotam,invalid,printerbug",
    )
    assert len(result["results"]) == 2 and session.path("coerce.json").is_file()
    with pytest.raises(RuntimeError, match="listener"):
        coerce.Coerce().run(_target(), Session(tmp_path / "missing-listener"), AttackGraph())


def test_gpp_capability_redacts_and_records(monkeypatch: Any, tmp_path: Path) -> None:
    source = tmp_path / "sysvol"
    source.mkdir()
    monkeypatch.setattr(gpp_cpassword, "iter_gpp_files", lambda _root: [source / "Groups.xml"])
    monkeypatch.setattr(
        gpp_cpassword,
        "parse_gpp_file",
        lambda _path: [{"file": "Groups.xml", "username": "alice", "plaintext": "secret"}],
    )
    result = gpp_cpassword.GppCpasswordHunt().run(
        _target(), Session(tmp_path / "session"), AttackGraph(), sysvol=source
    )
    assert result["decrypted"] == 1
    assert result["entries"][0]["plaintext"] == "secret"
    included = gpp_cpassword.GppCpasswordHunt().run(
        _target(),
        Session(tmp_path / "included"),
        AttackGraph(),
        sysvol=source,
        include_secrets=True,
    )
    assert included["entries"][0]["plaintext"] == "secret"


def test_impacket_exec_safe_script_modes(monkeypatch: Any, tmp_path: Path) -> None:
    capability = impacket_exec.ImpacketExec()
    with pytest.raises(RuntimeError, match="--force"):
        capability.run(_target(), Session(tmp_path / "guard"), AttackGraph(), command="whoami")
    with pytest.raises(RuntimeError, match="unknown method"):
        capability.run(
            _target(),
            Session(tmp_path / "bad-method"),
            AttackGraph(),
            force=True,
            method="bad",
            command="whoami",
        )
    with pytest.raises(RuntimeError, match="Pass"):
        capability.run(_target(), Session(tmp_path / "no-command"), AttackGraph(), force=True)
    monkeypatch.setattr(impacket_exec, "require_impacket", lambda _name: None)
    for method in ("atexec", "dcomexec"):
        result = capability.run(
            _target(),
            Session(tmp_path / method),
            AttackGraph(),
            force=True,
            method=method,
            command="whoami",
        )
        assert result["method"] == method and result["outcome"]["note"]


def test_report_pdf_and_html_branches(tmp_path: Path) -> None:
    pytest.importorskip("reportlab")
    finding = {
        "title": "Test finding",
        "severity": "high",
        "impact": "Impact",
        "remediation": "Fix it",
        "evidence": [{"artifact": "a.json", "pointer": "/", "sha256": "a" * 64}],
        "attack_techniques": ("T1003",),
    }
    assert "Evidence:" in _finding_html(finding, True)
    assert _pdf(tmp_path / "technical.pdf", "Technical", [finding], "technical") is True
    assert _pdf(tmp_path / "remediation.pdf", "Remediation", [finding], "remediation") is True


def test_dcsync_mocked_collection_and_redaction(monkeypatch: Any, tmp_path: Path) -> None:
    class _Smb:
        def login(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    class _Remote:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def setExecMethod(self, _method: str) -> None:
            return None

        def enableRegistry(self) -> None:
            return None

        def finish(self) -> None:
            return None

    class _Hashes:
        def __init__(self, *_args: Any, **kwargs: Any) -> None:
            self.callback = kwargs["perSecretCallback"]

        def dump(self) -> None:
            self.callback(1, r"CORP\\alice:1105:lmhash:nthash")
            self.callback(1, "not-a-hash-line")

    monkeypatch.setattr(dcsync, "require_impacket", lambda _name: None)
    monkeypatch.setattr("impacket.smbconnection.SMBConnection", lambda *args, **kwargs: _Smb())
    monkeypatch.setattr("impacket.examples.secretsdump.RemoteOperations", _Remote)
    monkeypatch.setattr("impacket.examples.secretsdump.NTDSHashes", _Hashes)
    target = Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", password="pw")
    graph = AttackGraph()
    result = dcsync.Dcsync().run(target, Session(tmp_path / "session"), graph, just_user="alice")
    assert result["count"] == 1 and result["entries"][0]["nt_hash"] == "[REDACTED]"
    assert graph.nodes and result["principal_filter"] == ["alice"]
    included = dcsync.Dcsync().run(
        target,
        Session(tmp_path / "included"),
        AttackGraph(),
        just_user="alice",
        include_secrets=True,
    )
    assert included["entries"][0]["nt_hash"] == "nthash"


def test_password_spray_policy_and_safety_paths(monkeypatch: Any, tmp_path: Path) -> None:
    class _Conn:
        def __init__(self) -> None:
            self.entries: list[Any] = []
            self.unbound = False

        def search(self, _base: str, search_filter: str, **_kwargs: Any) -> None:
            if search_filter == "(objectClass=domain)":
                self.entries = [
                    SimpleNamespace(
                        lockoutThreshold=_Attr(5),
                        lockoutObservationWindow=_Attr(-300000000),
                        minPwdLength=_Attr(12),
                    )
                ]
            elif search_filter.startswith("(sAMAccountName="):
                sam = search_filter.split("=", 1)[1].rstrip(")")
                self.entries = [
                    SimpleNamespace(
                        sAMAccountName=_Attr(sam),
                        badPwdCount=_Attr(1 if sam == "alice" else 4),
                        badPasswordTime=_Attr(0),
                    )
                ]
            else:
                self.entries = [
                    SimpleNamespace(sAMAccountName=_Attr("alice")),
                    SimpleNamespace(sAMAccountName=_Attr("bob")),
                ]

        def unbind(self) -> None:
            self.unbound = True

    conn = _Conn()
    monkeypatch.setattr(
        password_spray, "ldap_connect", lambda _target: (conn, "DC=corp,DC=test", None)
    )
    monkeypatch.setattr(password_spray, "_try_bind", lambda *_args: (True, "ok"))
    result = password_spray.PasswordSpray().run(
        _target(),
        Session(tmp_path / "session"),
        AttackGraph(),
        password_to_try="Candidate!23",
        safety_margin=2,
    )
    assert result["hit_count"] == 1
    assert result["attempts"][1]["skipped"] == "at_or_near_lockout"
    assert conn.unbound
