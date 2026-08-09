"""Deep offline coverage for capabilities: report branches, pkinit_auth,
shadow_creds write path, cert-request happy path, gmsa/laps secrets path,
ticket_lifecycle operations, and core/acl parsing."""

from __future__ import annotations

import datetime
import json
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import adaf_attack.capabilities.cert_request as cert_request
import adaf_attack.capabilities.gmsa_laps_enum as gmsa
import adaf_attack.capabilities.pkinit_auth as pkinit
import adaf_attack.capabilities.shadow_creds as shadow
from adaf_attack.capabilities.report import Report
from adaf_attack.capabilities.ticket_lifecycle import TicketLifecycle
from adaf_attack.core.acl import (
    _guid_bytes_to_str,
    _mask_to_rights,
    _sid_to_str,
    fetch_sd,
    parse_interesting_aces,
)
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.rbcd_sd import build_allowed_to_act_sd
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

# --------------------------- report per-capability branches ---------------------------


def test_report_covers_all_capability_branches(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    # seed graph
    g = AttackGraph()
    g.add_node("USER@ALICE@CORP", "User", sam="alice")
    g.add_edge("USER@ALICE@CORP", "USER@ALICE@CORP", "MemberOf")
    g.save(session.path("graph.json"))
    session.path("interesting.json").write_text(
        json.dumps(
            {
                "top_paths": [
                    {"path": ["USER@ALICE@CORP"], "score": 3.5, "length": 1},
                ]
            }
        ),
        encoding="utf-8",
    )
    # seed every known finding file
    session.path("ldap-enum.json").write_text(
        json.dumps(
            {
                "users": [{"sam": "alice"}],
                "computers": [{"sam": "DC$"}],
                "groups": [],
                "delegation": [],
                "sid_history": [],
            }
        ),
        encoding="utf-8",
    )
    session.path("acl-enum.json").write_text(
        json.dumps(
            {"objects_scanned": 2, "interesting_edge_count": 5, "dcsync_principals": ["S-1-5-9"]}
        ),
        encoding="utf-8",
    )
    session.path("adcs-enum.json").write_text(
        json.dumps(
            {
                "cas": [{"cn": "CA"}],
                "templates": [{}],
                "esc1_candidates": ["User"],
                "esc2_candidates": [],
                "esc4_acl_templates": [],
                "esc7_ca_acl": [],
                "esc8_web_enrollment": [],
                "esc6": {"resolved": True, "esc6": True},
            }
        ),
        encoding="utf-8",
    )
    session.path("kerberoast.json").write_text(
        json.dumps({"tickets": [{"a": 1}]}), encoding="utf-8"
    )
    session.path("asrep-roast.json").write_text(json.dumps({"count": 2}), encoding="utf-8")
    session.path("shadow-creds.json").write_text(
        json.dumps({"accounts_with_keycred": [1], "writable_principals": [1, 2]}), encoding="utf-8"
    )
    session.path("rbcd.json").write_text(
        json.dumps({"rbcd_configured": [1], "writable_computers": [1]}), encoding="utf-8"
    )
    session.path("gpo-abuse.json").write_text(
        json.dumps({"gpos": [1], "writable_gpos": [], "links": []}), encoding="utf-8"
    )
    session.path("coercion-map.json").write_text(
        json.dumps({"hosts_checked": 2, "spooler_open": 1, "efsrpc_open": 0}), encoding="utf-8"
    )
    session.path("pkinit-auth.json").write_text(
        json.dumps({"ok": True, "method": "certipy", "list_field": [1, 2, 3]}), encoding="utf-8"
    )
    # generic dict path (dict with mixed value types)
    session.path("cert-request.json").write_text(
        json.dumps({"ok": True, "template": "User", "notes": ["a", "b"]}), encoding="utf-8"
    )
    session.path("gpo-sysvol.json").write_text(json.dumps({"paths": []}), encoding="utf-8")
    session.path("attack-paths.json").write_text(json.dumps({"count": 0}), encoding="utf-8")
    # corrupt one to hit _load exception path
    session.path("trusts-enum.json").write_text("not json", encoding="utf-8")

    target = Target(domain="corp.test", dc_ip="10.0.0.1")
    result = Report().run(target, session, AttackGraph())
    md = Path(result["md_path"]).read_text(encoding="utf-8")
    assert "AD CS" in md and "Shadow credentials" in md and "RBCD" in md
    assert "PKINIT" in md and "Coercion surface" in md and "GPO abuse" in md


def test_report_hydrates_graph_from_disk_when_empty(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    g = AttackGraph()
    g.add_node("X", "Base")
    g.save(session.path("graph.json"))
    result = Report().run(Target(domain="corp.test", dc_ip="1.1.1.1"), session, AttackGraph())
    assert Path(result["md_path"]).is_file()


# --------------------------- cert_request happy path + errors ---------------------------


def test_cert_request_seeds_template_and_ca_from_adcs_enum(
    monkeypatch: Any, tmp_path: Path
) -> None:
    session = Session(base_dir=tmp_path)
    session.path("adcs-enum.json").write_text(
        json.dumps(
            {
                "esc1_candidates": ["SeedTemplate"],
                "cas": [{"cn": "SeedCA"}],
            }
        ),
        encoding="utf-8",
    )
    proc = SimpleNamespace(returncode=0, stdout="issued", stderr="")
    monkeypatch.setattr(cert_request.subprocess, "run", lambda *a, **k: proc)
    # simulate certipy writing a pfx
    (session.root / "issued.pfx").write_bytes(b"pfx")
    graph = AttackGraph()
    result = cert_request.CertRequest().run(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="alice", password="secret"),
        session,
        graph,
        force=True,
    )
    assert result["ok"] is True
    assert result["template"] == "SeedTemplate"
    assert result["ca"] == "SeedCA"
    assert "pfx" in result
    assert any(edge.kind == "EnrolledCertificate" for edge in graph.edges)


def test_cert_request_no_template_or_username(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    with pytest.raises(RuntimeError, match="No --template"):
        cert_request.CertRequest().run(
            Target(domain="corp.test", dc_ip="10.0.0.1", username="alice", password="p"),
            session,
            AttackGraph(),
            force=True,
        )
    with pytest.raises(RuntimeError, match="Username required"):
        cert_request.CertRequest().run(
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            session,
            AttackGraph(),
            force=True,
            template="User",
        )


def test_cert_request_certipy_returns_error(monkeypatch: Any, tmp_path: Path) -> None:
    proc = SimpleNamespace(returncode=1, stdout="", stderr="denied")
    monkeypatch.setattr(cert_request.subprocess, "run", lambda *a, **k: proc)
    session = Session(base_dir=tmp_path)
    result = cert_request.CertRequest().run(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="alice", hashes=":aabb"),
        session,
        AttackGraph(),
        force=True,
        template="User",
        ca="CorpCA",
        alt_name="admin@corp.test",
    )
    assert result["ok"] is False
    assert result["method"] == "certipy"


def test_cert_request_generic_error_path(monkeypatch: Any, tmp_path: Path) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise TimeoutError("subprocess timed out")

    monkeypatch.setattr(cert_request.subprocess, "run", boom)
    session = Session(base_dir=tmp_path)
    result = cert_request.CertRequest().run(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="alice", password="x"),
        session,
        AttackGraph(),
        force=True,
        template="User",
    )
    assert result["method"] == "error"
    assert "subprocess timed out" in result["error"]


# --------------------------- pkinit_auth ---------------------------


def _make_pem_pair(session: Session, sam: str) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sam)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sam)]))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    session.path(f"shadow-{sam}.key.pem").write_bytes(key_pem)
    session.path(f"shadow-{sam}.cert.pem").write_bytes(cert_pem)


def test_pkinit_auth_requires_force(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="requires --force"):
        pkinit.PkinitAuth().run(
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            Session(base_dir=tmp_path),
            AttackGraph(),
            sam="alice",
        )


def test_pkinit_auth_no_material(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="No shadow key/cert"):
        pkinit.PkinitAuth().run(
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            Session(base_dir=tmp_path),
            AttackGraph(),
            force=True,
            sam="alice",
        )


def test_pkinit_auth_missing_pfx(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="PFX not found"):
        pkinit.PkinitAuth().run(
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            Session(base_dir=tmp_path),
            AttackGraph(),
            force=True,
            sam="alice",
            pfx=str(tmp_path / "does-not-exist.pfx"),
        )


def test_pkinit_auth_missing_key_cert(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="key/cert not found"):
        pkinit.PkinitAuth().run(
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            Session(base_dir=tmp_path),
            AttackGraph(),
            force=True,
            sam="alice",
            key=str(tmp_path / "no.key"),
            cert=str(tmp_path / "no.cert"),
        )


def test_pkinit_auth_needs_identity(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    # Provide an existing pfx (via material generation for a known SAM), but pass none as identity
    _make_pem_pair(session, "alice")
    pfx = session.path("m.pfx")
    pfx.write_bytes(b"any")
    # No sam/username → PkinitAuth raises before running subprocess
    with pytest.raises(RuntimeError, match="Need sam/username"):
        pkinit.PkinitAuth().run(
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            session,
            AttackGraph(),
            force=True,
            pfx=str(pfx),
        )


def test_pkinit_auth_certipy_success(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    _make_pem_pair(session, "alice")

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        # simulate certipy writing a ccache next to the cwd
        Path(kwargs["cwd"], "alice.ccache").write_bytes(b"ticket-bytes")
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(pkinit.subprocess, "run", fake_run)
    result = pkinit.PkinitAuth().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        force=True,
        sam="alice",
    )
    assert result["ok"] is True
    assert result["method"] == "certipy"
    assert result["ccache"].endswith("alice.ccache")


def test_pkinit_auth_certipy_missing(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    _make_pem_pair(session, "alice")

    def boom(cmd: list[str], **kwargs: Any) -> Any:
        raise FileNotFoundError

    monkeypatch.setattr(pkinit.subprocess, "run", boom)
    result = pkinit.PkinitAuth().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        force=True,
        sam="alice",
    )
    assert result["method"] in {"certipy-missing", "impacket"}
    assert result["ok"] is False
    assert Path(result["playbook"]).is_file()


def test_pkinit_auth_certipy_nonzero(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    _make_pem_pair(session, "alice")

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        return SimpleNamespace(returncode=2, stdout="", stderr="denied")

    monkeypatch.setattr(pkinit.subprocess, "run", fake_run)
    result = pkinit.PkinitAuth().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        force=True,
        sam="alice",
    )
    assert result["ok"] is False
    assert Path(result["playbook"]).is_file()


def test_pkinit_auth_certipy_zero_no_ccache(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    _make_pem_pair(session, "alice")

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(pkinit.subprocess, "run", fake_run)
    result = pkinit.PkinitAuth().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        force=True,
        sam="alice",
    )
    # No ccache file → ok=True but no 'ccache' key
    assert result["ok"] is True
    assert "ccache" not in result


def test_pkinit_auth_certipy_generic_error(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    _make_pem_pair(session, "alice")

    def boom(cmd: list[str], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="certipy", timeout=120)

    monkeypatch.setattr(pkinit.subprocess, "run", boom)
    result = pkinit.PkinitAuth().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        force=True,
        sam="alice",
    )
    assert result["method"] in {"certipy-error", "impacket"}
    assert "error_certipy" in result or "error" in result


def test_pkinit_auth_find_shadow_by_glob(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    _make_pem_pair(session, "sqlsvc")

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        return SimpleNamespace(returncode=1, stdout="", stderr="deny")

    monkeypatch.setattr(pkinit.subprocess, "run", fake_run)
    result = pkinit.PkinitAuth().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        force=True,
        # no sam → should discover via glob
    )
    assert result["sam"] == "sqlsvc"


# --------------------------- shadow_creds write ---------------------------


class _Attr:
    def __init__(self, value: Any = None, values: list[Any] | None = None) -> None:
        self.value = value
        self.values = values if values is not None else ([] if value is None else [value])

    def __bool__(self) -> bool:
        return self.value is not None or bool(self.values)

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **values: Any) -> None:
        self._values = {key: _Attr(value) for key, value in values.items()}

    def __getattr__(self, name: str) -> _Attr:
        return self._values.get(name, self._values.get(name.replace("-", "_"), _Attr()))

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _ShadowWriteConn:
    def __init__(self, *, modify_ok: bool = True, missing: bool = False) -> None:
        self.entries: list[_Entry] = []
        self.unbound = False
        self.modify_ok = modify_ok
        self.missing = missing
        self.result = "success"
        self.modified: list[Any] = []

    def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
        if "KeyCredentialLink=*" in search_filter:
            self.entries = []
        elif "sAMAccountName=" in search_filter:
            if self.missing:
                self.entries = []
            else:
                self.entries = [
                    _Entry(
                        distinguishedName="CN=krbtgt,DC=corp,DC=test",
                        msDS_KeyCredentialLink=[],
                    )
                ]
        else:
            self.entries = []

    def modify(self, dn: str, changes: Any) -> bool:
        self.modified.append((dn, changes))
        self.result = "success" if self.modify_ok else "denied"
        return self.modify_ok

    def unbind(self) -> None:
        self.unbound = True


def test_shadow_creds_write_success(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _ShadowWriteConn()
    monkeypatch.setattr(shadow, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(shadow, "fetch_sd", lambda c, dn: None)
    session = Session(base_dir=tmp_path)
    result = shadow.ShadowCreds().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        force=True,
        write_target="krbtgt",
    )
    attempt = result["write_attempt"]
    assert attempt["ok"] is True
    assert attempt["ldap_written"] is True
    assert Path(attempt["key_pem"]).is_file()
    assert Path(attempt["cert_pem"]).is_file()


def test_shadow_creds_write_account_not_found(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _ShadowWriteConn(missing=True)
    monkeypatch.setattr(shadow, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(shadow, "fetch_sd", lambda c, dn: None)
    result = shadow.ShadowCreds().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path),
        AttackGraph(),
        force=True,
        write_target="nobody",
    )
    assert result["write_attempt"]["ok"] is False
    assert "not found" in result["write_attempt"]["error"]


def test_shadow_creds_write_modify_failure(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _ShadowWriteConn(modify_ok=False)
    monkeypatch.setattr(shadow, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(shadow, "fetch_sd", lambda c, dn: None)
    result = shadow.ShadowCreds().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path),
        AttackGraph(),
        force=True,
        write_target="krbtgt",
    )
    attempt = result["write_attempt"]
    assert attempt["ok"] is False


def test_shadow_creds_write_exception(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _ShadowWriteConn()
    monkeypatch.setattr(shadow, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(shadow, "fetch_sd", lambda c, dn: None)

    def boom(sam: str, dn: str) -> Any:
        raise ValueError("cannot generate")

    import adaf_attack.core.keycred as keycred_mod

    monkeypatch.setattr(keycred_mod, "generate_shadow_material", boom)
    result = shadow.ShadowCreds().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path),
        AttackGraph(),
        force=True,
        write_target="krbtgt",
    )
    assert result["write_attempt"]["ok"] is False
    assert "cannot generate" in result["write_attempt"]["error"]


# --------------------------- ticket_lifecycle ---------------------------


@pytest.fixture()
def _vault_key(monkeypatch: Any) -> None:
    from cryptography.fernet import Fernet

    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())


def test_ticket_lifecycle_inventory(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    session.path("tgt.ccache").write_bytes(b"tk")
    session.path("cert.pfx").write_bytes(b"pf")
    result = TicketLifecycle().run(
        Target(domain="corp.test", dc_ip="1.1.1.1"), session, AttackGraph()
    )
    assert "tgt.ccache" in result["artifacts"] and "cert.pfx" in result["artifacts"]


def test_ticket_lifecycle_import_and_export_ccache(_vault_key: None, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    src = tmp_path / "src.ccache"
    src.write_bytes(b"cc")
    imported = TicketLifecycle().run(
        Target(domain="corp.test", dc_ip="1.1.1.1"),
        session,
        AttackGraph(),
        operation="import-ccache",
        artifact=str(src),
    )
    assert Path(imported["ccache"]).is_file()
    exported = TicketLifecycle().run(
        Target(domain="corp.test", dc_ip="1.1.1.1"),
        session,
        AttackGraph(),
        operation="export-ccache",
    )
    assert Path(exported["ccache"]).is_file()


def test_ticket_lifecycle_import_and_export_pfx(_vault_key: None, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    src = tmp_path / "src.pfx"
    src.write_bytes(b"pf")
    imported = TicketLifecycle().run(
        Target(domain="corp.test", dc_ip="1.1.1.1"),
        session,
        AttackGraph(),
        operation="import-pfx",
        artifact=str(src),
    )
    assert Path(imported["pfx"]).is_file()
    exported = TicketLifecycle().run(
        Target(domain="corp.test", dc_ip="1.1.1.1"),
        session,
        AttackGraph(),
        operation="export-pfx",
    )
    assert Path(exported["pfx"]).is_file()


def test_ticket_lifecycle_pem_and_pfx_conversion(_vault_key: None, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    _make_pem_pair(session, "conv")
    key = session.path("shadow-conv.key.pem")
    cert = session.path("shadow-conv.cert.pem")
    to_pfx = TicketLifecycle().run(
        Target(domain="corp.test", dc_ip="1.1.1.1"),
        session,
        AttackGraph(),
        operation="pem-to-pfx",
        artifact=f"{key},{cert}",
    )
    assert Path(to_pfx["pfx"]).is_file()
    to_pem = TicketLifecycle().run(
        Target(domain="corp.test", dc_ip="1.1.1.1"),
        session,
        AttackGraph(),
        operation="pfx-to-pem",
        artifact=to_pfx["pfx"],
    )
    assert Path(to_pem["key"]).is_file() and Path(to_pem["cert"]).is_file()


def test_ticket_lifecycle_error_paths(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    with pytest.raises(RuntimeError, match="existing ccache"):
        TicketLifecycle().run(
            Target(domain="c", dc_ip="1.1.1.1"),
            session,
            AttackGraph(),
            operation="import-ccache",
            artifact="",
        )
    with pytest.raises(RuntimeError, match="existing PFX"):
        TicketLifecycle().run(
            Target(domain="c", dc_ip="1.1.1.1"),
            session,
            AttackGraph(),
            operation="import-pfx",
        )
    with pytest.raises(RuntimeError, match="key.pem>,<cert.pem"):
        TicketLifecycle().run(
            Target(domain="c", dc_ip="1.1.1.1"),
            session,
            AttackGraph(),
            operation="pem-to-pfx",
            artifact="only-one-file",
        )
    with pytest.raises(RuntimeError, match="key or certificate"):
        TicketLifecycle().run(
            Target(domain="c", dc_ip="1.1.1.1"),
            session,
            AttackGraph(),
            operation="pem-to-pfx",
            artifact="a.key,b.cert",
        )
    with pytest.raises(RuntimeError, match="Unsupported operation"):
        TicketLifecycle().run(
            Target(domain="c", dc_ip="1.1.1.1"),
            session,
            AttackGraph(),
            operation="unknown-op",
        )


# --------------------------- gmsa/laps secrets branches ---------------------------


class _GmsaConn:
    def __init__(self, blob: bytes) -> None:
        self.entries: list[_Entry] = []
        self.unbound = False
        self.blob = blob

    def search(self, base_dn: str, query: str, **kwargs: Any) -> None:
        if query == gmsa.GMSA_FILTER:
            self.entries = [
                _Entry(
                    sAMAccountName="svc$",
                    distinguishedName="CN=svc,DC=corp,DC=test",
                    msDS_ManagedPasswordInterval=30,
                    msDS_ManagedPassword=self.blob,
                )
            ]
        else:
            self.entries = [
                _Entry(
                    sAMAccountName="WEB01$",
                    distinguishedName="CN=WEB01,DC=corp,DC=test",
                    ms_Mcs_AdmPwd="LegacyPwd",
                    msLAPS_Password='{"n":"admin","p":"secret"}',
                    msLAPS_EncryptedPassword=b"\x00" * 32,
                )
            ]

    def unbind(self) -> None:
        self.unbound = True


def _build_managed_password_blob(current: str, previous: str) -> bytes:
    """Build a minimal MSDS-MANAGEDPASSWORD_BLOB with current/previous passwords."""
    header_len = 16
    cur = current.encode("utf-16-le") + b"\x00\x00"
    prev = previous.encode("utf-16-le") + b"\x00\x00"
    cur_off = header_len
    prev_off = cur_off + len(cur)
    total = prev_off + len(prev)
    header = struct.pack("<HHIHHHH", 1, 0, total, cur_off, prev_off, 0, 0)
    return header + cur + prev


def test_gmsa_laps_secret_paths(monkeypatch: Any, tmp_path: Path) -> None:
    blob = _build_managed_password_blob("CurrPwd!", "PrevPwd!")
    conn = _GmsaConn(blob)
    monkeypatch.setattr(gmsa, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gmsa, "fetch_sd", lambda c, dn: None)
    result = gmsa.GmsaLapsEnum().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path),
        AttackGraph(),
        include_secrets=True,
    )
    assert result["secrets_returned"] >= 3
    assert result["gmsas"][0]["managed_password"]["current_password"] == "CurrPwd!"
    laps = result["laps_computers"][0]
    assert laps["ms_mcs_admpwd"] == "LegacyPwd"
    assert "mslaps_password" in laps
    assert laps["mslaps_encrypted_present"] is True


# --------------------------- core/acl parsing ---------------------------


def test_guid_bytes_helper_fallback_and_valid() -> None:
    assert _guid_bytes_to_str(b"abc") == b"abc".hex()
    assert len(_guid_bytes_to_str(b"\x00" * 16)) == 36


def test_sid_to_str_fallback_when_impacket_import_fails(monkeypatch: Any) -> None:
    import sys as _sys

    monkeypatch.setitem(_sys.modules, "impacket.ldap.ldaptypes", None)
    # 16-byte SID: revision=1, subauth_count=2, authority=5, subs=[21, 42]
    payload = (
        bytes([1, 2])
        + (5).to_bytes(6, "big")
        + (21).to_bytes(4, "little")
        + (42).to_bytes(4, "little")
    )
    assert _sid_to_str(payload) == "S-1-5-21-42"
    # too-short → hex fallback
    assert _sid_to_str(b"\x01\x02") == "0102"


def test_mask_to_rights_covers_extended_and_property_rights() -> None:
    from adaf_attack.core.acl import (
        ADS_RIGHT_DS_CONTROL_ACCESS,
        GUID_CERTIFICATE_AUTOENROLLMENT,
        GUID_CERTIFICATE_ENROLLMENT,
        GUID_DS_REPLICATION_GET_CHANGES,
        GUID_FORCE_CHANGE_PASSWORD,
        READ_PROPERTY,
        WRITE_PROPERTY,
    )

    # Extended right + specific GUIDs
    assert "ForceChangePassword" in _mask_to_rights(
        ADS_RIGHT_DS_CONTROL_ACCESS, GUID_FORCE_CHANGE_PASSWORD
    )
    assert "GetChanges" in _mask_to_rights(
        ADS_RIGHT_DS_CONTROL_ACCESS, GUID_DS_REPLICATION_GET_CHANGES
    )
    assert "Enroll" in _mask_to_rights(ADS_RIGHT_DS_CONTROL_ACCESS, GUID_CERTIFICATE_ENROLLMENT)
    assert "AutoEnroll" in _mask_to_rights(
        ADS_RIGHT_DS_CONTROL_ACCESS, GUID_CERTIFICATE_AUTOENROLLMENT
    )
    assert "AllExtendedRights" in _mask_to_rights(ADS_RIGHT_DS_CONTROL_ACCESS, None)
    # Read-only property
    assert _mask_to_rights(READ_PROPERTY, None) == ["ReadProperty"]
    # WriteProperty when no other rights present
    assert "WriteProperty" in _mask_to_rights(WRITE_PROPERTY, None)


def test_parse_interesting_aces_on_real_sd() -> None:
    sd = build_allowed_to_act_sd("S-1-5-21-1-2-3-1105")
    aces = parse_interesting_aces(sd)
    assert any(a.right == "GenericAll" for a in aces)
    assert any(a.principal_sid == "S-1-5-21-1-2-3-1105" for a in aces)


def test_parse_interesting_aces_import_failure(monkeypatch: Any) -> None:
    import sys as _sys

    monkeypatch.setitem(_sys.modules, "impacket.ldap.ldaptypes", None)
    with pytest.raises(RuntimeError, match="ACL parsing requires Impacket"):
        parse_interesting_aces(b"\x00" * 20)


# --------------------------- fetch_sd ---------------------------


class _SdEntry:
    def __init__(self, present: bool = True) -> None:
        self._present = present
        self.nTSecurityDescriptor = SimpleNamespace(
            raw_values=[b"sdbytes"] if present else [], __bool__=lambda: present
        )

    def __bool__(self) -> bool:
        return True


class _SdConn:
    def __init__(self, entries: list[Any], ok: bool = True) -> None:
        self.entries = entries
        self._ok = ok

    def search(self, dn: str, filt: str, **kwargs: Any) -> bool:
        return self._ok


def test_fetch_sd_returns_bytes_or_none() -> None:
    class _E:
        class _NS:
            raw_values = [b"desc"]

            def __bool__(self) -> bool:
                return True

        nTSecurityDescriptor = _NS()

    conn = _SdConn([_E()], ok=True)
    assert fetch_sd(conn, "CN=x") == b"desc"

    empty = _SdConn([], ok=True)
    assert fetch_sd(empty, "CN=x") is None

    class _EmptyE:
        nTSecurityDescriptor = None

    conn2 = _SdConn([_EmptyE()], ok=True)
    assert fetch_sd(conn2, "CN=x") is None
