"""Behavioral tests."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from typer.testing import CliRunner

import adaf_attack.capabilities.coerce as coerce
import adaf_attack.capabilities.impacket_exec as impacket_exec
import adaf_attack.capabilities.unpac_the_hash as unpac
import adaf_attack.cli as cli
import adaf_attack.core.impacket_helper as impacket_helper
import adaf_attack.core.reporting as reporting
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def _target(**kwargs: Any) -> Target:
    values = {"domain": "corp.test", "dc_ip": "10.0.0.1", "username": "alice", "password": "secret"}
    values.update(kwargs)
    return Target(**values)


def test_cli_pure_helpers_cover_time_sizes_paths_and_params(tmp_path: Path) -> None:
    assert cli._workspace_is_empty(tmp_path)
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    (session_dir / "session.json").write_text("{}")
    assert not cli._workspace_is_empty(tmp_path)
    assert cli._humanize_bytes(1) == "1 B"
    assert cli._humanize_bytes(1024) == "1.0 KB"
    assert cli._humanize_bytes(1024**5) == "1024.0 TB"
    assert cli._humanize_since(None) == "unknown"
    assert cli._humanize_since("not-a-date") == "not-a-date"
    for text in ("1s", "2m", "3h", "4d", "2026-08-01", "2026-08-01T00:00:00Z"):
        assert isinstance(cli._parse_since(text), datetime)
    with pytest.raises(cli.typer.BadParameter):
        cli._parse_since("")
    with pytest.raises(cli.typer.BadParameter):
        cli._parse_since("nonsense")
    assert cli._path_status(tmp_path)[0]
    assert cli._path_status(tmp_path / "new")[0] is False
    assert cli._parse_extra_params(None) == {}
    assert cli._parse_extra_params(["a=1", "b="]) == {"a": "1", "b": ""}
    with pytest.raises(cli.typer.BadParameter):
        cli._parse_extra_params(["bad"])
    with pytest.raises(cli.typer.BadParameter):
        cli._parse_extra_params(["=bad"])


def test_cli_error_and_alias_commands(monkeypatch: Any, tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli.app, ["--format", "json", "errors", "NOPE"])
    assert result.exit_code != 0 and "UNKNOWN_ERROR_CODE" in result.stdout
    result = runner.invoke(cli.app, ["--format", "json", "errors"])
    assert result.exit_code == 0 and '"ok": true' in result.stdout.lower()
    result = runner.invoke(cli.app, ["--format", "json", "config", "keys"])
    assert result.exit_code == 0
    graph = tmp_path / "graph.json"
    graph.write_text(json.dumps({"nodes": [], "edges": []}))
    result = runner.invoke(cli.app, ["--format", "json", "path", "rank", "--graph", str(graph)])
    assert result.exit_code == 0
    result = runner.invoke(cli.app, ["--format", "json", "capability", "show"])
    assert result.exit_code == 0


def test_impacket_helper_authentication_modes(monkeypatch: Any) -> None:
    module = ModuleType("impacket.smbconnection")

    class Conn:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

        def kerberosLogin(self, *args: Any, **kwargs: Any) -> None:
            self.calls.append(("kerb", args, kwargs))

        def login(self, *args: Any, **kwargs: Any) -> None:
            self.calls.append(("login", args, kwargs))

    module.SMBConnection = Conn
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", module)
    monkeypatch.setattr(impacket_helper, "require_impacket", lambda feature: None)
    for target in (
        _target(use_kerberos=True),
        _target(aes_key="aes"),
        _target(hashes=":aa"),
        _target(password="pw"),
    ):
        conn = impacket_helper.smb_connect("10.0.0.2", target)
        assert conn.calls
    assert "requires Impacket" in str(impacket_helper.ImpacketMissing("feature"))


def test_coerce_request_builders_cover_all_methods(monkeypatch: Any) -> None:
    efsr = ModuleType("impacket.dcerpc.v5.efsr")
    rprn = ModuleType("impacket.dcerpc.v5.rprn")

    class Request(dict[str, Any]):
        pass

    efsr.EfsRpcOpenFileRaw = Request
    rprn.RpcRemoteFindFirstPrinterChangeNotificationEx = Request
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.efsr", efsr)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rprn", rprn)
    for method in coerce.METHODS:
        request = coerce._build_coercion_request(method, r"\\listener\pwn\x")
        assert request is not None
    with pytest.raises(ValueError):
        coerce._build_coercion_request("unknown", "x")


def test_impacket_exec_all_methods_and_subprocess_helpers(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    monkeypatch.setattr(impacket_exec, "require_impacket", lambda feature: None)
    monkeypatch.setattr(impacket_exec, "_run_wmiexec", lambda *args: {"pid": 1})
    result = impacket_exec.ImpacketExec().run(
        _target(), session, AttackGraph(), force=True, command="whoami"
    )
    assert result["outcome"]["pid"] == 1
    for method in ("smbexec", "dcomexec", "atexec"):
        result = impacket_exec.ImpacketExec().run(
            _target(), session, AttackGraph(), force=True, method=method, command="whoami"
        )
        assert result["method"] == method
    with pytest.raises(RuntimeError, match="unknown method"):
        impacket_exec.ImpacketExec().run(
            _target(), session, AttackGraph(), force=True, method="bad", command="x"
        )
    with pytest.raises(RuntimeError, match="command"):
        impacket_exec.ImpacketExec().run(_target(), session, AttackGraph(), force=True)


def test_reporting_pdf_and_document_branches(monkeypatch: Any, tmp_path: Path) -> None:
    reportlab = ModuleType("reportlab")
    lib = ModuleType("reportlab.lib")
    pagesizes = ModuleType("reportlab.lib.pagesizes")
    styles = ModuleType("reportlab.lib.styles")
    platypus = ModuleType("reportlab.platypus")
    pagesizes.letter = (612, 792)
    styles.getSampleStyleSheet = lambda: {
        "Title": object(),
        "Heading2": object(),
        "BodyText": object(),
    }

    class Paragraph:
        def __init__(self, *args: Any) -> None:
            pass

    class Spacer:
        def __init__(self, *args: Any) -> None:
            pass

    class SimpleDocTemplate:
        def __init__(self, path: str, **kwargs: Any) -> None:
            self.path = path

        def build(self, parts: list[Any]) -> None:
            Path(self.path).write_bytes(b"%PDF-1.4 fake")

    platypus.Paragraph, platypus.Spacer, platypus.SimpleDocTemplate = (
        Paragraph,
        Spacer,
        SimpleDocTemplate,
    )
    reportlab.lib, reportlab.platypus = lib, platypus
    lib.pagesizes, lib.styles = pagesizes, styles
    for name, module in {
        "reportlab": reportlab,
        "reportlab.lib": lib,
        "reportlab.lib.pagesizes": pagesizes,
        "reportlab.lib.styles": styles,
        "reportlab.platypus": platypus,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    finding = {
        "severity": "high",
        "title": "Title",
        "impact": "Impact",
        "remediation": "Fix",
        "evidence": [{"artifact": "a", "pointer": "p"}],
        "attack_techniques": ["T1"],
    }
    assert "Title" in reporting._document("Title", "Sub", "Body")
    assert reporting._pdf(tmp_path / "technical.pdf", "T", [finding], "technical")
    assert reporting._pdf(tmp_path / "remediation.pdf", "T", [finding], "remediation")
    assert reporting._pdf(tmp_path / "executive.pdf", "T", [finding], "executive")


def test_unpac_pac_parser_handles_imported_blob(monkeypatch: Any) -> None:
    pac = ModuleType("impacket.krb5.pac")

    class PacType:
        def __init__(self, data: bytes) -> None:
            self.data = data
            self.buffers = [{"Offset": 0, "cbBufferSize": 2}]

        def __getitem__(self, key: str) -> Any:
            if key == "cBuffers":
                return 1
            return self.buffers

    class Info:
        def __init__(self, data: bytes) -> None:
            self.data = data

        def __getitem__(self, key: str) -> Any:
            return 2 if key == "ulType" else (0 if key == "Offset" else 2)

        def __len__(self) -> int:
            return 1

    pac.PAC_CREDENTIAL_INFO = lambda data: object()
    pac.PAC_INFO_BUFFER = Info
    pac.PACTYPE = PacType
    monkeypatch.setitem(sys.modules, "impacket.krb5.pac", pac)
    assert unpac._extract_nt_from_pac(b"blob") == {
        "status": "not_recovered",
        "reason": "PAC_CREDENTIAL_INFO present; pass asrep_key to decrypt",
    }


def test_remaining_capability_guards_and_helpers(monkeypatch: Any, tmp_path: Path) -> None:
    from adaf_attack.capabilities import (
        acl_write,
        ad_cve_scan,
        asreq_userhunt,
        computer_takeover,
        esc_chain,
        gpo_link,
        gpp_cpassword,
        s4u_abuse,
        sysvol_hunt,
        ticket_forge,
    )
    from adaf_attack.core import adcs_analyze, auth, gpp, redaction, target, user_config

    session = Session(base_dir=tmp_path)
    graph = AttackGraph()
    t = _target()

    class EmptyConn:
        entries: list[Any] = []

        def search(self, *args: Any, **kwargs: Any) -> None:
            return None

        def unbind(self) -> None:
            return None

    assert ad_cve_scan._check_noPAC(EmptyConn(), "DC=x") == {"error": "krbtgt not visible"}
    assert ad_cve_scan._check_functional_level(EmptyConn(), "DC=x") == {
        "error": "domain object not visible"
    }
    monkeypatch.setattr(ad_cve_scan, "ldap_connect", lambda _: (EmptyConn(), "DC=x", None))
    with pytest.raises(RuntimeError, match="configuration naming"):
        ad_cve_scan.AdCveScan().run(t, session, graph)

    with pytest.raises(RuntimeError, match="write-target"):
        acl_write.AclWrite().run(t, session, graph, force=True)
    with pytest.raises(RuntimeError, match="user list not found"):
        asreq_userhunt.AsreqUserhunt().run(t, session, graph, users=str(tmp_path / "missing"))
    with pytest.raises(RuntimeError, match="Pass -P users"):
        asreq_userhunt.AsreqUserhunt().run(t, session, graph)
    monkeypatch.setattr(computer_takeover, "ldap_connect", lambda _: (EmptyConn(), "DC=x", None))
    with pytest.raises(RuntimeError, match="Computer target"):
        computer_takeover.ComputerTakeover().run(
            t,
            session,
            graph,
            write_target="missing",
            attribute="dNSHostName",
            value="x",
            force=True,
        )
    assert esc_chain._pick_template({}) is None
    with pytest.raises(RuntimeError, match="adcs_session"):
        esc_chain.EscChain().run(t, session, graph)
    monkeypatch.setattr(gpo_link, "ldap_connect", lambda _: (EmptyConn(), "DC=x", None))
    with pytest.raises(RuntimeError, match="GPO link target"):
        gpo_link.GpoLink().run(t, session, graph, write_target="missing", value="x", force=True)
    with pytest.raises(RuntimeError, match="directory"):
        gpp_cpassword.GppCpasswordHunt().run(t, session, graph, root=str(tmp_path / "missing"))
    with pytest.raises(RuntimeError, match="requires --username"):
        s4u_abuse.S4uAbuse().run(
            target.Target(domain="corp.test", dc_ip="10.0.0.1"),
            session,
            graph,
            impersonate="administrator",
            spn="cifs/dc.corp.test",
        )
    with pytest.raises(RuntimeError, match="artifact"):
        sysvol_hunt.SysvolHunt().run(t, session, graph, artifact=str(tmp_path / "missing"))
    for kwargs, message in (
        ({"impersonate": "alice"}, "Provide -P nt"),
        ({"impersonate": "alice", "nt": "aa"}, "domain_sid"),
    ):
        with pytest.raises(RuntimeError, match=message):
            ticket_forge.TicketForge().run(t, session, graph, **kwargs)

    assert adcs_analyze.analyze_template_flags(application_policies=["Client Authentication"])[
        "client_auth_eku"
    ]
    with pytest.raises(RuntimeError, match="--username"):
        auth.get_kerberos_tgt(target.Target(domain="corp.test", dc_ip="10.0.0.1", password="x"))
    with pytest.raises(ValueError, match="Unknown redaction"):
        redaction.redact({}, profile="missing")
    assert target.Target(domain="corp.test", dc_ip="10.0.0.1").auth_user is None
    assert target.Target(domain="corp.test", dc_ip="10.0.0.1").resolved_ccache() is None
    monkeypatch.setattr(user_config, "load_user_config", lambda: {"x": 1})
    assert user_config.get_key("x") == 1
    bad = tmp_path / "bad.xml"
    bad.write_text('<Groups><User name="x" cpassword="bad"/></Groups>', encoding="utf-8")
    assert any("error" in item for item in gpp.parse_gpp_file(bad))


def test_mocked_remote_adapters(monkeypatch: Any) -> None:
    smb_mod = ModuleType("impacket.smbconnection")

    class Smb:
        def __init__(self, *args: Any) -> None:
            pass

        def getServerName(self) -> str:
            return "DC"

        def isSigningRequired(self) -> bool:
            return True

        def close(self) -> None:
            return None

    smb_mod.SMBConnection = Smb
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", smb_mod)
    import adaf_attack.capabilities.ad_cve_scan as cve

    assert cve._check_smb_signing("10.0.0.1")["signing_required"]

    examples = ModuleType("impacket.examples")
    smbexec = ModuleType("impacket.examples.smbexec")

    class Cmd:
        def __init__(self, *args: Any) -> None:
            self.finished = False

        def run(self, host: str) -> None:
            assert host

        def finish(self) -> None:
            self.finished = True

    smbexec.CMDEXEC = Cmd
    monkeypatch.setitem(sys.modules, "impacket.examples", examples)
    monkeypatch.setitem(sys.modules, "impacket.examples.smbexec", smbexec)
    assert "note" in impacket_exec._run_smbexec(_target(hashes=":aa"), "dc", "whoami", "C$")

    dcom = ModuleType("impacket.dcerpc.v5.dcom")
    dcomrt = ModuleType("impacket.dcerpc.v5.dcomrt")
    dtypes = ModuleType("impacket.dcerpc.v5.dtypes")
    wmi = ModuleType("impacket.dcerpc.v5.dcom.wmi")
    wmi.CLSID_WbemLevel1Login = "clsid"
    wmi.IID_IWbemLevel1Login = "iid"
    dtypes.NULL = None

    class Process:
        ReturnValue, ProcessId = 0, 42

        def Create(self, *args: Any) -> Any:
            return self

    class Services:
        def GetObject(self, name: str) -> tuple[Process, None]:
            return Process(), None

    class Login:
        def __init__(self, interface: Any) -> None:
            pass

        def NTLMLogin(self, *args: Any) -> Services:
            return Services()

        def RemRelease(self) -> None:
            return None

    wmi.IWbemLevel1Login = Login

    class Dcom:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def CoCreateInstanceEx(self, *args: Any) -> object:
            return object()

        def disconnect(self) -> None:
            return None

    dcomrt.DCOMConnection = Dcom
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.dcom", dcom)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.dcom.wmi", wmi)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.dcomrt", dcomrt)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.dtypes", dtypes)
    assert impacket_exec._run_wmiexec(_target(), "dc", "whoami")["pid"] == 42

    rpcrt = ModuleType("impacket.dcerpc.v5.rpcrt")
    transport = ModuleType("impacket.dcerpc.v5.transport")

    class Dce:
        def connect(self) -> None:
            pass

        def bind(self, value: Any) -> None:
            pass

        def request(self, request: Any) -> None:
            raise RuntimeError("STATUS_BAD_NETWORK_NAME")

        def disconnect(self) -> None:
            pass

    class Transport:
        def set_credentials(self, *args: Any) -> None:
            pass

        def set_kerberos(self, *args: Any, **kwargs: Any) -> None:
            pass

        def get_dce_rpc(self) -> Dce:
            return Dce()

    transport.DCERPCTransportFactory = lambda binding: Transport()
    rpcrt.uuidtup_to_bin = lambda value: b"uuid"
    import impacket.dcerpc.v5 as v5

    monkeypatch.setattr(v5, "rpcrt", rpcrt, raising=False)
    monkeypatch.setattr(v5, "transport", transport, raising=False)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rpcrt", rpcrt)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.transport", transport)
    monkeypatch.setattr(coerce, "_build_coercion_request", lambda method, listener: {})
    assert coerce._trigger(_target(use_kerberos=True), "dc", "listener", "petitpotam")["ok"]


def test_small_remaining_branches(monkeypatch: Any, tmp_path: Path) -> None:
    from adaf_attack.capabilities import (
        acl_enum,
        acl_write,
        gpo_sysvol,
        laps_read,
        next_actions,
        password_spray,
        shadow_creds,
    )
    from adaf_attack.core import control_plane, esc6_probe, findings, graph, registry, roast_format

    class Conn:
        entries: list[Any] = []
        result: dict[str, Any] = {}

        def search(self, *args: Any, **kwargs: Any) -> None:
            pass

        def unbind(self) -> None:
            pass

        def modify(self, *args: Any, **kwargs: Any) -> bool:
            return False

    t = _target()
    s = Session(base_dir=tmp_path)
    with pytest.raises(RuntimeError, match="security descriptor"):
        monkeypatch.setattr(acl_write, "ldap_connect", lambda _: (Conn(), "DC=x", None))
        monkeypatch.setattr(acl_write, "fetch_sd", lambda *args: None)
        acl_write.AclWrite().run(
            t, s, AttackGraph(), force=True, write_target="x", descriptor_hex="aa"
        )
    assert gpo_sysvol._parse_sysvol_unc("bad") is None
    assert laps_read._decode_v2_blob("not-a-blob").get("note") == "too-short"
    assert acl_enum._domain_targets(Conn(), "DC=x", "corp.test") is not None
    assert password_spray._filetime_to_dt(0) is None
    assert password_spray._account_lockout_state(Conn(), "DC=x", "missing") == (0, None)
    monkeypatch.setattr(
        password_spray,
        "Connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("bad")),
    )
    assert password_spray._try_bind(t, "x", "bad", False)[0] is False
    with pytest.raises(RuntimeError, match="spray_password"):
        password_spray.PasswordSpray().run(t, s, AttackGraph())
    assert next_actions.NextActions is not None
    assert shadow_creds._list_attr(Conn(), "missing") == []
    with pytest.raises(ValueError, match="Unknown OPSEC"):
        control_plane.resolve_opsec("missing")
    assert esc6_probe._parse_editflags("EditFlags: 0x2") == 2
    assert roast_format.format_tgs_hashcat("spn", "u", "d", object()) is None
    assert roast_format.format_asrep_hashcat("u", "d", object()) is None
    with pytest.raises(ValueError, match="already registered"):
        r = registry.CapabilityRegistry()
        cap = registry.Capability("x", "x", False, "x", (), None)
        r.register(cap)
        r.register(cap)
    assert graph.AttackGraph().find_node("missing") is None
    assert findings._load(tmp_path / "missing.json") is None


def test_cli_remaining_time_sessions_and_config_paths(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.cli as cli

    for seconds, suffix in ((1, "s ago"), (120, "m ago"), (7200, "h ago"), (172800, "d ago")):
        stamp = datetime.now(cli.UTC).timestamp() - seconds
        assert cli._humanize_since(datetime.fromtimestamp(stamp, cli.UTC).isoformat()).endswith(
            suffix
        )
    old = tmp_path / "old"
    old.mkdir()
    (old / "session.json").write_text('{"session_id":"old","created_at":"bad"}')
    current = tmp_path / "current"
    current.mkdir()
    (current / "session.json").write_text(
        '{"session_id":"current","created_at":"2026-08-08T00:00:00"}'
    )
    result = CliRunner().invoke(
        cli.app, ["--format", "json", "sessions", "--workspace", str(tmp_path), "--since", "1d"]
    )
    assert result.exit_code == 0, result.stdout
    monkeypatch.setattr(cli, "default_workspace_dir", lambda: tmp_path / "empty")
    monkeypatch.setattr(cli, "user_data_dir", lambda: tmp_path / "data")
    monkeypatch.setattr(cli, "user_config_dir", lambda: tmp_path / "config")
    result = CliRunner().invoke(cli.app, ["--format", "json", "doctor"])
    assert result.exit_code == 0, result.stdout


def test_cli_run_uses_saved_target_defaults_and_validates_required_options(
    monkeypatch: Any, tmp_path: Path
) -> None:
    import adaf_attack.cli as cli

    monkeypatch.setattr(
        cli,
        "load_user_config",
        lambda: {
            "target.domain": "corp.test",
            "target.dc_ip": "10.0.0.1",
            "target.username": "alice",
            "target.kerberos": True,
            "target.ldaps": True,
        },
    )
    monkeypatch.setattr(
        cli,
        "execute_capability",
        lambda *args, **kwargs: {"ok": True, "session_path": str(tmp_path)},
    )
    result = CliRunner().invoke(cli.app, ["--format", "json", "run", "report"])
    assert result.exit_code == 0, result.stdout
    monkeypatch.setattr(cli, "load_user_config", dict)
    result = CliRunner().invoke(cli.app, ["--format", "json", "run", "report"])
    assert result.exit_code != 0


def test_optional_ad_and_impacket_branches(monkeypatch: Any, tmp_path: Path) -> None:
    from adaf_attack.capabilities import asreq_userhunt, bloodhound_export, dcsync, esc_chain

    target = _target()
    session = Session(base_dir=tmp_path)
    graph = AttackGraph()

    users = tmp_path / "users.txt"
    users.write_text("alice\nbob\n", encoding="utf-8")
    monkeypatch.setattr(
        asreq_userhunt,
        "_probe_user",
        lambda user, domain, dc: {
            "user": user,
            "state": "asreproastable" if user == "alice" else "valid",
            "valid": True,
            "no_preauth": user == "alice",
        },
    )
    monkeypatch.setattr(asreq_userhunt, "require_impacket", lambda feature: None)
    result = asreq_userhunt.AsreqUserhunt().run(target, session, graph, users=users)
    assert result["valid"] == 2 and result["asreproastable"] == 1

    hydrated = Session(base_dir=tmp_path / "hydrated")
    hydrated.path("graph.json").write_text(
        '{"nodes":[{"id":"USER@ALICE@CORP.TEST","kind":"User"}],"edges":[]}',
        encoding="utf-8",
    )
    graph = AttackGraph()
    assert bloodhound_export._hydrate_graph_from_session(hydrated, graph)
    monkeypatch.setattr(bloodhound_export, "_hydrate_graph_from_session", lambda s, g: False)

    class Seed:
        def run(self, target, session, graph, **kwargs):
            graph.add_node("DOMAIN@CORP.TEST", "Domain")
            return {}

    import adaf_attack.capabilities.ldap_enum as ldap_enum

    monkeypatch.setattr(ldap_enum, "LdapEnum", Seed)
    result = bloodhound_export.BloodhoundExport().run(target, hydrated, AttackGraph())
    assert Path(result["json_path"]).is_file()

    with pytest.raises(RuntimeError, match="replicating"):
        dcsync.Dcsync().run(Target(domain="corp.test", dc_ip="10.0.0.1"), session, AttackGraph())

    prior = tmp_path / "adcs"
    prior.mkdir()
    (prior / "adcs-enum.json").write_text(
        '{"templates":[{"name":"UserTemplate","esc_signals":["ESC1"]}]}',
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match=r"template \+ CA"):
        esc_chain.EscChain().run(target, session, AttackGraph(), adcs_session=prior)


def test_additional_core_and_posture_branches(monkeypatch: Any, tmp_path: Path) -> None:
    from adaf_attack.core import adcs_analyze, control_plane, esc6_probe, gpp, graph, user_config

    monkeypatch.setattr(user_config, "user_config_dir", lambda: tmp_path / "config")
    result = adcs_analyze.analyze_template_flags(
        name_flags=adcs_analyze.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
        ekus=[adcs_analyze.EKU_ANY],
        enrollment_flags=adcs_analyze.CT_FLAG_PEND_ALL_REQUESTS,
    )
    assert "esc_tags" in result
    assert esc6_probe._parse_editflags("EditFlags: 0x00000010") == 16
    assert user_config.set_key("run.limit", "389")[1]["run.limit"] == 389
    unreadable = tmp_path / "directory"
    unreadable.mkdir()
    assert gpp.parse_gpp_file(unreadable)[0]["error"]
    root = tmp_path / "evidence"
    (root / "vault").mkdir(parents=True)
    (root / "keep.json").write_text("{}", encoding="utf-8")
    manifest = control_plane._manifest(root, "operator")
    assert all("vault" not in item["path"] for item in manifest["files"])
    g = graph.AttackGraph()
    g.add_node("USER@ALICE@CORP.TEST", "User", sam="ALICE")
    assert g.find_node("CORP") == "USER@ALICE@CORP.TEST"


def test_adapter_helpers_and_safe_fallbacks(monkeypatch: Any, tmp_path: Path) -> None:
    from adaf_attack.capabilities import (
        gpo_sysvol,
        gpp_cpassword,
        next_actions,
        ntlm_relay,
        password_spray,
        workflow_wrappers,
    )

    assert gpo_sysvol._parse_sysvol_unc(r"\\dc\SYSVOL\corp.test\Policies\{X}") == (
        "dc",
        "corp.test/Policies/{X}",
    )
    users = tmp_path / "users.txt"
    users.write_text("alice\n\n bob \n", encoding="utf-8")
    assert password_spray._load_users(str(users), object(), "DC=x", None) == ["alice", "bob"]

    class GoodConnection:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def unbind(self) -> None:
            pass

    monkeypatch.setattr(password_spray, "Connection", GoodConnection)
    assert password_spray._try_bind(_target(), "alice", "secret", False) == (True, "ok")
    with pytest.raises(RuntimeError, match="directory"):
        gpp_cpassword.GppCpasswordHunt().run(
            _target(),
            Session(base_dir=tmp_path / "gpp"),
            AttackGraph(),
            artifact=str(tmp_path / "missing"),
        )

    class HangingProcess:
        pid = 123
        returncode = None

        def wait(self, timeout: int) -> None:
            raise ntlm_relay.subprocess.TimeoutExpired("x", timeout)

        def terminate(self) -> None:
            return None

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(ntlm_relay.subprocess, "Popen", lambda *a, **k: HangingProcess())
    monkeypatch.setattr(ntlm_relay.shutil, "which", lambda name: "relay-bin")
    result = ntlm_relay.NtlmRelay().run(
        _target(),
        Session(base_dir=tmp_path / "relay"),
        AttackGraph(),
        force=True,
        relay_targets="dc",
    )
    assert result["return_code"] == -9
    assert next_actions.NextActions is not None

    monkeypatch.setattr(
        workflow_wrappers,
        "ShadowCreds",
        lambda: type("S", (), {"run": lambda *a, **k: {"ok": False}})(),
    )
    result = workflow_wrappers.ShadowPkinitWorkflow().run(
        _target(), Session(base_dir=tmp_path / "workflow"), AttackGraph(), force=True, sam="alice"
    )
    assert result["pkinit"]["skipped"] == "shadow_write_failed"


def test_asreq_and_roast_nested_ticket_branches() -> None:
    from adaf_attack.capabilities.asreq_userhunt import _classify_kdc_error
    from adaf_attack.core import roast_format

    assert _classify_kdc_error("unrecognized KDC response") == ("error", False, None)

    class Part:
        def __init__(self, values: dict[str, Any]):
            self.values = values

        def getComponentByName(self, name: str) -> Any:
            return self.values.get(name)

    inner = Part({"etype": 18, "cipher": b"0123456789abcdef"})
    ticket = Part({"enc-part": Part({"enc-part": inner})})
    cipher, etype = roast_format._extract_cipher_and_etype(ticket)
    assert cipher == b"0123456789abcdef" and etype == 18


def test_cli_spinner_execution_path(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.cli as cli

    calls: list[str] = []

    def fake_execute(*args: Any, **kwargs: Any) -> dict[str, Any]:
        kwargs["log"]("spinner update")
        calls.append(args[0])
        return {"ok": True}

    monkeypatch.setattr(cli, "execute_capability", fake_execute)
    import click
    from typer.main import get_command

    ctx = click.Context(get_command(cli.app))
    ctx.ensure_object(dict).update(output_format="human", no_color=True)
    result = cli._execute_with_spinner(
        ctx,
        "report",
        _target(),
        False,
        False,
        tmp_path,
        None,
        {},
    )
    assert result == {"ok": True} and calls == ["report"]


def test_asreq_impacket_error_classification_and_empty_pac(monkeypatch: Any) -> None:
    from adaf_attack.capabilities import asreq_userhunt, unpac_the_hash

    krb5 = ModuleType("impacket.krb5")
    constants = ModuleType("impacket.krb5.constants")
    kerberosv5 = ModuleType("impacket.krb5.kerberosv5")
    types = ModuleType("impacket.krb5.types")

    class KerberosError(Exception):
        pass

    class Principal:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

    constants.PrincipalNameType = type("P", (), {"NT_PRINCIPAL": type("N", (), {"value": 1})})
    types.Principal = Principal
    kerberosv5.KerberosError = KerberosError
    kerberosv5.getKerberosTGT = lambda *args: (_ for _ in ()).throw(
        KerberosError("KDC_ERR_PREAUTH_REQUIRED")
    )
    krb5.constants = constants
    krb5.kerberosv5 = kerberosv5
    krb5.types = types
    monkeypatch.setitem(sys.modules, "impacket.krb5", krb5)
    monkeypatch.setitem(sys.modules, "impacket.krb5.constants", constants)
    monkeypatch.setitem(sys.modules, "impacket.krb5.kerberosv5", kerberosv5)
    monkeypatch.setitem(sys.modules, "impacket.krb5.types", types)
    assert asreq_userhunt._probe_user("alice", "corp.test", "10.0.0.1")["valid"]
    kerberosv5.getKerberosTGT = lambda *args: (_ for _ in ()).throw(RuntimeError("unknown"))
    assert asreq_userhunt._probe_user("alice", "corp.test", "10.0.0.1")["state"] == "error"
    pac = ModuleType("impacket.krb5.pac")
    pac.PAC_CREDENTIAL_INFO = object
    pac.PAC_INFO_BUFFER = object
    pac.PACTYPE = lambda data: {"Buffers": []}
    monkeypatch.setitem(sys.modules, "impacket.krb5.pac", pac)
    assert unpac_the_hash._extract_nt_from_pac(b"no-buffer") is None
    monkeypatch.setenv("KRB5CCNAME", "old.ccache")
    with unpac_the_hash._temporary_krb5ccname("new.ccache"):
        assert unpac_the_hash.os.environ["KRB5CCNAME"] == "new.ccache"
    assert unpac_the_hash.os.environ["KRB5CCNAME"] == "old.ccache"


def test_remaining_capability_success_and_guard_branches(monkeypatch: Any, tmp_path: Path) -> None:
    from adaf_attack.capabilities import (
        cert_request,
        coerce,
        gpp_cpassword,
        password_spray,
        ticket_forge,
    )
    from adaf_attack.core import user_config

    missing_file = tmp_path / "not-a-directory.txt"
    missing_file.write_text("x", encoding="utf-8")
    with pytest.raises(RuntimeError, match="not a directory"):
        gpp_cpassword.GppCpasswordHunt().run(
            _target(), Session(base_dir=tmp_path / "gpp"), AttackGraph(), path=str(missing_file)
        )

    monkeypatch.setattr(ticket_forge, "require_impacket", lambda feature: None)
    with pytest.raises(RuntimeError, match="Silver tickets require"):
        ticket_forge.TicketForge().run(
            _target(),
            Session(base_dir=tmp_path / "ticket"),
            AttackGraph(),
            variant="silver",
            impersonate="alice",
            nt="aa",
            domain_sid="S-1-5-21-x",
        )

    monkeypatch.setattr(user_config, "user_config_dir", lambda: tmp_path / "config")
    _, values = user_config.set_key("target.ldaps", "true")
    assert values["target.ldaps"] is True

    class Conn:
        def unbind(self) -> None:
            return None

    monkeypatch.setattr(password_spray, "ldap_connect", lambda target: (Conn(), "DC=x", None))
    monkeypatch.setattr(
        password_spray,
        "_read_lockout_policy",
        lambda *args: {
            "lockout_threshold": 5,
            "observation_window_seconds": 30,
        },
    )
    monkeypatch.setattr(password_spray, "_load_users", lambda *args: ["alice", "bob"])
    monkeypatch.setattr(password_spray, "_account_lockout_state", lambda *args: (0, None))
    monkeypatch.setattr(password_spray, "_try_bind", lambda *args: (False, "invalid"))
    result = password_spray.PasswordSpray().run(
        _target(),
        Session(base_dir=tmp_path / "spray"),
        AttackGraph(),
        spray_password="Secret123!",
        max_attempts=1,
        delay_seconds=0,
    )
    assert len(result["attempts"]) == 1

    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(cert_request.subprocess, "run", lambda *args, **kwargs: Proc())
    cert_result = cert_request.CertRequest().run(
        _target(),
        Session(base_dir=tmp_path / "cert"),
        AttackGraph(),
        template="User",
        upn="alice@corp.test",
        ca="CA",
        force=True,
    )
    assert cert_result["ok"] is True and "pfx" not in cert_result

    class Dce:
        def connect(self) -> None:
            return None

        def bind(self, value: Any) -> None:
            return None

        def request(self, request: Any) -> None:
            return None

    class Transport:
        def set_credentials(self, *args: Any) -> None:
            return None

        def get_dce_rpc(self) -> Dce:
            return Dce()

    fake_transport = ModuleType("impacket.dcerpc.v5.transport")
    fake_transport.DCERPCTransportFactory = lambda binding: Transport()
    fake_rpcrt = ModuleType("impacket.dcerpc.v5.rpcrt")
    fake_rpcrt.uuidtup_to_bin = lambda value: value
    import impacket.dcerpc.v5 as v5

    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.transport", fake_transport)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rpcrt", fake_rpcrt)
    monkeypatch.setattr(v5, "transport", fake_transport, raising=False)
    monkeypatch.setattr(v5, "rpcrt", fake_rpcrt, raising=False)
    monkeypatch.setattr(coerce, "_build_coercion_request", lambda method, listener: object())
    assert coerce._trigger(_target(), "dc", "listener", "dfscoerce")["ok"] is True


def test_more_evidence_and_recommendation_branches(monkeypatch: Any, tmp_path: Path) -> None:
    from adaf_attack.capabilities import gpo_sysvol, next_actions, password_spray, sysvol_hunt
    from adaf_attack.core import findings, roast_format

    assert gpo_sysvol._parse_sysvol_unc("") is None
    mirror = tmp_path / "sysvol"
    mirror.mkdir()
    (mirror / "plain.xml").write_text("<Groups />", encoding="utf-8")
    result = sysvol_hunt.SysvolHunt().run(
        _target(),
        Session(base_dir=tmp_path / "sysvol-session"),
        AttackGraph(),
        artifact=str(mirror),
    )
    assert result["count"] == 0

    class Graph:
        nodes = {"x": {}}

        def rank_exploit_chains(self, limit: int) -> list[dict[str, Any]]:
            return [
                {"terminal_relation": "HasSPN", "impact": "roast", "score": 4},
                {"terminal_relation": "HasSPN", "impact": "duplicate", "score": 3},
                {"terminal_relation": "Unknown", "impact": "skip", "score": 1},
            ]

    actions = next_actions.NextActions().run(
        _target(), Session(base_dir=tmp_path / "actions"), Graph(), limit=10
    )
    assert actions["count"] == 2 and actions["actions"][0]["capability"] == "kerberoast"
    assert actions["actions"][1]["review_only"] is True

    sleeps: list[float] = []
    monkeypatch.setattr(
        password_spray,
        "time",
        type("T", (), {"sleep": staticmethod(lambda value: sleeps.append(value))}),
    )

    class Conn:
        def unbind(self) -> None:
            return None

    monkeypatch.setattr(password_spray, "ldap_connect", lambda target: (Conn(), "DC=x", None))
    monkeypatch.setattr(
        password_spray,
        "_read_lockout_policy",
        lambda *args: {
            "lockout_threshold": 0,
            "observation_window_seconds": 0,
        },
    )
    monkeypatch.setattr(password_spray, "_load_users", lambda *args: ["alice"])
    monkeypatch.setattr(password_spray, "_account_lockout_state", lambda *args: (0, None))
    monkeypatch.setattr(password_spray, "_try_bind", lambda *args: (False, "invalid"))
    with pytest.raises(RuntimeError, match="non-zero lockoutThreshold"):
        password_spray.PasswordSpray().run(
            _target(),
            Session(base_dir=tmp_path / "spray-delay"),
            AttackGraph(),
            spray_password="Secret123!",
            delay_seconds=0.01,
        )
    assert sleeps == []

    class Part:
        def getComponentByName(self, name: str) -> Any:
            return {"cipher": "6162", "etype": 17}.get(name)

    assert roast_format._extract_cipher_and_etype(type("T", (), {"encPart": Part()})())[0] == b"ab"

    finding_session = tmp_path / "findings-session"
    finding_session.mkdir()
    data = {
        "esc9_candidates": [{"template": "User"}],
        "esc10_candidates": [{"template": "Machine"}],
        "esc11_candidates": [{"template": "CA"}],
        "esc13_candidates": [{"template": "Alt"}],
    }
    (finding_session / "adcs-enum.json").write_text(json.dumps(data), encoding="utf-8")
    generated = findings.findings_from_session(finding_session)
    assert len(generated) >= 4
