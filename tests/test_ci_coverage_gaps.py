"""Offline coverage for the remaining error-path and guard branches.

Each test drives one specific defensive branch that is otherwise only reached
against a live directory, keeping the full-source coverage gate at 100% without
network access.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from typer.testing import CliRunner

import adaf_attack.cli as cli
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

runner = CliRunner()


def _target(**kwargs: Any) -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10", **kwargs)


# ---------------------------------------------------------------------------
# LDAP-style attribute/entry/connection doubles shared by several tests.
# ---------------------------------------------------------------------------
class _Attr:
    def __init__(self, value: Any = None, values: list[Any] | None = None) -> None:
        self.value = value
        self.values = values if values is not None else ([] if value is None else [value])
        self.raw_values = self.values

    def __bool__(self) -> bool:
        return self.value is not None or bool(self.values)

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **values: Any) -> None:
        self._values = {
            key: value if isinstance(value, _Attr) else _Attr(value)
            for key, value in values.items()
        }

    def __getattr__(self, name: str) -> _Attr:
        return self._values.get(name, self._values.get(name.replace("-", "_"), _Attr()))

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


# ---------------------------------------------------------------------------
# capabilities.acl_enum: security descriptor missing -> skip the object
# ---------------------------------------------------------------------------
def test_acl_enum_skips_targets_without_descriptor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import adaf_attack.capabilities.acl_enum as acl_enum

    class _Conn:
        def __init__(self) -> None:
            self.unbound = False

        def unbind(self) -> None:
            self.unbound = True

    conn = _Conn()
    monkeypatch.setattr(acl_enum, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(acl_enum, "_sid_index", lambda connection, base_dn: {})
    monkeypatch.setattr(
        acl_enum,
        "_high_value_targets",
        lambda connection, base_dn, domain: [("DOMAIN@CORP.TEST", "DC=corp,DC=test", "Domain")],
    )
    monkeypatch.setattr(acl_enum, "fetch_sd", lambda connection, dn: None)

    result = acl_enum.AclEnum().run(_target(), Session(tmp_path), AttackGraph())

    assert result["interesting_edge_count"] == 0
    assert conn.unbound is True


# ---------------------------------------------------------------------------
# capabilities.adcs_enum: RuntimeError from SD parse propagates
# ---------------------------------------------------------------------------
def test_adcs_enum_reraises_runtime_error_from_sd_parse(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import adaf_attack.capabilities.adcs_enum as adcs_enum

    class _Conn:
        def __init__(self, template: Any) -> None:
            self.template = template
            self.entries: list[Any] = []
            self.unbound = False

        def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
            self.entries = (
                [self.template] if search_filter == "(objectClass=pKICertificateTemplate)" else []
            )

        def unbind(self) -> None:
            self.unbound = True

    conn = _Conn(_Entry())
    monkeypatch.setattr(
        adcs_enum,
        "ldap_connect",
        lambda target: (conn, "DC=corp,DC=test", "CN=Configuration,DC=corp,DC=test"),
    )
    monkeypatch.setattr(
        adcs_enum,
        "_analyze_template",
        lambda entry: {"cn": "UserTemplate", "dn": "CN=UserTemplate,DC=corp,DC=test"},
    )
    monkeypatch.setattr(adcs_enum, "fetch_sd", lambda connection, dn: b"descriptor")
    monkeypatch.setattr(
        adcs_enum,
        "parse_interesting_aces",
        lambda sd: (_ for _ in ()).throw(RuntimeError("bad certificate descriptor")),
    )

    # The inner ``except RuntimeError: raise`` re-raises into the template
    # enumeration's outer guard, so the run completes without exposing templates.
    result = adcs_enum.AdcsEnum().run(_target(), Session(tmp_path), AttackGraph())
    assert result["templates"] == []


# ---------------------------------------------------------------------------
# capabilities.asreq_userhunt: unclassified KDC error stores the raw message
# ---------------------------------------------------------------------------
def test_asreq_probe_records_unclassified_kerberos_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from adaf_attack.capabilities import asreq_userhunt

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
        KerberosError("KDC_ERR_MYSTERY unmapped response")
    )
    krb5.constants = constants
    krb5.kerberosv5 = kerberosv5
    krb5.types = types
    monkeypatch.setitem(sys.modules, "impacket.krb5", krb5)
    monkeypatch.setitem(sys.modules, "impacket.krb5.constants", constants)
    monkeypatch.setitem(sys.modules, "impacket.krb5.kerberosv5", kerberosv5)
    monkeypatch.setitem(sys.modules, "impacket.krb5.types", types)

    record = asreq_userhunt._probe_user("alice", "corp.test", "10.0.0.1")
    assert record["state"] == "error"
    assert record["kdc_error"] == "KDC_ERR_MYSTERY unmapped response"


# ---------------------------------------------------------------------------
# capabilities.bloodhound_export: hydrate saved edges from a local graph
# ---------------------------------------------------------------------------
def test_bloodhound_hydrates_saved_edges(tmp_path: Path) -> None:
    from adaf_attack.capabilities import bloodhound_export

    session = Session(tmp_path)
    session.path("graph.json").write_text(
        json.dumps(
            {
                "nodes": [{"id": "A", "kind": "User"}, {"id": "B", "kind": "Group"}],
                "edges": [{"source": "A", "target": "B", "kind": "MemberOf"}],
            }
        ),
        encoding="utf-8",
    )
    graph = AttackGraph()
    assert bloodhound_export._hydrate_graph_from_session(session, graph) is True
    assert {edge.kind for edge in graph.edges} == {"MemberOf"}


# ---------------------------------------------------------------------------
# capabilities.coerce: unexpected RPC error reports ok=False
# ---------------------------------------------------------------------------
def test_coerce_trigger_reports_unexpected_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import adaf_attack.capabilities.coerce as coerce

    # Inject fake impacket submodules via sys.modules rather than importing the
    # real ones: importing them would bind the real submodules to the parent
    # package and leak into other tests that rely on these fakes.
    rpcrt = ModuleType("impacket.dcerpc.v5.rpcrt")
    transport = ModuleType("impacket.dcerpc.v5.transport")

    class _Dce:
        def connect(self) -> None:
            return None

        def bind(self, _uuid: Any) -> None:
            return None

        def request(self, _request: Any) -> None:
            raise OSError("ERROR_UNEXPECTED coercion did not fire")

        def disconnect(self) -> None:
            return None

    class _RpcTransport:
        def set_credentials(self, *args: Any) -> None:
            return None

        def set_kerberos(self, *args: Any, **kwargs: Any) -> None:
            return None

        def get_dce_rpc(self) -> _Dce:
            return _Dce()

    transport.DCERPCTransportFactory = lambda binding: _RpcTransport()
    rpcrt.uuidtup_to_bin = lambda value: b"uuid"
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rpcrt", rpcrt)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.transport", transport)
    monkeypatch.setattr(coerce, "_build_coercion_request", lambda method, listener: {})

    outcome = coerce._trigger(_target(), "10.0.0.1", "10.0.0.2", "petitpotam")
    assert outcome["ok"] is False
    assert "ERROR_UNEXPECTED" in outcome["error"]


# ---------------------------------------------------------------------------
# capabilities.dcsync: inline single principal + pass-the-hash login branch
# ---------------------------------------------------------------------------
def test_dcsync_single_principal_and_hash_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from adaf_attack.capabilities import dcsync

    monkeypatch.setattr(dcsync, "require_impacket", lambda _feature: None)

    # Stub secretsdump so importing it does not pull in the real
    # impacket.dcerpc.v5.transport while SMBConnection is patched (that first
    # import would otherwise permanently bind transport.SMBConnection to the
    # stub and leak into later tests).
    secretsdump = ModuleType("impacket.examples.secretsdump")
    secretsdump.NTDSHashes = object
    secretsdump.RemoteOperations = object
    monkeypatch.setitem(sys.modules, "impacket.examples.secretsdump", secretsdump)

    class _Smb:
        def login(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("offline hash login failure")

    monkeypatch.setattr("impacket.smbconnection.SMBConnection", lambda *args, **kwargs: _Smb())
    target = _target(username="alice", hashes=":" + "a" * 32)

    with pytest.raises(RuntimeError, match="offline hash login"):
        dcsync.Dcsync().run(target, Session(tmp_path), AttackGraph(), principals="administrator")


# ---------------------------------------------------------------------------
# capabilities.ldap_enum: GPO enumeration failure is tolerated
# ---------------------------------------------------------------------------
def test_ldap_enum_tolerates_gpo_search_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import adaf_attack.capabilities.ldap_enum as ldap_enum

    class _Conn:
        def __init__(self) -> None:
            self.entries: list[Any] = []
            self.unbound = False

        def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
            if search_filter == ldap_enum.GPO_FILTER:
                raise RuntimeError("GPO subtree unavailable")
            self.entries = []

        def unbind(self) -> None:
            self.unbound = True

    conn = _Conn()
    monkeypatch.setattr(ldap_enum, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))

    result = ldap_enum.LdapEnum().run(_target(), Session(tmp_path), AttackGraph())
    assert result["gpos"] == []
    assert conn.unbound is True


# ---------------------------------------------------------------------------
# capabilities.rbcd: modify exception is wrapped into an error result
# ---------------------------------------------------------------------------
def test_rbcd_set_wraps_modify_exception(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import adaf_attack.capabilities.rbcd as rbcd

    on_entry = _Entry(distinguishedName="CN=APP01,DC=corp,DC=test", objectSid="S-1-5-21-1-2-3-1105")
    from_entry = _Entry(
        distinguishedName="CN=WEB01,DC=corp,DC=test", objectSid="S-1-5-21-1-2-3-1106"
    )
    responses = {
        f"(&(objectClass=computer)({rbcd.ATTR}=*))": [],
        "(sAMAccountName=APP01$)": [on_entry],
        "(sAMAccountName=WEB01$)": [from_entry],
    }

    class _Conn:
        def __init__(self) -> None:
            self.entries: list[Any] = []
            self.result = "success"
            self.unbound = False

        def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
            self.entries = responses.get(search_filter, responses.get(base_dn, []))

        def modify(self, dn: str, changes: Any) -> bool:
            raise RuntimeError("LDAP modify rejected")

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(rbcd, "ldap_connect", lambda target: (_Conn(), "DC=corp,DC=test", None))
    result = rbcd.Rbcd().run(
        _target(),
        Session(tmp_path),
        AttackGraph(),
        force=True,
        set_on="APP01$",
        set_from="WEB01$",
    )
    attempt = result["set_attempt"]
    assert attempt["ok"] is False
    assert "LDAP modify rejected" in attempt["error"]


# ---------------------------------------------------------------------------
# capabilities.report: an unlistable session root falls back to no artifacts
# ---------------------------------------------------------------------------
def test_report_tolerates_unlistable_session_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from adaf_attack.capabilities.report import Report

    session = Session(base_dir=tmp_path)
    real_iterdir = Path.iterdir

    def fake_iterdir(self: Path) -> Any:
        if self == session.root:
            raise OSError("directory listing unavailable")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", fake_iterdir)

    out = Report().run(_target(), session, AttackGraph())
    assert Path(out["md_path"]).is_file()
    assert "## Session artifacts" in Path(out["md_path"]).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# capabilities.shadow_creds: entry without descriptor is skipped
# ---------------------------------------------------------------------------
def test_shadow_creds_skips_entries_without_descriptor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import adaf_attack.capabilities.shadow_creds as shadow_creds

    writable = _Entry(sAMAccountName="krbtgt", distinguishedName="CN=krbtgt,DC=corp,DC=test")

    class _Conn:
        def __init__(self) -> None:
            self.entries: list[Any] = []
            self.unbound = False

        def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
            self.entries = [] if "KeyCredentialLink=*" in search_filter else [writable]

        def unbind(self) -> None:
            self.unbound = True

    conn = _Conn()
    monkeypatch.setattr(
        shadow_creds, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None)
    )
    monkeypatch.setattr(shadow_creds, "fetch_sd", lambda connection, dn: None)

    result = shadow_creds.ShadowCreds().run(_target(), Session(tmp_path), AttackGraph())
    assert result["writable_principals"] == []
    assert conn.unbound is True


# ---------------------------------------------------------------------------
# capabilities.template_mod: modify failure logs the LDAP result
# ---------------------------------------------------------------------------
def test_template_mod_reports_modify_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import adaf_attack.capabilities.template_mod as template_mod

    entry = _Entry(
        distinguishedName="CN=User,CN=Certificate Templates,DC=corp,DC=test",
        **{
            "pKIExtendedKeyUsage": _Attr(values=["1.2.3"]),
            "msPKI-Certificate-Name-Flag": _Attr(0),
            "msPKI-Enrollment-Flag": _Attr(2),
        },
    )

    class _Conn:
        def __init__(self) -> None:
            self.entries = [entry]
            self.result = "insufficientAccessRights"
            self.unbound = False

        def search(self, *args: Any, **kwargs: Any) -> bool:
            return True

        def modify(self, dn: str, changes: Any) -> bool:
            return False

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(
        template_mod, "ldap_connect", lambda target: (_Conn(), "DC=corp,DC=test", "CN=Config")
    )
    result = template_mod.TemplateMod().run(
        _target(username="alice", password="secret"),
        Session(base_dir=tmp_path),
        AttackGraph(),
        template="User",
        force=True,
    )
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# core.findings: AD CS policy-probe candidates become findings
# ---------------------------------------------------------------------------
def test_findings_from_session_includes_policy_probe_candidates(tmp_path: Path) -> None:
    from adaf_attack.core.findings import findings_from_session

    session = tmp_path / "s"
    session.mkdir()
    (session / "adcs-policy-probe.json").write_text(
        json.dumps({"esc10_candidates": ["User"], "esc11_candidates": [], "esc13_candidates": []}),
        encoding="utf-8",
    )
    findings = findings_from_session(session)
    assert any(f.document()["id"].startswith("ADAF-ADCS-ESC10") for f in findings)


# ---------------------------------------------------------------------------
# core.forest_campaign: vault index references are collected
# ---------------------------------------------------------------------------
def test_compose_forest_campaign_collects_vault_refs(tmp_path: Path) -> None:
    from adaf_attack.core.forest_campaign import compose_forest_campaign

    session = tmp_path / "session-1"
    (session / "vault").mkdir(parents=True)
    (session / "vault" / "index.json").write_text(
        json.dumps({"items": {"alice.tgt": {"kind": "ccache", "secret": True}}}),
        encoding="utf-8",
    )
    result = compose_forest_campaign([session])
    assert result["vault_references"] == [
        {"session": str(session), "name": "alice.tgt", "kind": "ccache", "secret": True}
    ]


# ---------------------------------------------------------------------------
# core.graph: depth-zero short-circuit and the visited-depth revisit guard
# ---------------------------------------------------------------------------
def test_rank_exploit_chains_depth_zero_and_revisit_guard() -> None:
    graph = AttackGraph()
    for node in ("A", "B", "C"):
        graph.add_node(node, "User", sam=node)
    graph.add_edge("A", "B", "MemberOf")
    graph.add_edge("A", "C", "MemberOf")
    graph.add_edge("B", "C", "MemberOf")

    assert graph.rank_exploit_chains(["A"], max_depth=0) == []
    # The diamond forces node C to be re-reached at a deeper depth than recorded.
    assert graph.rank_exploit_chains(["A"]) == []


# ---------------------------------------------------------------------------
# core.profiles: default profiles path lives under the user config dir
# ---------------------------------------------------------------------------
def test_profiles_path_points_at_user_config() -> None:
    from adaf_attack.core.profiles import profiles_path

    assert profiles_path().name == "profiles.json"


# ---------------------------------------------------------------------------
# core.rbcd_sd: unparseable SID bytes fall through to the string path
# ---------------------------------------------------------------------------
def test_sid_from_ldap_value_handles_unparseable_bytes() -> None:
    from adaf_attack.core.rbcd_sd import sid_from_ldap_value

    assert sid_from_ldap_value(b"\x01") is None


# ---------------------------------------------------------------------------
# core.reporting: PDF generation is skipped when reportlab is unavailable
# ---------------------------------------------------------------------------
def test_pdf_report_returns_false_without_reportlab(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from adaf_attack.core import reporting

    monkeypatch.setitem(sys.modules, "reportlab.lib.pagesizes", None)
    assert reporting._pdf(tmp_path / "out.pdf", "Title", [], "executive") is False


# ---------------------------------------------------------------------------
# core.runner: resolved DN edges trigger a graph re-save
# ---------------------------------------------------------------------------
def test_runner_saves_graph_when_dn_edges_resolve(tmp_path: Path) -> None:
    from adaf_attack.core.registry import Capability, capability_registry
    from adaf_attack.core.runner import execute_capability

    class _Runner:
        def run(
            self,
            target: Target,
            session: Session,
            graph: AttackGraph,
            *,
            include_secrets: bool = False,
            force: bool = False,
            **kwargs: Any,
        ) -> dict[str, Any]:
            graph.add_node("GROUP@ADMINS", "Group", dn="CN=Admins,DC=corp,DC=test")
            graph.add_node("USER@ALICE", "User", sam="alice")
            graph.add_edge("USER@ALICE", "GROUPDN@CN=Admins,DC=corp,DC=test", "MemberOf")
            return {"ok": True}

    capability_registry._capabilities["t-dn-resolve"] = Capability(
        id="t-dn-resolve", summary="test", runner=_Runner()
    )
    try:
        out = execute_capability("t-dn-resolve", _target(), workspace=tmp_path)
    finally:
        capability_registry._capabilities.pop("t-dn-resolve", None)

    assert out["ok"] is True
    assert (Path(out["session_path"]) / "graph.json").is_file()


# ---------------------------------------------------------------------------
# core.ux: search truncation and malformed findings handling
# ---------------------------------------------------------------------------
def test_unified_search_truncates_at_limit() -> None:
    from adaf_attack.core.ux import unified_search

    result = unified_search("enum", limit=1)
    assert result["count"] == 1


def test_session_findings_summary_ignores_non_list(tmp_path: Path) -> None:
    from adaf_attack.core.ux import session_findings_summary

    (tmp_path / "findings.json").write_text(
        json.dumps({"findings": "not-a-list"}), encoding="utf-8"
    )
    summary = session_findings_summary(tmp_path)
    assert summary["finding_count"] == 0


# ---------------------------------------------------------------------------
# core.ux_extra: unregistered follow-ups skipped; malformed findings ignored
# ---------------------------------------------------------------------------
def test_next_actions_skips_unregistered_followups(monkeypatch: pytest.MonkeyPatch) -> None:
    import adaf_attack.core.ux as ux
    from adaf_attack.core.registry import capability_registry
    from adaf_attack.core.ux_extra import format_next_actions_block

    cap = capability_registry.list()[0]
    monkeypatch.setattr(ux, "suggested_next_actions", lambda _cap: ["capability-does-not-exist"])
    block = format_next_actions_block(cap, domain="corp.test", dc_ip="10.0.0.1")
    assert block["count"] == 0


def test_session_findings_dashboard_ignores_non_list(tmp_path: Path) -> None:
    from adaf_attack.core.ux_extra import session_findings_dashboard

    (tmp_path / "findings.json").write_text(
        json.dumps({"findings": "not-a-list"}), encoding="utf-8"
    )
    dashboard = session_findings_dashboard(tmp_path)
    assert dashboard["findings"] == []


# ---------------------------------------------------------------------------
# cli.doctor: a populated workspace reports the non-first-run next step
# ---------------------------------------------------------------------------
def test_doctor_reports_returning_workspace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    prior = tmp_path / "prior-session"
    prior.mkdir()
    (prior / "session.json").write_text(json.dumps({"session_id": "prior"}), encoding="utf-8")
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))

    result = runner.invoke(cli.app, ["--format", "json", "doctor"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["first_run"] is False
    assert "capability-help" in payload["next_step"]


# ---------------------------------------------------------------------------
# cli.run: interactive destructive confirmation and spinner execution paths
# ---------------------------------------------------------------------------
class _TtyStdout:
    def __init__(self, real: Any) -> None:
        self._real = real

    def isatty(self) -> bool:
        return True

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class _SysProxy:
    def __init__(self, real: Any) -> None:
        self._real = real

    def __getattr__(self, name: str) -> Any:
        if name == "stdout":
            return _TtyStdout(self._real.stdout)
        return getattr(self._real, name)


def test_run_interactive_destructive_confirmation_abort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[str] = []
    monkeypatch.setattr(
        cli, "execute_capability", lambda *a, **k: called.append(a[0]) or {"ok": True}
    )
    monkeypatch.setattr(cli, "sys", _SysProxy(sys))

    result = runner.invoke(
        cli.app,
        ["run", "shadow-creds", "--domain", "corp.test", "--dc-ip", "10.0.0.1", "--force"],
        input="n\n",
    )
    assert result.exit_code != 0
    assert "USER_ABORTED" in result.output
    assert called == []


def test_run_interactive_spinner_and_session_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(capability: str, target: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "session_path": "/tmp/session",
            "session_id": "sess-123",
            "interesting": {},
        }

    monkeypatch.setattr(cli, "execute_capability", fake_run)
    monkeypatch.setattr(cli, "sys", _SysProxy(sys))

    result = runner.invoke(
        cli.app, ["run", "ldap-enum", "--domain", "corp.test", "--dc-ip", "10.0.0.1"]
    )
    assert result.exit_code == 0, result.output
    assert "sess-123" in result.output


# ---------------------------------------------------------------------------
# cli.start: missing Textual dependency surfaces an actionable error
# ---------------------------------------------------------------------------
def test_start_reports_missing_tui_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "adaf_attack.tui.app", None)
    result = runner.invoke(cli.app, ["--format", "json", "start"])
    assert result.exit_code != 0
    assert "TUI_DEPENDENCY_MISSING" in result.output


# ---------------------------------------------------------------------------
# cli.demo: packaged fixture errors and replacement of an existing session
# ---------------------------------------------------------------------------
def test_demo_reports_missing_fixtures(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import adaf_attack.demo as demo

    def fail_materialize(destination: Path) -> Path:
        raise FileNotFoundError("packaged demo fixture missing")

    monkeypatch.setattr(demo, "materialize_demo_session", fail_materialize)
    result = runner.invoke(cli.app, ["--format", "json", "demo", "--workspace", str(tmp_path)])
    assert result.exit_code != 0
    assert "DEMO_FIXTURES_MISSING" in result.output


def test_demo_replaces_existing_session(tmp_path: Path) -> None:
    stale = tmp_path / "demo-session"
    stale.mkdir()
    (stale / "stale.txt").write_text("obsolete", encoding="utf-8")

    result = runner.invoke(cli.app, ["--format", "json", "demo", "--workspace", str(tmp_path)])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["mode"] == "offline-demo"
    assert not (stale / "stale.txt").exists()
