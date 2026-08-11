"""Focused tests for every branch in the local profile and completion helpers."""

from __future__ import annotations

import builtins
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest
from typer.testing import CliRunner

from adaf_attack.cli import app
from adaf_attack.core import completions, profiles, user_config


def test_completion_generators_and_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each supported shell has a usable script and hint."""
    for shell, marker in {
        "bash": "complete -F",
        "zsh": "compdef _adaf_attack",
        "fish": "complete -c adaf-attack",
        "powershell": "Register-ArgumentCompleter",
    }.items():
        assert marker in completions.generate_completion(shell)
        assert completions.completion_install_hint(shell)
    with pytest.raises(ValueError, match="Unsupported shell"):
        completions.generate_completion("cmd")

    from adaf_attack.core.registry import capability_registry

    monkeypatch.setattr(capability_registry, "ids", lambda: (_ for _ in ()).throw(RuntimeError()))
    assert completions._capability_ids() == []


def test_profiles_all_persistence_validation_and_opsec_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Profile persistence handles absent, malformed, valid, and invalid data."""
    profile_file = tmp_path / "nested" / "profiles.json"
    config_file = tmp_path / "config.json"
    monkeypatch.setattr(profiles, "profiles_path", lambda: profile_file)
    monkeypatch.setattr(user_config, "config_path", lambda: config_file)

    assert profiles.load_profiles() == {}
    profile_file.parent.mkdir(parents=True)
    profile_file.write_text("[]", encoding="utf-8")
    assert profiles.load_profiles() == {}
    profile_file.write_text("not json", encoding="utf-8")
    assert profiles.load_profiles() == {}

    with pytest.raises(ValueError, match="non-empty"):
        profiles.set_profile("bad name", {})
    with pytest.raises(ValueError, match="Unknown profile field"):
        profiles.set_profile("lab", {"unknown": "value"})
    with pytest.raises(ValueError, match="opsec_profile"):
        profiles.set_profile("lab", {"opsec_profile": "unsafe"})

    saved = profiles.set_profile(
        "lab",
        {"domain": "corp.test", "ldaps": "yes", "kerberos": "0", "opsec_profile": "stealth"},
    )
    assert saved["ldaps"] is True and saved["kerberos"] is False
    assert profiles.get_profile("lab") == saved
    assert profiles.list_profiles() == [{"name": "lab", **saved}]
    assert profiles.apply_profile_to_defaults("lab")["target.domain"] == "corp.test"
    assert profiles.active_opsec("loud") == "loud"
    assert profiles.active_opsec(profile_name="lab") == "stealth"
    assert profiles.active_opsec("invalid", "missing") == "stealth"
    assert profiles.delete_profile("lab") is True
    assert profiles.delete_profile("lab") is False
    with pytest.raises(ValueError, match="Unknown profile"):
        profiles.apply_profile_to_defaults("lab")


def test_profile_cli_errors_and_secondary_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLI profile commands exercise user-facing error and clear-default paths."""
    monkeypatch.setattr(profiles, "profiles_path", lambda: tmp_path / "profiles.json")
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")
    runner = CliRunner()
    missing = runner.invoke(app, ["--format", "json", "profile", "show", "missing"])
    assert missing.exit_code == 1
    invalid = runner.invoke(app, ["--format", "json", "profile", "set", "lab", "--opsec", "bad"])
    assert invalid.exit_code == 1
    assert runner.invoke(app, ["--format", "json", "profile", "default"]).exit_code == 0
    assert runner.invoke(app, ["--format", "json", "profile", "delete", "missing"]).exit_code == 1
    unsupported = runner.invoke(app, ["--format", "json", "completions", "cmd"])
    assert unsupported.exit_code == 1
    assert json.loads(unsupported.output)["error"]["code"] == "UNSUPPORTED_SHELL"


def test_profile_and_session_human_output_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Human output exercises tables, panels, and missing-session remediation."""
    monkeypatch.setattr(profiles, "profiles_path", lambda: tmp_path / "profiles.json")
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")
    runner = CliRunner()
    assert runner.invoke(app, ["profile", "list"]).exit_code == 0
    assert (
        runner.invoke(
            app,
            [
                "profile",
                "set",
                "lab",
                "--domain",
                "corp.test",
                "--dc-ip",
                "192.0.2.10",
                "--notes",
                "x",
            ],
        ).exit_code
        == 0
    )
    assert runner.invoke(app, ["profile", "list"]).exit_code == 0
    assert runner.invoke(app, ["profile", "show", "lab"]).exit_code == 0
    assert runner.invoke(app, ["profile", "default", "lab"]).exit_code == 0
    assert runner.invoke(app, ["profile", "use", "missing"]).exit_code == 1
    assert runner.invoke(app, ["profile", "default", "missing"]).exit_code == 1
    assert runner.invoke(app, ["profile", "set", "bad name"]).exit_code == 1
    assert runner.invoke(app, ["completions", "fish"]).exit_code == 0
    assert (
        runner.invoke(app, ["session", "show", "--session", str(tmp_path / "missing")]).exit_code
        == 1
    )

    session = tmp_path / "session"
    session.mkdir()
    (session / "session.json").write_text('{"session_id":"human"}', encoding="utf-8")
    (session / "interesting.json").write_text(
        '{"top_paths":[{"score":3,"path":["a@corp","b@corp"]}]}', encoding="utf-8"
    )
    (session / "graph.json").write_text('{"summary":{"nodes":2,"edges":1}}', encoding="utf-8")
    (session / "findings.json").write_text('{"findings":[]}', encoding="utf-8")
    shown = runner.invoke(app, ["session", "show", "--session", str(session)])
    assert shown.exit_code == 0 and "Top paths" in shown.output


def test_ux_helpers_cover_empty_and_malformed_offline_inputs(tmp_path: Path) -> None:
    """UX helpers retain usable output for malformed or empty session data."""
    from adaf_attack.core.registry import Capability
    from adaf_attack.core.ux import (
        build_ready_command,
        group_capabilities_by_phase,
        session_findings_summary,
        unified_search,
    )
    from adaf_attack.core.ux_extra import format_next_actions_block, session_findings_dashboard

    cap = Capability("custom", "unexpected", "summary", False, lambda **_: {})
    assert group_capabilities_by_phase() is not None
    command = build_ready_command(
        "ldap-enum", domain="corp.test", dc_ip="192.0.2.10", username="user", extra={"x": "y"}
    )
    assert "--username user" in command and "-P x=y" in command
    assert unified_search("") == {"query": "", "capabilities": [], "count": 0}
    session = tmp_path / "session"
    session.mkdir()
    (session / "findings.json").write_text('{"findings": {}}', encoding="utf-8")
    (session / "interesting.json").write_text('{"top_paths": {}}', encoding="utf-8")
    (session / "graph.json").write_text("{}", encoding="utf-8")
    assert session_findings_summary(session)["finding_count"] == 0
    assert session_findings_dashboard(session)["findings"] == []
    assert format_next_actions_block(cap)["count"] == 0


def test_ux_handles_custom_phases_and_malformed_dashboard_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Operator views retain predictable output for extension and malformed-data cases."""
    from adaf_attack.core import ux, ux_extra
    from adaf_attack.core.registry import Capability

    cap = Capability(id="custom", summary="custom", category="extension", tags=("graph",))
    monkeypatch.setattr(ux, "capability_phase", lambda _: "extension")
    monkeypatch.setattr(
        ux, "capability_registry", type("Registry", (), {"list": lambda _: [cap]})()
    )
    assert list(ux.group_capabilities_by_phase()) == ["extension"]
    assert ux.stages_for_capability(cap)[-2] == "analyze"
    assert ux.suggested_next_actions(cap) == []

    session = tmp_path / "malformed"
    session.mkdir()
    (session / "findings.json").write_text('{"findings":["bad", {"id":"x"}]}', encoding="utf-8")
    (session / "interesting.json").write_text('{"top_paths":"bad"}', encoding="utf-8")
    (session / "session.json").write_text("{}", encoding="utf-8")
    (session / "graph.json").write_text("{}", encoding="utf-8")
    dashboard = ux_extra.session_findings_dashboard(session, limit=1)
    assert dashboard["findings"] == [
        {"id": "x", "title": "untitled", "severity": "unknown", "category": None}
    ]
    assert dashboard["top_paths"] == []


def test_dcsync_principal_file_and_kerberos_error_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DCSync accepts an offline principal file and propagates SMB authentication errors."""
    from adaf_attack.capabilities import dcsync
    from adaf_attack.core.graph import AttackGraph
    from adaf_attack.core.session import Session
    from adaf_attack.core.target import Target

    principal_file = tmp_path / "principals.txt"
    principal_file.write_text("alice\n# comment\n bob \n", encoding="utf-8")
    monkeypatch.setattr(dcsync, "require_impacket", lambda _: None)

    class Smb:
        def kerberosLogin(self, *args, **kwargs) -> None:  # noqa: N802
            raise RuntimeError("offline kerberos failure")

    monkeypatch.setattr("impacket.smbconnection.SMBConnection", lambda *args, **kwargs: Smb())
    target = Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", use_kerberos=True)
    with pytest.raises(RuntimeError, match="offline kerberos"):
        dcsync.Dcsync().run(
            target,
            Session(tmp_path / "session"),
            AttackGraph(),
            principals=str(principal_file),
        )


def test_unpac_validates_credential_material_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """unPAC rejects incomplete certificate material before network operations."""
    from adaf_attack.capabilities import unpac_the_hash
    from adaf_attack.core.graph import AttackGraph
    from adaf_attack.core.session import Session
    from adaf_attack.core.target import Target

    monkeypatch.setattr(unpac_the_hash, "require_impacket", lambda _: None)
    target = Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", password="pw")
    with pytest.raises(RuntimeError, match="pfx"):
        unpac_the_hash.UnpacTheHash().run(
            target, Session(tmp_path / "session"), AttackGraph(), sam="alice", key="key.pem"
        )


def test_unpac_passes_pem_material_and_stops_without_a_mocked_ccache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The PKINIT adapter receives both PEM paths without contacting a KDC."""
    from adaf_attack.capabilities import unpac_the_hash
    from adaf_attack.core.graph import AttackGraph
    from adaf_attack.core.session import Session
    from adaf_attack.core.target import Target

    received: dict[str, object] = {}

    class _Pkinit:
        def run(self, *args: object, **kwargs: object) -> dict[str, str]:
            received.update(kwargs)
            return {}

    module = ModuleType("adaf_attack.capabilities.pkinit_auth")
    module.PkinitAuth = _Pkinit
    monkeypatch.setattr(unpac_the_hash, "require_impacket", lambda _: None)
    monkeypatch.setitem(sys.modules, "adaf_attack.capabilities.pkinit_auth", module)
    with pytest.raises(RuntimeError, match="did not produce a ccache"):
        unpac_the_hash.UnpacTheHash().run(
            Target(domain="corp.test", dc_ip="192.0.2.10"),
            Session(tmp_path / "session"),
            AttackGraph(),
            sam="alice",
            key="cert.key",
            cert="cert.pem",
        )
    assert received["key"] == "cert.key"
    assert received["cert"] == "cert.pem"


def test_unpac_pac_parser_skips_a_mocked_malformed_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Malformed PAC buffers are ignored rather than aborting offline analysis."""
    from adaf_attack.capabilities import unpac_the_hash

    pac = ModuleType("impacket.krb5.pac")

    class _PacType:
        def __init__(self, data: bytes) -> None:
            self.buffers = [object()]

        def __getitem__(self, key: str) -> list[object]:
            return self.buffers

    pac.PACTYPE = _PacType
    pac.PAC_INFO_BUFFER = lambda _: (_ for _ in ()).throw(ValueError("mocked PAC"))
    pac.PAC_CREDENTIAL_INFO = lambda _: object()
    monkeypatch.setitem(sys.modules, "impacket.krb5.pac", pac)
    assert unpac_the_hash._extract_nt_from_pac(b"malformed") is None


def test_unpac_uses_mocked_ccache_and_tgs_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A complete UnPAC parse path can be exercised with only local stand-ins."""
    from adaf_attack.capabilities import unpac_the_hash
    from adaf_attack.core.graph import AttackGraph
    from adaf_attack.core.session import Session
    from adaf_attack.core.target import Target

    class _Pkinit:
        def run(self, *args: object, **kwargs: object) -> dict[str, str]:
            return {"ccache": str(tmp_path / "ticket.ccache")}

    class _Client:
        def prettyPrint(self) -> bytes:  # noqa: N802
            return b"alice@CORP.TEST"

    class _Credential:
        def __getitem__(self, key: str) -> _Client:
            assert key == "client"
            return _Client()

        def toTGT(self) -> dict[str, object]:  # noqa: N802
            return {"KDC_REP": b"rep", "cipher": object(), "sessionKey": object()}

    class _CCache:
        credentials = [_Credential()]

        @classmethod
        def loadFile(cls, path: str) -> _CCache:  # noqa: N802
            return cls()

    pkinit_module = ModuleType("adaf_attack.capabilities.pkinit_auth")
    pkinit_module.PkinitAuth = _Pkinit
    constants = ModuleType("impacket.krb5.constants")
    constants.PrincipalNameType = type(
        "Types", (), {"NT_SRV_INST": type("Value", (), {"value": 2})}
    )
    ccache = ModuleType("impacket.krb5.ccache")
    ccache.CCache = _CCache
    kerberos = ModuleType("impacket.krb5.kerberosv5")
    kerberos.getKerberosTGS = lambda *args: (b"mocked-tgs", object(), object(), object())
    types_module = ModuleType("impacket.krb5.types")
    types_module.Principal = lambda name, type: (name, type)
    krb5 = ModuleType("impacket.krb5")
    krb5.constants = constants

    monkeypatch.setattr(unpac_the_hash, "require_impacket", lambda _: None)
    monkeypatch.setattr(unpac_the_hash, "_extract_nt_from_pac", lambda data: "mocked-pac")
    monkeypatch.setitem(sys.modules, "adaf_attack.capabilities.pkinit_auth", pkinit_module)
    monkeypatch.setitem(sys.modules, "impacket.krb5", krb5)
    monkeypatch.setitem(sys.modules, "impacket.krb5.constants", constants)
    monkeypatch.setitem(sys.modules, "impacket.krb5.ccache", ccache)
    monkeypatch.setitem(sys.modules, "impacket.krb5.kerberosv5", kerberos)
    monkeypatch.setitem(sys.modules, "impacket.krb5.types", types_module)
    result = unpac_the_hash.UnpacTheHash().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"),
        Session(tmp_path / "session"),
        AttackGraph(),
        sam="alice",
        pfx="cert.pfx",
    )
    assert result["pac_credential_info"] == "mocked-pac"


def test_core_configuration_and_dependency_errors_are_safe_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unreadable config and absent optional crypto dependencies return useful errors."""
    from adaf_attack.core import gpp, impacket_helper, user_config

    broken = tmp_path / "config.json"
    broken.write_text("{not-json", encoding="utf-8")
    monkeypatch.setattr(user_config, "config_path", lambda: broken)
    assert user_config.load_user_config() == {}

    real_import = builtins.__import__

    def missing_impacket(name: str, *args: object, **kwargs: object) -> object:
        if name == "impacket":
            raise ImportError("mocked missing impacket")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_impacket)
    with pytest.raises(impacket_helper.ImpacketMissing):
        impacket_helper.require_impacket("offline-test")

    def missing_crypto(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("cryptography"):
            raise ImportError("mocked missing crypto")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_crypto)
    with pytest.raises(RuntimeError, match="requires cryptography"):
        gpp.decrypt_cpassword("AA")
    monkeypatch.setattr(builtins, "__import__", real_import)
    with pytest.raises(ValueError, match="invalid base64"):
        gpp.decrypt_cpassword("£")


def test_adapter_helper_error_paths_are_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Adapter helper failures return safe, structured values without network use."""
    from adaf_attack.capabilities import ad_cve_scan, gmsa_laps_enum, rbcd, sysvol_hunt

    class BrokenSMB:
        def __init__(self, *args, **kwargs) -> None:
            raise OSError("offline")

    monkeypatch.setattr("impacket.smbconnection.SMBConnection", BrokenSMB)
    assert ad_cve_scan._check_smb_signing("192.0.2.10")["error"] == "offline"
    assert sysvol_hunt._decrypt_cpassword("not-base64") is None
    assert gmsa_laps_enum._parse_managed_password_blob(b"invalid") is None

    class BrokenText:
        def __str__(self) -> str:
            raise ValueError("bad descriptor")

    assert rbcd._parse_security_descriptor_sids(BrokenText()) == []


def test_cert_request_ignores_malformed_prior_adcs_artifact(tmp_path: Path) -> None:
    """A corrupt prior AD CS artifact cannot supply a template and fails safely."""
    from adaf_attack.capabilities.cert_request import CertRequest
    from adaf_attack.core.graph import AttackGraph
    from adaf_attack.core.session import Session
    from adaf_attack.core.target import Target

    session = Session(tmp_path)
    session.path("adcs-enum.json").write_text("not-json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="No --template"):
        CertRequest().run(
            Target(domain="corp.test", dc_ip="192.0.2.10", username="alice"),
            session,
            AttackGraph(),
            force=True,
        )


def test_asrep_roast_reports_missing_optional_dependency(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Missing Kerberos dependencies are reported before LDAP or KDC activity."""
    from adaf_attack.capabilities.asrep_roast import AsrepRoast
    from adaf_attack.core.graph import AttackGraph
    from adaf_attack.core.session import Session
    from adaf_attack.core.target import Target

    original_import = builtins.__import__

    def no_impacket(name: str, *args: object, **kwargs: object) -> object:
        if name == "impacket.krb5":
            raise ImportError("test missing dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_impacket)
    with pytest.raises(RuntimeError, match="requires Impacket"):
        AsrepRoast().run(
            Target(domain="corp.test", dc_ip="192.0.2.10"), Session(tmp_path), AttackGraph()
        )


def test_secretsdump_adapter_handles_offline_registry_sam_and_lsa_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Remote-registry adapter degrades safely when individual extraction stages fail."""
    from adaf_attack.capabilities import secretsdump_local
    from adaf_attack.core.graph import AttackGraph
    from adaf_attack.core.session import Session
    from adaf_attack.core.target import Target

    monkeypatch.setattr(secretsdump_local, "require_impacket", lambda _: None)
    monkeypatch.setattr(secretsdump_local, "smb_connect", lambda host, target: object())

    class RegistryFailure:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def setExecMethod(self, method: str) -> None:  # noqa: N802
            pass

        def enableRegistry(self) -> None:  # noqa: N802
            raise OSError("registry offline")

    monkeypatch.setattr("impacket.examples.secretsdump.RemoteOperations", RegistryFailure)
    target = Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", password="pw")
    with pytest.raises(RuntimeError, match="registry enable"):
        secretsdump_local.SecretsdumpLocal().run(
            target, Session(tmp_path / "registry"), AttackGraph()
        )

    class Remote:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def setExecMethod(self, method: str) -> None:  # noqa: N802
            pass

        def enableRegistry(self) -> None:  # noqa: N802
            pass

        def getBootKey(self) -> bytes:  # noqa: N802
            return b"boot"

        def finish(self) -> None:
            pass

    class BrokenDump:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def dump(self) -> None:
            raise OSError("offline dump")

        def dumpCachedHashes(self) -> None:  # noqa: N802
            raise OSError("offline lsa")

        def dumpSecrets(self) -> None:  # noqa: N802
            raise OSError("offline lsa")

        def finish(self) -> None:
            pass

    monkeypatch.setattr("impacket.examples.secretsdump.RemoteOperations", Remote)
    monkeypatch.setattr("impacket.examples.secretsdump.SAMHashes", BrokenDump)
    monkeypatch.setattr("impacket.examples.secretsdump.LSASecrets", BrokenDump)
    result = secretsdump_local.SecretsdumpLocal().run(
        target, Session(tmp_path / "dump"), AttackGraph()
    )
    assert result["sam_count"] == 0 and result["lsa_count"] == 0


def test_shadow_creds_and_rbcd_ignore_malformed_acl_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ACL parse failures are contained while enumeration artifacts are still produced."""
    from types import SimpleNamespace

    from adaf_attack.capabilities import rbcd, shadow_creds
    from adaf_attack.core.graph import AttackGraph
    from adaf_attack.core.session import Session
    from adaf_attack.core.target import Target

    class Conn:
        def __init__(self) -> None:
            self.calls = 0
            self.entries: list[object] = []

        def search(self, *args, **kwargs) -> None:
            self.calls += 1
            if self.calls == 2:
                self.entries = [
                    SimpleNamespace(sAMAccountName="admin", distinguishedName="CN=admin")
                ]
            else:
                self.entries = []

        def unbind(self) -> None:
            pass

    target = Target(domain="corp.test", dc_ip="192.0.2.10")
    for module, adapter in ((shadow_creds, shadow_creds.ShadowCreds), (rbcd, rbcd.Rbcd)):
        conn = Conn()
        monkeypatch.setattr(
            module, "ldap_connect", lambda target, c=conn: (c, "DC=corp,DC=test", None)
        )
        monkeypatch.setattr(module, "fetch_sd", lambda connection, dn: b"broken")
        monkeypatch.setattr(
            module,
            "parse_interesting_aces",
            lambda sd: (_ for _ in ()).throw(ValueError("bad acl")),
        )
        result = adapter().run(
            target, Session(tmp_path / module.__name__.split(".")[-1]), AttackGraph()
        )
        assert result
