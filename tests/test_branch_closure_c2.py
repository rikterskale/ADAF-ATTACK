"""Branch-closure tests (batch 2) for impacket/subprocess-backed capabilities."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

import adaf_attack.capabilities.cert_request as cert_request
import adaf_attack.capabilities.dcsync as dcsync
import adaf_attack.capabilities.gpp_cpassword as gpp_cpassword
import adaf_attack.capabilities.kerberoast as kerberoast
import adaf_attack.capabilities.next_actions as next_actions
import adaf_attack.capabilities.ntlm_relay as ntlm_relay
import adaf_attack.capabilities.pkinit_auth as pkinit_auth
import adaf_attack.capabilities.report as report
import adaf_attack.capabilities.s4u_abuse as s4u_abuse
import adaf_attack.capabilities.secretsdump_local as secretsdump_local
import adaf_attack.capabilities.ticket_forge as ticket_forge
import adaf_attack.capabilities.unpac_the_hash as unpac_the_hash
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def _target(**kwargs: Any) -> Target:
    values = {
        "domain": "corp.test",
        "dc_ip": "10.0.0.1",
        "username": "alice",
        "password": "Secret1!",
    }
    values.update(kwargs)
    return Target(**values)


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value
        self.values = value if isinstance(value, list) else ([] if value is None else [value])
        self.raw_values = self.values

    def __bool__(self) -> bool:
        return self.value is not None and self.value != []

    def __str__(self) -> str:
        return str(self.value)


def test_cert_request_seeds_nothing_from_empty_esc1_candidates(
    monkeypatch: Any, tmp_path: Path
) -> None:
    session = Session(tmp_path)
    session.path("adcs-enum.json").write_text(
        json.dumps({"esc1_candidates": [], "cas": [{"cn": "CORP-CA"}]}), encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="No --template"):
        cert_request.CertRequest().run(_target(), session, AttackGraph(), force=True)


def test_dcsync_without_principal_filter(monkeypatch: Any, tmp_path: Path) -> None:
    secretsdump = ModuleType("impacket.examples.secretsdump")

    class _RemoteOps:
        def __init__(self, smb: Any, **kwargs: Any) -> None:
            pass

        def setExecMethod(self, method: str) -> None:
            pass

        def enableRegistry(self) -> None:
            pass

        def finish(self) -> None:
            pass

    class _NTDSHashes:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.cb = kwargs["perSecretCallback"]

        def dump(self) -> None:
            self.cb(4, "alice:500:lmhash:nthash:::")

    secretsdump.NTDSHashes = _NTDSHashes
    secretsdump.RemoteOperations = _RemoteOps
    monkeypatch.setitem(sys.modules, "impacket.examples.secretsdump", secretsdump)
    monkeypatch.setattr(dcsync, "require_impacket", lambda feature: None)

    class _Smb:
        def login(self, *args: Any, **kwargs: Any) -> None:
            pass

    monkeypatch.setattr("impacket.smbconnection.SMBConnection", lambda *a, **k: _Smb())
    result = dcsync.Dcsync().run(_target(), Session(tmp_path), AttackGraph())
    assert result["principal_filter"] == []
    assert result["count"] == 1


def _kb_conn(entries: list[Any]) -> Any:
    return SimpleNamespace(entries=entries, search=lambda *a, **k: None, unbind=lambda: None)


def test_kerberoast_skips_spnless_accounts_and_unknown_etype_labels(
    monkeypatch: Any, tmp_path: Path
) -> None:
    with_spn = SimpleNamespace(sAMAccountName="svc", servicePrincipalName=["HTTP/a"])
    without_spn = SimpleNamespace(sAMAccountName="nosvc", servicePrincipalName=[])
    monkeypatch.setattr(
        kerberoast, "ldap_connect", lambda t: (_kb_conn([with_spn, without_spn]), "DC=x", None)
    )
    monkeypatch.setattr(kerberoast, "get_kerberos_tgt", lambda t: ("tgt", "c", None, "sk"))
    import impacket.krb5.kerberosv5 as kv5

    monkeypatch.setattr(kv5, "getKerberosTGS", lambda *a, **k: ("tgs", "c", None, "sk"))
    monkeypatch.setattr(
        kerberoast,
        "format_tgs_hashcat",
        lambda spn, sam, domain, tgs: "$krb5tgs$99$*svc$CORP.TEST$HTTP/a*$aa$bb",
    )
    result = kerberoast.Kerberoast().run(
        _target(), Session(tmp_path / "kb"), AttackGraph(), include_secrets=True
    )
    assert result["count"] == 1
    assert result["tickets"][0]["format"] == "hashcat-13100"


def test_next_actions_falls_back_to_plan_command_without_template(
    monkeypatch: Any, tmp_path: Path
) -> None:
    class _FakeGraph:
        def __init__(self) -> None:
            self.nodes = {"DOMAIN@CORP.TEST"}
            self.edges = [SimpleNamespace(kind="TrustedBy")]

        def rank_exploit_chains(self, limit: int) -> list[dict[str, Any]]:
            return [
                {
                    "terminal_relation": "TrustedBy",
                    "length": 1,
                    "edges": ["TrustedBy"],
                    "score": 4,
                    "impact": "review trust",
                    "path": ["DOMAIN@CORP.TEST"],
                }
            ]

    session = Session(tmp_path)
    result = next_actions.NextActions().run(_target(), session, _FakeGraph())
    assert result["count"] == 1
    action = result["actions"][0]
    assert action["capability"] == "trusts-enum"
    assert action["command"].startswith("adaf-attack plan trusts-enum")


def test_ntlm_relay_log_already_in_artifacts(monkeypatch: Any, tmp_path: Path) -> None:
    class RelaySession(Session):
        def path(self, *parts: str) -> Path:
            if parts and parts[0] == "relay.log":
                target_dir = super().path("relay-artifacts")
                return target_dir / "relay.log"
            return super().path(*parts)

    class _Proc:
        pid = 7
        returncode = 0

        def wait(self, timeout: int) -> None:
            return None

    monkeypatch.setattr(ntlm_relay.subprocess, "Popen", lambda *a, **k: _Proc())
    monkeypatch.setattr(ntlm_relay.shutil, "which", lambda name: "/usr/bin/ntlmrelayx")
    session = RelaySession(base_dir=tmp_path / "relay")
    result = ntlm_relay.NtlmRelay().run(
        _target(),
        session,
        AttackGraph(),
        force=True,
        relay_targets=["10.0.0.2"],
        duration_seconds=1,
    )
    assert result["return_code"] == 0
    assert result["artifacts"].count(result["log"]) == 1


def test_pkinit_writes_playbook_when_certipy_unavailable(monkeypatch: Any, tmp_path: Path) -> None:
    # When certipy cannot produce a TGT the capability falls back to writing a
    # ready-to-run playbook and printing the install hint.
    pfx = tmp_path / "card.pfx"
    pfx.write_bytes(b"pfx-bytes")

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("certipy exploded")

    monkeypatch.setattr(pkinit_auth.subprocess, "run", boom)
    session = Session(tmp_path / "pk")

    result = pkinit_auth.PkinitAuth().run(
        _target(), session, AttackGraph(), force=True, sam="alice", pfx=str(pfx)
    )

    assert result["ok"] is not True
    assert result["method"] == "certipy-error"
    assert result.get("playbook")
    assert Path(result["playbook"]).is_file()


def test_report_handles_non_dict_finding_and_nested_values(tmp_path: Path) -> None:
    session = Session(tmp_path)
    session.path("trusts-enum.json").write_text(json.dumps(["not-a-dict"]), encoding="utf-8")
    session.path("gmsa-laps-enum.json").write_text(
        json.dumps({"accounts": {"nested": 1}}), encoding="utf-8"
    )
    result = report.Report().run(_target(), session, AttackGraph())
    text = Path(result["md_path"]).read_text(encoding="utf-8")
    assert "### Trusts" in text
    assert "- accounts:" not in text


def test_gpp_hunt_record_without_plaintext(monkeypatch: Any, tmp_path: Path) -> None:
    source = tmp_path / "sysvol"
    source.mkdir()
    monkeypatch.setattr(gpp_cpassword, "iter_gpp_files", lambda _root: [source / "Groups.xml"])
    monkeypatch.setattr(
        gpp_cpassword,
        "parse_gpp_file",
        lambda _path: [{"file": "Groups.xml", "username": "svc", "error": "bad base64"}],
    )
    result = gpp_cpassword.GppCpasswordHunt().run(
        _target(), Session(tmp_path / "gpp"), AttackGraph(), sysvol=source
    )
    assert result["decrypted"] == 0 and result["count"] == 1


def test_s4u_with_existing_graph_nodes(monkeypatch: Any, tmp_path: Path) -> None:
    examples = ModuleType("impacket.examples.getST")

    class GetST:
        def __init__(self, *args: Any) -> None:
            pass

        def run(self) -> None:
            pass

    examples.GETST = GetST
    monkeypatch.setitem(sys.modules, "impacket.examples.getST", examples)
    monkeypatch.setattr(s4u_abuse, "require_impacket", lambda name: None)
    graph = AttackGraph()
    graph.add_node("USER@ALICE@CORP.TEST", "User")
    result = s4u_abuse.S4uAbuse().run(
        _target(),
        Session(tmp_path / "s4u"),
        graph,
        impersonate="administrator",
        spn="cifs/dc01.corp.test",
    )
    assert result["impersonate"] == "administrator"


def test_secretsdump_local_skips_short_sam_records(monkeypatch: Any, tmp_path: Path) -> None:
    module = ModuleType("impacket.examples.secretsdump")

    class Remote:
        def __init__(self, conn: Any, **kwargs: Any) -> None:
            pass

        def setExecMethod(self, method: str) -> None:
            pass

        def enableRegistry(self) -> None:
            pass

        def getBootKey(self) -> bytes:
            return b"boot"

        def finish(self) -> None:
            pass

    class Sam:
        def __init__(self, *args: Any, perSecretCallback: Any, **kwargs: Any) -> None:
            self.cb = perSecretCallback

        def dump(self) -> None:
            self.cb("Administrator:500:aaa:bbb:::")
            self.cb("malformed-line")

        def finish(self) -> None:
            pass

    class Lsa:
        def __init__(self, *args: Any, perSecretCallback: Any, **kwargs: Any) -> None:
            pass

        def dumpCachedHashes(self) -> None:
            pass

        def dumpSecrets(self) -> None:
            pass

        def finish(self) -> None:
            pass

    module.RemoteOperations, module.SAMHashes, module.LSASecrets = Remote, Sam, Lsa
    monkeypatch.setitem(sys.modules, "impacket.examples.secretsdump", module)
    monkeypatch.setattr(secretsdump_local, "require_impacket", lambda name: None)
    monkeypatch.setattr(secretsdump_local, "smb_connect", lambda host, target: object())
    result = secretsdump_local.SecretsdumpLocal().run(
        _target(), Session(tmp_path / "sd"), AttackGraph()
    )
    assert result["sam_count"] == 2
    assert len(result["sam_entries"]) == 2


def test_ticket_forge_ignores_non_ccache_files(monkeypatch: Any, tmp_path: Path) -> None:
    forge_module = ModuleType("impacket.examples.ticketer")

    class Ticketer:
        def __init__(self, *args: Any) -> None:
            pass

        def run(self) -> None:
            pass

    forge_module.TICKETER = Ticketer
    monkeypatch.setitem(sys.modules, "impacket.examples.ticketer", forge_module)
    monkeypatch.setattr(ticket_forge, "require_impacket", lambda name: None)
    forge_session = Session(tmp_path / "forge")
    forge_session.path("tickets/notes.txt").write_text("not a ticket", encoding="utf-8")
    forged = ticket_forge.TicketForge().run(
        _target(),
        forge_session,
        AttackGraph(),
        impersonate="administrator",
        nt="aa" * 16,
        domain_sid="S-1-5-21-1-2-3",
        variant="golden",
    )
    assert forged["ccache_paths"] == []


def test_extract_nt_from_pac_skips_other_buffer_types(monkeypatch: Any) -> None:
    pac_module = ModuleType("impacket.krb5.pac")

    class _Buffer:
        pass

    class _Info:
        def __getitem__(self, key: str) -> int:
            return 1

    class _PacType:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def __getitem__(self, key: str) -> list[Any]:
            return [_Buffer()]

    pac_module.PACTYPE = _PacType
    pac_module.PAC_INFO_BUFFER = lambda buf: _Info()
    pac_module.PAC_CREDENTIAL_INFO = object
    monkeypatch.setitem(sys.modules, "impacket.krb5.pac", pac_module)
    assert unpac_the_hash._extract_nt_from_pac(b"\x00" * 16) is None
