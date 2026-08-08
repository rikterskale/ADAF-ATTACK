"""Offline happy/error paths for the remaining operator adapters."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import adaf_attack.capabilities.esc_chain as esc_chain
import adaf_attack.capabilities.laps_read as laps_read
import adaf_attack.capabilities.ntlm_relay as ntlm_relay
import adaf_attack.capabilities.s4u_abuse as s4u_abuse
import adaf_attack.capabilities.secretsdump_local as secretsdump_local
import adaf_attack.capabilities.template_mod as template_mod
import adaf_attack.capabilities.ticket_forge as ticket_forge
import adaf_attack.capabilities.unpac_the_hash as unpac_the_hash
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any = None, values: list[Any] | None = None) -> None:
        self.value = value
        self.values = values if values is not None else ([] if value is None else [value])

    def __bool__(self) -> bool:
        return self.value is not None or bool(self.values)

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **attrs: Any) -> None:
        self._attrs = {
            key: value if isinstance(value, _Attr) else _Attr(value) for key, value in attrs.items()
        }
        for key, value in self._attrs.items():
            setattr(self, key, value)

    def __getitem__(self, key: str) -> _Attr:
        return self._attrs[key]


class _Conn:
    def __init__(self, entries: list[_Entry]) -> None:
        self.entries = entries
        self.result = {"description": "success"}
        self.unbound = False
        self.modified: list[tuple[str, dict[str, Any]]] = []

    def search(self, *args: Any, **kwargs: Any) -> bool:
        return True

    def modify(self, dn: str, changes: dict[str, Any]) -> bool:
        self.modified.append((dn, changes))
        return True

    def unbind(self) -> None:
        self.unbound = True


def _target(**kwargs: Any) -> Target:
    return Target(
        domain="corp.test", dc_ip="10.0.0.1", username="alice", password="secret", **kwargs
    )


def test_laps_run_covers_v1_v2_and_redaction(monkeypatch: Any, tmp_path: Path) -> None:
    blob = (123).to_bytes(8, "little") + (20).to_bytes(4, "little") + b"\0" * 4 + b"blob"
    entry = _Entry(
        sAMAccountName="WEB$",
        distinguishedName="CN=WEB,DC=corp,DC=test",
        dNSHostName="web.corp.test",
        **{
            laps_read.V1_ATTR: _Attr("v1-secret"),
            laps_read.V1_EXPIRY: _Attr(42),
            laps_read.V2_PLAIN: _Attr("v2-secret"),
            laps_read.V2_ATTR: _Attr(blob),
        },
    )
    conn = _Conn([entry])
    monkeypatch.setattr(laps_read, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    session = Session(base_dir=tmp_path)
    result = laps_read.LapsRead().run(_target(), session, AttackGraph())
    assert result["v1_readable"] == 1 and result["v2_readable"] == 2
    assert result["entries"][0]["v1_password"] == "[REDACTED]"
    assert conn.unbound


def test_template_mod_applies_changes_and_registers_rollback(
    monkeypatch: Any, tmp_path: Path
) -> None:
    entry = _Entry(
        distinguishedName="CN=User,CN=Certificate Templates,DC=corp,DC=test",
        **{
            "pKIExtendedKeyUsage": _Attr(values=["1.2.3"]),
            "msPKI-Certificate-Name-Flag": _Attr(0),
            "msPKI-Enrollment-Flag": _Attr(2),
        },
    )
    conn = _Conn([entry])
    monkeypatch.setattr(
        template_mod, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", "CN=Config")
    )
    session = Session(base_dir=tmp_path)
    result = template_mod.TemplateMod().run(
        _target(), session, AttackGraph(), template="User", force=True
    )
    assert result["ok"] is True
    assert template_mod.CLIENT_AUTH_EKU in result["applied"]["pKIExtendedKeyUsage"]
    assert Path(result_path := session.path("template-mod-User.rollback.json")).is_file()
    assert json.loads(result_path.read_text())["attrs"]["msPKI-Enrollment-Flag"] == 2


def test_template_mod_guards_and_missing_template(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    with pytest.raises(RuntimeError, match="template="):
        template_mod.TemplateMod().run(_target(), session, AttackGraph(), force=True)
    with pytest.raises(RuntimeError, match="force"):
        template_mod.TemplateMod().run(_target(), session, AttackGraph(), template="User")
    monkeypatch.setattr(
        template_mod, "ldap_connect", lambda target: (_Conn([]), "DC=x", "CN=Config")
    )
    with pytest.raises(RuntimeError, match="not found"):
        template_mod.TemplateMod().run(
            _target(), session, AttackGraph(), template="User", force=True
        )


def test_ntlm_relay_success_and_timeout(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(ntlm_relay.shutil, "which", lambda name: "/usr/bin/relay")

    class Proc:
        pid = 7
        returncode = 0

        def wait(self, timeout: int) -> None:
            return None

        def terminate(self) -> None:
            return None

        def kill(self) -> None:
            return None

    monkeypatch.setattr(ntlm_relay.subprocess, "Popen", lambda *args, **kwargs: Proc())
    session = Session(base_dir=tmp_path)
    result = ntlm_relay.NtlmRelay().run(
        _target(),
        session,
        AttackGraph(),
        force=True,
        relay_targets="10.0.0.2,10.0.0.3",
        duration_seconds=1,
    )
    assert result["return_code"] == 0 and result["truncated"] is False

    class TimeoutProc(Proc):
        returncode = None

        def wait(self, timeout: int) -> None:
            if timeout == 1:
                raise ntlm_relay.subprocess.TimeoutExpired("relay", timeout)

    monkeypatch.setattr(ntlm_relay.subprocess, "Popen", lambda *args, **kwargs: TimeoutProc())
    timed = ntlm_relay.NtlmRelay().run(
        _target(),
        Session(base_dir=tmp_path / "timed"),
        AttackGraph(),
        force=True,
        relay_targets=["10.0.0.2"],
        duration_seconds=1,
    )
    assert timed["truncated"] is True


def test_ntlm_relay_guards(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    with pytest.raises(RuntimeError, match="destructive"):
        ntlm_relay.NtlmRelay().run(_target(), session, AttackGraph())
    with pytest.raises(RuntimeError, match="allowlist"):
        ntlm_relay.NtlmRelay().run(_target(), session, AttackGraph(), force=True)
    monkeypatch.setattr(ntlm_relay.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="not on PATH"):
        ntlm_relay.NtlmRelay().run(
            _target(), session, AttackGraph(), force=True, relay_targets=["x"]
        )


def test_secretsdump_local_mocked_impacket(monkeypatch: Any, tmp_path: Path) -> None:
    module = ModuleType("impacket.examples.secretsdump")

    class Remote:
        def __init__(self, conn: Any, **kwargs: Any) -> None:
            pass

        def setExecMethod(self, method: str) -> None:
            assert method == "smbexec"

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

        def finish(self) -> None:
            pass

    class Lsa:
        def __init__(self, *args: Any, perSecretCallback: Any, **kwargs: Any) -> None:
            self.cb = perSecretCallback

        def dumpCachedHashes(self) -> None:
            self.cb("cached", "cached")

        def dumpSecrets(self) -> None:
            self.cb("secret", "secret")

        def finish(self) -> None:
            pass

    module.RemoteOperations, module.SAMHashes, module.LSASecrets = Remote, Sam, Lsa
    monkeypatch.setitem(sys.modules, "impacket.examples.secretsdump", module)
    monkeypatch.setattr(secretsdump_local, "require_impacket", lambda name: None)
    monkeypatch.setattr(secretsdump_local, "smb_connect", lambda host, target: object())
    result = secretsdump_local.SecretsdumpLocal().run(
        _target(), Session(base_dir=tmp_path), AttackGraph()
    )
    assert result["sam_count"] == 1 and result["lsa_count"] == 2
    assert result["sam_entries"][0]["raw"] == "Administrator:500:aaa:bbb:::"


def test_s4u_and_ticket_forge_mocked(monkeypatch: Any, tmp_path: Path) -> None:
    examples = ModuleType("impacket.examples.getST")

    class GetST:
        def __init__(self, *args: Any) -> None:
            pass

        def run(self) -> None:
            pass

    examples.GETST = GetST
    monkeypatch.setitem(sys.modules, "impacket.examples.getST", examples)
    monkeypatch.setattr(s4u_abuse, "require_impacket", lambda name: None)
    s4u_session = Session(base_dir=tmp_path / "s4u")
    s4u_session.path("s4u/alice.ccache").write_bytes(b"ticket")
    result = s4u_abuse.S4uAbuse().run(
        _target(), s4u_session, AttackGraph(), impersonate="administrator", spn="cifs/dc"
    )
    assert result["ccache_paths"]

    forge_module = ModuleType("impacket.examples.ticketer")

    class Ticketer:
        def __init__(self, *args: Any) -> None:
            pass

        def run(self) -> None:
            pass

    forge_module.TICKETER = Ticketer
    monkeypatch.setitem(sys.modules, "impacket.examples.ticketer", forge_module)
    monkeypatch.setattr(ticket_forge, "require_impacket", lambda name: None)
    forge_session = Session(base_dir=tmp_path / "forge")
    forge_session.path("tickets/golden.ccache").write_bytes(b"ticket")
    forged = ticket_forge.TicketForge().run(
        _target(),
        forge_session,
        AttackGraph(),
        impersonate="administrator",
        nt="aa" * 16,
        domain_sid="S-1-5-21-1-2-3",
        variant="golden",
    )
    assert forged["variant"] == "golden"


def test_s4u_ticket_and_unpac_guards(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    monkeypatch.setattr(s4u_abuse, "require_impacket", lambda name: None)
    with pytest.raises(RuntimeError, match="Requires"):
        s4u_abuse.S4uAbuse().run(_target(), session, AttackGraph())
    monkeypatch.setattr(ticket_forge, "require_impacket", lambda name: None)
    with pytest.raises(RuntimeError, match="impersonate"):
        ticket_forge.TicketForge().run(_target(), session, AttackGraph())
    monkeypatch.setattr(unpac_the_hash, "require_impacket", lambda name: None)
    with pytest.raises(RuntimeError, match="sam"):
        unpac_the_hash.UnpacTheHash().run(_target(), session, AttackGraph())


def test_unpac_delegates_pkinit_and_records_parse_failure(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(unpac_the_hash, "require_impacket", lambda name: None)

    class Pkinit:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, str]:
            return {"ccache": str(tmp_path / "ticket.ccache")}

    module = ModuleType("adaf_attack.capabilities.pkinit_auth")
    module.PkinitAuth = Pkinit
    monkeypatch.setitem(sys.modules, "adaf_attack.capabilities.pkinit_auth", module)
    result = unpac_the_hash.UnpacTheHash().run(
        _target(), Session(base_dir=tmp_path), AttackGraph(), sam="alice", pfx="cert.pfx"
    )
    assert result["sam"] == "alice" and result["pac_credential_info"].startswith("parse-failed:")


def test_esc_chain_delegates_cert_and_pkinit(monkeypatch: Any, tmp_path: Path) -> None:
    class Cert:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, str]:
            return {"pfx": "issued.pfx"}

    class Pkinit:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, bool]:
            return {"ok": True}

    monkeypatch.setattr(esc_chain, "CertRequest", Cert, raising=False)
    monkeypatch.setattr(esc_chain, "PkinitAuth", Pkinit, raising=False)
    # The classes are imported inside run, so replace the modules they come from.
    cert_module = ModuleType("adaf_attack.capabilities.cert_request")
    cert_module.CertRequest = Cert
    pkinit_module = ModuleType("adaf_attack.capabilities.pkinit_auth")
    pkinit_module.PkinitAuth = Pkinit
    monkeypatch.setitem(sys.modules, "adaf_attack.capabilities.cert_request", cert_module)
    monkeypatch.setitem(sys.modules, "adaf_attack.capabilities.pkinit_auth", pkinit_module)
    result = esc_chain.EscChain().run(
        _target(), Session(base_dir=tmp_path), AttackGraph(), template="User", ca="CA", sam="alice"
    )
    assert result["cert_request"]["pfx"] == "issued.pfx" and result["pkinit_auth"]["ok"]
