"""Behavioral coverage for RM-003 capability adapter edge paths."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from ldap3.core.exceptions import LDAPException

import adaf_attack.capabilities.adcs_esc as adcs_esc
import adaf_attack.capabilities.campaign_run as campaign_run
import adaf_attack.capabilities.credential_free as credential_free
import adaf_attack.capabilities.credential_inventory as credential_inventory
import adaf_attack.capabilities.esc_chain as esc_chain
import adaf_attack.capabilities.next_actions as next_actions
import adaf_attack.capabilities.ntlm_relay as ntlm_relay
import adaf_attack.capabilities.password_spray as password_spray
import adaf_attack.capabilities.relay_ops as relay_ops
import adaf_attack.capabilities.unpac_the_hash as unpac_the_hash
import adaf_attack.capabilities.workflow_wrappers as workflow_wrappers
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import Capability, SafetyProfile
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def _target(**overrides: Any) -> Target:
    values: dict[str, Any] = {
        "domain": "corp.test",
        "dc_ip": "192.0.2.10",
        "username": "alice",
        "password": "Secret1!",
    }
    values.update(overrides)
    return Target(**values)


def test_campaign_records_unavailable_reserved_unknown_and_legacy_outcomes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class LegacyRunner:
        def run(self, *args: Any, **kwargs: Any) -> str:
            return "legacy-complete"

    class ModernRunner:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, bool]:
            return {"ok": True}

    registry = {
        "unavailable": SimpleNamespace(runner=None),
        "legacy": SimpleNamespace(runner=LegacyRunner()),
        "modern": Capability(
            id="modern",
            summary="test capability",
            runner=ModernRunner(),
            safety=SafetyProfile(),
        ),
    }
    monkeypatch.setattr(campaign_run.capability_registry, "get", registry.get)
    monkeypatch.setattr(
        campaign_run,
        "execute_capability",
        lambda *args, **kwargs: {"ok": True, "executed": True},
    )
    monkeypatch.setattr(
        campaign_run,
        "verify_scoped_approval",
        lambda *args, **kwargs: {"approval_id": "A-1", "approved_by": "reviewer"},
    )
    session = Session(tmp_path / "campaign")
    plan = tmp_path / "campaign-plan.json"
    plan.write_text(
        json.dumps(
            {
                "phases": [
                    {"id": "unavailable", "capability": "unavailable"},
                    {"id": "reserved", "capability": "legacy", "params": {"session": "spoof"}},
                    {"id": "unknown", "capability": "missing", "destructive": True},
                    {"id": "modern", "capability": "modern"},
                    {"id": "legacy", "capability": "legacy"},
                ]
            }
        ),
        encoding="utf-8",
    )
    result = campaign_run.CampaignRun().run(
        _target(),
        session,
        AttackGraph(),
        force=True,
        plan=plan,
    )

    phases = {row["id"]: row for row in result["phases"]}
    assert phases["unavailable"]["error"] == "unknown capability: unavailable"
    assert "reserved execution parameters" in phases["reserved"]["error"]
    assert phases["unknown"]["error"] == "unknown capability: missing"
    assert phases["modern"]["ok"] is True
    assert phases["legacy"]["ok"] is True
    assert result["completed"] == 2


@pytest.mark.parametrize("error", [OSError("refused"), TimeoutError("slow")])
def test_credential_free_tcp_probe_reports_connection_errors(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(credential_free.socket, "create_connection", fail)
    result = credential_free._tcp_probe("192.0.2.10", 389, 0.1)
    assert result == {
        "port": 389,
        "service": "ldap",
        "reachable": False,
        "error": type(error).__name__,
    }


def test_credential_free_tcp_probe_reports_reachable_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Socket:
        def __enter__(self) -> Socket:
            return self

        def __exit__(self, *args: Any) -> None:
            return None

    monkeypatch.setattr(
        credential_free.socket, "create_connection", lambda *args, **kwargs: Socket()
    )
    assert credential_free._tcp_probe("192.0.2.10", 443, 0.1) == {
        "port": 443,
        "service": "https",
        "reachable": True,
    }


def test_anonymous_ldap_probe_uses_domain_fallback_and_keeps_probe_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Info:
        other: dict[str, list[str]] = {}

    class FakeServer:
        info = Info()

    class FakeConnection:
        bound = True
        entries: list[object] = []

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.searches: list[str] = []
            self.unbound = False

        def search(self, base: str, query: str, **kwargs: Any) -> bool:
            self.searches.append(query)
            if "objectCategory=person" in query:
                raise LDAPException("anonymous read denied")
            return False

        def unbind(self) -> None:
            self.unbound = True

    conn: FakeConnection | None = None

    def build_connection(*args: Any, **kwargs: Any) -> FakeConnection:
        nonlocal conn
        conn = FakeConnection()
        return conn

    monkeypatch.setattr(credential_free, "Server", lambda *args, **kwargs: FakeServer())
    monkeypatch.setattr(credential_free, "Connection", build_connection)
    result = credential_free.AnonymousLdapProbe().run(
        Target(domain="child.corp.test", dc_ip="192.0.2.10"),
        Session(tmp_path / "ldap"),
        AttackGraph(),
    )

    assert result["ok"] is True
    assert result["default_naming_context"] == "DC=child,DC=corp,DC=test"
    assert any(item.get("error") == "LDAPException" for item in result["checks"])
    assert conn is not None and conn.unbound


def test_anonymous_ldap_probe_returns_redacted_failure_when_bind_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeServer:
        info = SimpleNamespace(other={})

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise OSError("directory unavailable")

    monkeypatch.setattr(credential_free, "Server", lambda *args, **kwargs: FakeServer())
    monkeypatch.setattr(credential_free, "Connection", fail)
    result = credential_free.AnonymousLdapProbe().run(
        _target(username=None, password=None),
        Session(tmp_path / "ldap-failed"),
        AttackGraph(),
    )
    assert result == {
        "ok": False,
        "authentication": "anonymous",
        "checks": [],
        "error": "OSError",
    }


def test_credential_inventory_rejects_escape_paths_for_export_and_purge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    session = Session(tmp_path / "inventory")
    exported = credential_inventory._export_items(
        session, names=["../outside.json", "missing.json"], include_secrets=False
    )
    assert exported["errors"] == [
        {"name": "../outside.json", "error": "session path escapes session root"},
        {"name": "missing.json", "error": "not found in vault or session files"},
    ]
    purged = credential_inventory._purge(
        session, names=["../outside.json"], purge_all=False, purge_files=True
    )
    assert purged == {"removed_vault": [], "removed_files": [], "purge_all": False}


class _RelayAttr:
    def __init__(self, value: Any = None) -> None:
        self.value = value
        self.values = value if isinstance(value, list) else ([] if value is None else [value])
        self.raw_values = self.values

    def __bool__(self) -> bool:
        return self.value is not None and self.value != []

    def __str__(self) -> str:
        return str(self.value)


class _RelayEntry:
    def __init__(self, **values: Any) -> None:
        self._values = {key: _RelayAttr(value) for key, value in values.items()}

    def __getattr__(self, name: str) -> _RelayAttr:
        return self._values.get(name, _RelayAttr())


class _RelayConnection:
    def __init__(self, entry: _RelayEntry, *, add_ok: bool = True, modify_ok: bool = True) -> None:
        self.entry = entry
        self.add_ok = add_ok
        self.modify_ok = modify_ok
        self.entries: list[_RelayEntry] = []
        self.result = {"result": 0}
        self.modified = False
        self.unbound = False

    def search(self, *args: Any, **kwargs: Any) -> bool:
        self.entries = [self.entry]
        return True

    def add(self, *args: Any, **kwargs: Any) -> bool:
        return self.add_ok

    def modify(self, *args: Any, **kwargs: Any) -> bool:
        self.modified = True
        return self.modify_ok

    def unbind(self) -> None:
        self.unbound = True


def _dcshadow_entry(spns: list[str]) -> _RelayEntry:
    return _RelayEntry(
        sAMAccountName="ROGUE$",
        distinguishedName="CN=ROGUE,DC=corp,DC=test",
        dNSHostName="rogue.corp.test",
        servicePrincipalName=spns,
    )


def test_dcshadow_prepares_without_duplicate_spns_or_native_push(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dns = "rogue.corp.test"
    existing = [
        f"GC/{dns}",
        f"E3514235-4B06-11D1-AB04-00C04FC2DCD2/{dns}",
        f"ldap/{dns}",
    ]
    conn = _RelayConnection(_dcshadow_entry(existing))
    monkeypatch.setattr(
        relay_ops,
        "ldap_connect",
        lambda target: (conn, "DC=corp,DC=test", "CN=Configuration,DC=corp,DC=test"),
    )
    result = relay_ops.DcShadow().run(
        _target(),
        Session(tmp_path / "dcshadow-prepared"),
        AttackGraph(),
        force=True,
        computer="ROGUE$",
    )
    assert result["ok"] is True
    assert result["status"] == "prepared"
    assert result["replication_push"]["spns_added"] == []
    assert conn.modified is False
    assert conn.unbound


def test_dcshadow_continues_when_spn_registration_is_denied(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    conn = _RelayConnection(_dcshadow_entry([]), modify_ok=False)
    monkeypatch.setattr(
        relay_ops,
        "ldap_connect",
        lambda target: (conn, "DC=corp,DC=test", "CN=Configuration,DC=corp,DC=test"),
    )
    result = relay_ops.DcShadow().run(
        _target(),
        Session(tmp_path / "dcshadow-spn-denied"),
        AttackGraph(),
        force=True,
        computer="ROGUE$",
    )
    assert result["ok"] is True
    assert result["replication_push"]["spn_ok"] is False


@pytest.mark.parametrize("push_result", [{"ok": False, "error": "denied"}, "missing"])
def test_dcshadow_preserves_native_push_failure_details(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, push_result: Any
) -> None:
    conn = _RelayConnection(_dcshadow_entry([]))
    monkeypatch.setattr(
        relay_ops,
        "ldap_connect",
        lambda target: (conn, "DC=corp,DC=test", "CN=Configuration,DC=corp,DC=test"),
    )
    if push_result == "missing":
        from adaf_attack.core.impacket_helper import ImpacketMissing

        def fail_push(*args: Any, **kwargs: Any) -> Any:
            raise ImpacketMissing("IDL_DRSAddEntry")

        monkeypatch.setattr("adaf_attack.core.drs_addentry.add_entry_modify", fail_push)
    else:
        monkeypatch.setattr(
            "adaf_attack.core.drs_addentry.add_entry_modify", lambda *args, **kwargs: push_result
        )
    result = relay_ops.DcShadow().run(
        _target(),
        Session(tmp_path / f"dcshadow-{str(push_result)[:4]}"),
        AttackGraph(),
        force=True,
        computer="ROGUE$",
        object="CN=Alice,DC=corp,DC=test",
        attribute="description",
        value="pushed",
    )
    assert result["ok"] is False
    assert result["replication_push"]["performed"] is False
    if push_result == "missing":
        assert "Impacket required" in result["replication_push"]["note"]
    else:
        assert result["replication_push"]["error"] == "denied"


@pytest.mark.parametrize(
    "extras, message",
    [
        (["--unknown"], "not allowed"),
        (["--http-port"], "requires a value"),
        (["--https-port", "-1"], "non-option value"),
        (["--http-port", "abc"], "integer port"),
        (["--http-port", "65536"], "1-65535"),
    ],
)
def test_ntlm_relay_rejects_unsafe_extra_options(extras: list[str], message: str) -> None:
    with pytest.raises(RuntimeError, match=message):
        ntlm_relay._validate_extras(extras)


def test_ntlm_relay_reports_invalid_shell_extras_before_launch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ntlm_relay.shutil, "which", lambda name: "relay-bin")
    with pytest.raises(RuntimeError, match="invalid ntlm-relay extras"):
        ntlm_relay.NtlmRelay().run(
            _target(),
            Session(tmp_path / "relay-invalid"),
            AttackGraph(),
            force=True,
            relay_targets="dc",
            extras="'unterminated",
        )


def test_unpac_parser_reports_decrypt_failure_and_non_counting_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "adaf_attack.core.unpac.decrypt_pac_credential_info",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad key")),
    )
    assert unpac_the_hash._extract_nt_from_pac(b"pac", "aa" * 32) == {
        "status": "not_recovered",
        "reason": "PAC_CREDENTIAL_INFO decryption failed",
    }
    assert unpac_the_hash._pac_buffer_count({"cBuffers": "not-an-int"}, object()) == 0


def test_unpac_ccache_context_removes_absent_environment_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    with unpac_the_hash._temporary_krb5ccname("temporary.ccache"):
        assert unpac_the_hash.os.environ["KRB5CCNAME"] == "temporary.ccache"
    assert "KRB5CCNAME" not in unpac_the_hash.os.environ


def test_unpac_parser_ignores_uninspectable_pac_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    pac = ModuleType("impacket.krb5.pac")

    class FakePac:
        def __init__(self, data: bytes) -> None:
            self.buffers = [object()]

        def __getitem__(self, key: str) -> Any:
            if key == "cBuffers":
                return 1
            if key == "Buffers":
                return self.buffers
            raise KeyError(key)

    class BrokenInfo:
        def __getitem__(self, key: str) -> Any:
            raise ValueError("bad field")

        def __len__(self) -> int:
            return 1

    pac.PACTYPE = FakePac
    pac.PAC_INFO_BUFFER = lambda value: BrokenInfo()
    pac.PAC_CREDENTIAL_INFO = lambda value: object()
    monkeypatch.setitem(sys.modules, "impacket.krb5.pac", pac)
    assert unpac_the_hash._extract_nt_from_pac(b"malformed") is None


def test_unpac_run_reports_missing_key_and_u2u_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(unpac_the_hash, "require_impacket", lambda name: None)

    class Pkinit:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ccache": str(tmp_path / "ticket.ccache")}

    import adaf_attack.capabilities.pkinit_auth as pkinit_auth

    monkeypatch.setattr(pkinit_auth, "PkinitAuth", Pkinit)
    no_key = unpac_the_hash.UnpacTheHash().run(
        _target(), Session(tmp_path / "unpac-no-key"), AttackGraph(), sam="alice", pfx="x.pfx"
    )
    assert no_key["ok"] is False
    assert "AS-REP key unavailable" in no_key["pac_credential_info"]["reason"]

    class WithKey:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ccache": str(tmp_path / "ticket.ccache"), "asrep_key": "bb" * 32}

    monkeypatch.setattr(pkinit_auth, "PkinitAuth", WithKey)
    monkeypatch.setattr(
        unpac_the_hash,
        "request_u2u_pac",
        lambda **kwargs: {"ok": False, "error": "KDC denied U2U"},
    )
    failed = unpac_the_hash.UnpacTheHash().run(
        _target(), Session(tmp_path / "unpac-failed"), AttackGraph(), sam="alice", pfx="x.pfx"
    )
    assert failed["status"] == "not_recovered"
    assert failed["pac_credential_info"] == {
        "status": "not_recovered",
        "reason": "KDC denied U2U",
        "asrep_key_present": True,
    }


def test_next_actions_handles_empty_fallbacks_and_remaps_plan_commands(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Graph:
        nodes = {"evidence": {}}

        def rank_exploit_chains(self, limit: int) -> list[dict[str, Any]]:
            return [
                {"terminal_relation": "HasSPN", "edges": ["HasSPN"], "score": 1},
                {"terminal_relation": "CanASREP", "edges": ["CanASREP"], "score": 2},
                {"terminal_relation": "Unknown", "edges": ["Unknown"], "score": 3},
                {"terminal_relation": "Unknown", "edges": ["Unknown"], "score": 4},
                {"terminal_relation": "NoExamples", "edges": ["NoExamples"], "score": 5},
                {"terminal_relation": "ESC9", "edges": ["ESC9"], "score": 6},
            ]

    def fake_commands(chain: dict[str, Any], target: Target, **kwargs: Any) -> list[dict[str, Any]]:
        relation = chain["terminal_relation"]
        if relation == "NoExamples":
            return []
        if relation == "ESC9":
            return []
        if relation == "HasSPN":
            command = "adaf-attack plan HasSPN -d corp.test"
        elif relation == "CanASREP":
            command = "review manually"
        else:
            command = "adaf-attack plan Unknown -d corp.test"
        return [
            {
                "capability": f"plan:{relation}",
                "risk": "unknown",
                "approval_required": False,
                "command": command,
                "fallback": True,
            }
        ]

    monkeypatch.setattr(next_actions, "build_exploit_commands", fake_commands)
    result = next_actions.NextActions().run(
        _target(), Session(tmp_path / "actions"), Graph(), limit=10
    )
    by_relation = {item["terminal_relation"]: item for item in result["actions"]}
    assert result["count"] == 4
    assert by_relation["HasSPN"]["command"] == "adaf-attack plan kerberoast -d corp.test"
    assert by_relation["CanASREP"]["command"] == "review manually"
    assert sum(item["terminal_relation"] == "Unknown" for item in result["actions"]) == 1


def test_password_spray_applies_delay_after_each_attempt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Conn:
        def __init__(self) -> None:
            self.unbind_count = 0

        def unbind(self) -> None:
            self.unbind_count += 1

    conn = Conn()
    sleeps: list[float] = []
    monkeypatch.setattr(
        password_spray, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None)
    )
    monkeypatch.setattr(
        password_spray,
        "_read_lockout_policy",
        lambda *args: {"lockout_threshold": 5, "observation_window_seconds": 60},
    )
    monkeypatch.setattr(password_spray, "_load_users", lambda *args: ["alice"])
    monkeypatch.setattr(password_spray, "_account_lockout_state", lambda *args: (0, None))
    monkeypatch.setattr(password_spray, "_try_bind", lambda *args: (False, "invalid"))
    monkeypatch.setattr(password_spray.time, "sleep", lambda value: sleeps.append(value))
    result = password_spray.PasswordSpray().run(
        _target(),
        Session(tmp_path / "spray"),
        AttackGraph(),
        spray_password="Secret123!",
        delay_seconds=0.25,
    )
    assert result["attempt_count"] == 1
    assert sleeps == [0.25]
    assert conn.unbind_count == 1


def test_workflow_target_normalizes_computer_sam_and_rejects_credentialless_match() -> None:
    built = workflow_wrappers._controlled_computer_target(
        _target(username="OTHER", password=None), "OTHER", {"computer_password": "pw"}
    )
    assert built is not None and built.username == "OTHER$"
    assert (
        workflow_wrappers._controlled_computer_target(
            _target(username="OTHER", password=None), "OTHER", {}
        )
        is None
    )


def test_adcs_native_forge_reports_pfx_without_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from cryptography.hazmat.primitives.serialization import pkcs12

    pfx = tmp_path / "cert-only.pfx"
    pfx.write_bytes(b"mocked-pfx")
    monkeypatch.setattr(
        pkcs12,
        "load_key_and_certificates",
        lambda *args, **kwargs: (None, object(), None),
    )
    result = adcs_esc._forge_golden_cert_native(
        Session(tmp_path / "adcs"), ca_pfx=str(pfx), upn="administrator@corp.test"
    )
    assert result == {"ok": False, "method": "native-forge", "error": "CA PFX missing key or cert"}


def test_esc_chain_accepts_already_prefixed_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        adcs_esc,
        "_run_certipy",
        lambda *args, **kwargs: {"ok": False, "method": "playbook-only", "playbook": "x"},
    )
    result = esc_chain.EscChain().run(
        _target(),
        Session(tmp_path / "esc-chain"),
        AttackGraph(),
        force=True,
        template="UserTemplate",
        ca="CorpCA",
        esc="ESC9",
    )
    assert result["esc"] == "ESC9"
    assert result["cert_request"]["ok"] is False


def test_attack_paths_public_enrichment_wrapper_adds_commands() -> None:
    chains = [{"terminal_relation": "HasSPN", "start": "USER@alice@CORP", "end": "USER@alice@CORP"}]
    from adaf_attack.capabilities import attack_paths

    result = attack_paths.emit_ranked_paths_for_target(chains, _target())
    assert result[0]["example_commands"]
