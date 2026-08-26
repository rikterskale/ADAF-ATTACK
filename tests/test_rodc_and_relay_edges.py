"""Offline tests for RODC delegation and relay execution branches."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

import adaf_attack.capabilities.coerce as coerce
import adaf_attack.capabilities.identity_bridge as identity_bridge
import adaf_attack.capabilities.ntlm_relay as ntlm_relay
import adaf_attack.capabilities.rodc_delegation as rodc_delegation
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value
        self.values = value if isinstance(value, list) else ([] if value is None else [value])

    def __bool__(self) -> bool:
        return self.value is not None

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **values: Any) -> None:
        self.values = {key: _Attr(value) for key, value in values.items()}

    def __getattr__(self, name: str) -> _Attr:
        return self.values.get(name, self.values.get(name.replace("-", "_"), _Attr()))

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10")


def test_rodc_enumerates_computers_krbtgt_and_delegation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Conn:
        entries: list[Any] = []

        def search(self, _base: str, query: str, **kwargs: Any) -> None:
            if "67108864" in query:
                self.entries = [
                    _Entry(
                        sAMAccountName="RODC01$",
                        distinguishedName="CN=RODC",
                        dNSHostName="rodc",
                        userAccountControl=0x4000000,
                        **{
                            "msDS-RevealOnDemandGroup": ["CN=Allowed"],
                            "msDS-NeverRevealGroup": ["CN=Denied"],
                            "msDS-AuthenticatedAtDC": ["CN=User"],
                            "managedBy": "CN=Admin",
                        },
                    )
                ]
            elif "krbtgt_" in query:
                self.entries = [
                    _Entry(
                        sAMAccountName="krbtgt_1",
                        distinguishedName="CN=krbtgt",
                        **{"msDS-SecondaryKrbTgtNumber": 1},
                    )
                ]
            else:
                self.entries = [
                    _Entry(
                        sAMAccountName="APP$",
                        distinguishedName="CN=APP",
                        userAccountControl=0x1080000,
                        **{
                            "msDS-AllowedToDelegateTo": ["cifs/dc"],
                            "msDS-AllowedToActOnBehalfOfOtherIdentity": "x",
                        },
                    )
                ]

        def unbind(self) -> None:
            return None

    monkeypatch.setattr(rodc_delegation, "ldap_connect", lambda target: (Conn(), "DC=corp", None))
    result = rodc_delegation.RodcDelegation().run(_target(), Session(tmp_path), AttackGraph())
    assert result["count"] == 3 and result["rodc_computers"][0]["partial_secrets"]


def test_ntlm_relay_executes_offline_and_ingests_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())
    session = Session(tmp_path)
    binary = tmp_path / "relay.exe"
    binary.write_text("", encoding="utf-8")
    monkeypatch.setattr(ntlm_relay.shutil, "which", lambda name: str(binary))

    class Proc:
        pid = 1
        returncode = 0

        def wait(self, timeout: int) -> None:
            return None

    monkeypatch.setattr(ntlm_relay.subprocess, "Popen", lambda *args, **kwargs: Proc())
    result = ntlm_relay.NtlmRelay().run(
        _target(),
        session,
        AttackGraph(),
        force=True,
        relay_targets="server1,server2",
        duration_seconds=1,
    )
    assert result["return_code"] == 0 and len(result["relay_targets"]) == 2
    with pytest.raises(RuntimeError, match="not allowed"):
        ntlm_relay._build_argv(_target(), ["x"], 445, "out", ["--x"])
    artifact = tmp_path / "hashes.txt"
    artifact.write_text(
        "user::CORP:00000000000000000000000000000000:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nNTLMv2 payload",
        encoding="utf-8",
    )
    assert len(ntlm_relay._ingest_artifacts_to_vault(session, [str(artifact), "missing"])) == 2
    with pytest.raises(RuntimeError, match="destructive"):
        ntlm_relay.NtlmRelay().run(_target(), session, AttackGraph())


def test_hybrid_identity_signals_cover_cloud_and_exchange_markers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Conn:
        entries = [
            _Entry(
                sAMAccountName="sync$",
                distinguishedName="CN=sync,DC=corp,DC=test",
                description="Azure AD Connect pass-through authentication seamless sso password hash sync",
                servicePrincipalName=["AzureADKerberos"],
                **{
                    "msDS-ExternalDirectoryObjectId": "id",
                    "msDS-ConsistencyGuid": "guid",
                    "msExchRemoteRecipientType": 4,
                    "userPrincipalName": "sync@tenant.onmicrosoft.com",
                    "proxyAddresses": ["smtp:user#EXT#@tenant.onmicrosoft.com"],
                },
            )
        ]

        def search(self, *args: Any, **kwargs: Any) -> None:
            return None

        def unbind(self) -> None:
            return None

    monkeypatch.setattr(identity_bridge, "ldap_connect", lambda target: (Conn(), "DC=corp", None))
    result = identity_bridge.HybridSignals().run(_target(), Session(tmp_path), AttackGraph())
    assert result["count"] >= 5 and result["posture"]["azure_ad_connect_hint"]


def test_coercion_allowlist_sources_and_host_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    map_file = tmp_path / "coercion-map.json"
    map_file.write_text(
        '{"hosts": [{"host": "print.corp", "spooler": true}, {"dns": "off.corp"}]}',
        encoding="utf-8",
    )
    assert coerce._load_allowlist({"allow_hosts": "a,a,b"}, None) == ["a", "b"]
    assert coerce._load_allowlist({"hosts": ["a", "b"], "host": "c"}, None) == ["a", "b"]
    assert coerce._load_allowlist({"coercion_session": map_file}, None) == ["print.corp"]
    assert coerce._load_allowlist({}, "dc.corp") == []
    monkeypatch.setattr(coerce, "require_impacket", lambda name: None)
    monkeypatch.setattr(coerce, "_trigger", lambda *args: {"ok": True})
    with pytest.raises(RuntimeError, match="not in the approved"):
        coerce.Coerce().run(
            _target(),
            Session(tmp_path / "session"),
            AttackGraph(),
            listener="l",
            host="other",
            allow_hosts="ok",
        )
