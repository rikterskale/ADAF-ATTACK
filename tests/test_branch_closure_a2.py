"""Branch-closure tests for joined_workflows and esc_chain."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import adaf_attack.capabilities.esc_chain as esc_chain
import adaf_attack.capabilities.joined_workflows as joined_workflows
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.rbcd_sd import build_allowed_to_act_sd
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def __bool__(self) -> bool:
        return self.value is not None and self.value != []

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **attributes: Any) -> None:
        self._attributes = {name: _Attr(value) for name, value in attributes.items()}

    def __getattr__(self, name: str) -> _Attr:
        return self._attributes.get(name.replace("_", "-"), self._attributes.get(name, _Attr()))

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _Conn:
    def __init__(
        self, by_filter: dict[str, list[_Entry]] | None = None, modify_ok: bool = True
    ) -> None:
        self.by_filter = by_filter or {}
        self.entries: list[_Entry] = []
        self.result = {"result": 0, "description": "success"}
        self.modify_ok = modify_ok
        self.unbound = False

    def search(self, base: str, search_filter: str, **kwargs: Any) -> bool:
        for key, entries in self.by_filter.items():
            if key in search_filter or search_filter in key or key in base:
                self.entries = entries
                return True
        self.entries = []
        return True

    def modify(self, dn: str, changes: Any) -> bool:
        return self.modify_ok

    def unbind(self) -> None:
        self.unbound = True


def _target(**kwargs: Any) -> Target:
    values = {
        "domain": "corp.test",
        "dc_ip": "10.0.0.1",
        "username": "alice",
        "password": "Secret1!",
    }
    values.update(kwargs)
    return Target(**values)


def test_targeted_kerberoast_skips_spn_restore_without_previous(
    monkeypatch: Any, tmp_path: Path
) -> None:
    class _Write:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            if kwargs.get("clear"):
                return {"ok": True}
            return {"ok": True}

    class _Roast:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"tickets": [{"account": "bob"}]}

    monkeypatch.setattr(joined_workflows, "WriteSpn", _Write)
    monkeypatch.setattr(joined_workflows, "Kerberoast", _Roast)

    result = joined_workflows.TargetedKerberoast().run(
        _target(), Session(tmp_path), AttackGraph(), force=True, sam="bob"
    )

    assert result["ok"] is True
    assert result["roast"] == {"tickets": [{"account": "bob"}]}
    assert result["revert"] == {"ok": True}


def test_dcsync_grant_workflow_handles_failed_modify(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _Conn(modify_ok=False)
    monkeypatch.setattr(
        joined_workflows, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None)
    )
    monkeypatch.setattr(
        joined_workflows, "fetch_sd", lambda *_a, **_k: build_allowed_to_act_sd("S-1-5-21-1-2-3-9")
    )

    class _Dcsync:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            raise AssertionError("dcsync must not run when the grant fails")

    monkeypatch.setattr(joined_workflows, "Dcsync", _Dcsync)

    result = joined_workflows.DcsyncGrantWorkflow().run(
        _target(), Session(tmp_path), AttackGraph(), force=True, principal_sid="S-1-5-21-1-2-3-4"
    )

    assert result["ok"] is False
    assert result["grant"]["ok"] is False
    assert result["dcsync"] == {"skipped": "grant_failed"}


def test_nopac_workflow_records_no_rollback_when_rename_modify_fails(
    monkeypatch: Any, tmp_path: Path
) -> None:
    class _Maq:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True, "sam": "NEW$", "dn": "CN=NEW,DC=corp,DC=test"}

    conn = _Conn(
        {
            "NEW$": [_Entry(sAMAccountName="NEW$", distinguishedName="CN=NEW,DC=corp,DC=test")],
            "DC01": [_Entry(sAMAccountName="DC01$", distinguishedName="CN=DC01,DC=corp,DC=test")],
        },
        modify_ok=False,
    )
    monkeypatch.setattr(joined_workflows, "MaqAddComputer", _Maq)
    monkeypatch.setattr(
        joined_workflows, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None)
    )
    session = Session(tmp_path)

    result = joined_workflows.NopacWorkflow().run(
        _target(), session, AttackGraph(), force=True, dc="DC01$"
    )

    assert result["ok"] is False
    assert result["rename"]["ok"] is False
    assert result["restore"] == {"skipped": True}
    assert not session.path("cleanup.json").exists()


def test_esc_chain_signals_ignore_non_list_raw_values() -> None:
    signals = esc_chain._signals_from_template({"esc_tags": "ESC1", "esc1_candidate": True})
    assert signals == ["ESC1"]


def _install_cert_mocks(
    monkeypatch: Any, cert_result: dict[str, Any], pkinit_result: dict[str, Any]
) -> None:
    class _Cert:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return cert_result

    class _Pkinit:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return pkinit_result

    cert_module = ModuleType("adaf_attack.capabilities.cert_request")
    cert_module.CertRequest = _Cert  # type: ignore[attr-defined]
    pkinit_module = ModuleType("adaf_attack.capabilities.pkinit_auth")
    pkinit_module.PkinitAuth = _Pkinit  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "adaf_attack.capabilities.cert_request", cert_module)
    monkeypatch.setitem(sys.modules, "adaf_attack.capabilities.pkinit_auth", pkinit_module)


def test_esc_chain_prefers_explicit_ca_and_skips_ca_selection(
    monkeypatch: Any, tmp_path: Path
) -> None:
    prior = tmp_path / "prior"
    prior.mkdir()
    (prior / "adcs-enum.json").write_text(
        json.dumps({"templates": [{"cn": "UserTemplate", "esc_tags": ["ESC1"]}]}),
        encoding="utf-8",
    )
    _install_cert_mocks(monkeypatch, {"pfx": "issued.pfx"}, {"ok": True})

    result = esc_chain.EscChain().run(
        _target(),
        Session(tmp_path),
        AttackGraph(),
        ca="CORP-CA",
        adcs_session=prior,
    )

    assert result["template"] == "UserTemplate"
    assert result["ca"] == "CORP-CA"
    assert result["picked"]["signals"] == ["ESC1"]
    assert result["pkinit_auth"]["ok"] is True


def test_esc_chain_selects_first_ca_publishing_template(monkeypatch: Any, tmp_path: Path) -> None:
    prior = tmp_path / "prior"
    prior.mkdir()
    (prior / "adcs-enum.json").write_text(
        json.dumps(
            {
                "templates": [{"cn": "UserTemplate", "esc_tags": ["ESC1"]}],
                "cas": [
                    {"cn": "UNRELATED-CA", "templates": ["OtherTemplate"]},
                    {"cn": "PUBLISHING-CA", "templates": ["UserTemplate"]},
                ],
            }
        ),
        encoding="utf-8",
    )
    _install_cert_mocks(monkeypatch, {"pfx": "issued.pfx"}, {"ok": True})

    result = esc_chain.EscChain().run(
        _target(), Session(tmp_path), AttackGraph(), adcs_session=prior
    )

    assert result["ca"] == "PUBLISHING-CA"
    assert result["pkinit_auth"]["ok"] is True


def test_esc_chain_skips_pkinit_when_cert_request_yields_no_pfx(
    monkeypatch: Any, tmp_path: Path
) -> None:
    _install_cert_mocks(monkeypatch, {"ok": False}, {"ok": True})

    result = esc_chain.EscChain().run(
        _target(), Session(tmp_path), AttackGraph(), template="T", ca="CA"
    )

    assert result["pkinit_auth"] == {}
    assert result["cert_request"]["ok"] is False
