"""Deep coverage sweep for capability run() branches: bloodhound, asrep,
kerberoast, gmsa/laps, ldap_enum, rbcd, acl_enum, shadow_creds, gpo_abuse,
esc6, and core/acl edge cases."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from adaf_attack.capabilities.bloodhound_export import BloodhoundExport, _hydrate_graph_from_session
from adaf_attack.capabilities.identity_bridge import BloodhoundImport
from adaf_attack.core.acl import _mask_to_rights, _sid_to_str
from adaf_attack.core.bloodhound import (
    _domain_from_id,
    _node_properties,
    _object_id,
    export_bloodhound,
    import_bloodhound,
    save_bloodhound,
    save_bloodhound_zip,
)
from adaf_attack.core.graph import AttackGraph, Node
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

# --------------------------- bloodhound core ---------------------------


def test_bloodhound_helpers() -> None:
    assert _domain_from_id("USER@ALICE@CORP") == "CORP"
    assert _domain_from_id("DOMAIN@CORP") == "CORP"
    assert _domain_from_id("STANDALONE") == ""


def test_bloodhound_object_id_and_properties() -> None:
    node = Node(id="USER@A@C", kind="User", properties={"sid": "S-1-5-21-1", "sam": "alice"})
    assert _object_id(node) == "S-1-5-21-1"
    props = _node_properties(node)
    assert props["name"] == "alice"
    node2 = Node(id="X@Y", kind="Base", properties={"dn": "cn=x"})
    props2 = _node_properties(node2)
    assert "distinguishedname" in props2


def test_export_import_bloodhound_roundtrip(tmp_path: Path) -> None:
    g = AttackGraph()
    g.add_node("USER@A@C", "User", sam="a", admin_count=1, sid="S-1-5-21-100")
    g.add_node("DOMAIN@C", "Domain")
    g.add_edge("USER@A@C", "DOMAIN@C", "DCSync")
    doc = export_bloodhound(g, domain="corp.test")
    assert doc["meta"]["node_count"] == 2

    json_path = save_bloodhound(g, tmp_path / "bh.json", domain="corp.test")
    assert json_path.is_file()

    zip_path = save_bloodhound_zip(g, tmp_path / "bh.zip", domain="corp.test")
    assert zip_path.is_file()

    # import path
    g2 = AttackGraph()
    counts = import_bloodhound(json_path, g2)
    assert counts["nodes"] > 0

    # malformed data still handled (dict-shape variants)
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps({"graph": {"nodes": ["not-dict"], "edges": ["nope"]}}), encoding="utf-8"
    )
    g3 = AttackGraph()
    counts_bad = import_bloodhound(bad, g3)
    assert counts_bad == {"nodes": 0, "edges": 0}


def test_bloodhound_import_capability(monkeypatch: Any, tmp_path: Path) -> None:
    artifact = tmp_path / "bh.json"
    artifact.write_text(
        json.dumps(
            {"graph": {"nodes": [{"id": "X@Y", "kinds": ["User"], "properties": {}}], "edges": []}}
        ),
        encoding="utf-8",
    )
    session = Session(base_dir=tmp_path / "sess")
    result = BloodhoundImport().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        artifact=str(artifact),
    )
    assert Path(result["json_path"]).is_file()
    assert Path(result["zip_path"]).is_file()


def test_bloodhound_import_missing_artifact(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="requires --artifact"):
        BloodhoundImport().run(
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            Session(base_dir=tmp_path / "s"),
            AttackGraph(),
        )


def test_bloodhound_export_hydrates_from_session(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "sess")
    seed = AttackGraph()
    seed.add_node("USER@A@C", "User", sam="a")
    seed.save(session.path("graph.json"))
    graph = AttackGraph()
    result = BloodhoundExport().run(Target(domain="corp.test", dc_ip="10.0.0.1"), session, graph)
    assert Path(result["json_path"]).is_file()
    assert result["summary"]["nodes"] >= 1


def test_hydrate_graph_from_session_missing(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "empty")
    assert _hydrate_graph_from_session(session, AttackGraph()) is False


def test_hydrate_graph_from_session_corrupt(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "corrupt")
    session.path("graph.json").write_text("nope", encoding="utf-8")
    assert _hydrate_graph_from_session(session, AttackGraph()) is False


# --------------------------- core/acl remaining branches ---------------------------


def test_sid_to_str_impacket_path() -> None:
    from impacket.ldap.ldaptypes import LDAP_SID

    sid = LDAP_SID()
    sid.fromCanonical("S-1-5-21-100-200-300-1105")
    assert _sid_to_str(sid.getData()) == "S-1-5-21-100-200-300-1105"


def test_mask_to_rights_generic_all_and_writes() -> None:
    from adaf_attack.core.acl import (
        GENERIC_ALL,
        GENERIC_WRITE,
        WRITE_DACL,
        WRITE_OWNER,
    )

    assert _mask_to_rights(GENERIC_ALL, None) == ["GenericAll"]
    # 0x0F01FF alt path
    assert _mask_to_rights(0x0F01FF, None) == ["GenericAll"]
    rights = _mask_to_rights(WRITE_DACL | WRITE_OWNER | GENERIC_WRITE, None)
    assert {"WriteDacl", "WriteOwner", "GenericWrite"} <= set(rights)


# --------------------------- asrep_roast (no impacket LDAP call) ---------------------------


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def __bool__(self) -> bool:
        return self.value is not None

    def __str__(self) -> str:
        return str(self.value)

    def __iter__(self) -> Any:
        return iter(self.value if isinstance(self.value, list) else [])


class _Entry:
    def __init__(self, **v: Any) -> None:
        self._v = {k: _Attr(val) for k, val in v.items()}

    def __getattr__(self, name: str) -> _Attr:
        return self._v.get(name, _Attr())

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _LdapConn:
    def __init__(self, entries: list[_Entry] | None = None) -> None:
        self.entries = entries or []
        self.unbound = False

    def search(self, *a: Any, **k: Any) -> None:
        pass

    def unbind(self) -> None:
        self.unbound = True


def test_asrep_roast_captures_ldap_users_and_swallows_kdc_errors(
    monkeypatch: Any, tmp_path: Path
) -> None:
    import adaf_attack.capabilities.asrep_roast as ar

    entries = [_Entry(sAMAccountName="alice"), _Entry(sAMAccountName="bob")]
    conn = _LdapConn(entries)
    monkeypatch.setattr(ar, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    # sendReceive fails deterministically for every candidate
    import impacket.krb5.kerberosv5 as kv5

    monkeypatch.setattr(
        kv5, "sendReceive", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("KDC error"))
    )

    session = Session(base_dir=tmp_path / "s")
    graph = AttackGraph()
    result = ar.AsrepRoast().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        graph,
        include_secrets=True,
    )
    assert result["count"] == 2
    assert all("error" in t for t in result["tickets"])


def test_asrep_roast_include_secrets_writes_hashes(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.capabilities.asrep_roast as ar

    conn = _LdapConn([_Entry(sAMAccountName="carol")])
    monkeypatch.setattr(ar, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    # Fake a successful sendReceive → decoder → we monkey-patch the whole decoder path.
    fake_asrep = SimpleNamespace()

    class _EncPart:
        def __getitem__(self, key: str) -> Any:
            if key == "etype":
                return 23
            if key == "cipher":
                return bytes(range(32))
            raise KeyError(key)

    fake_asrep.__getitem__ = lambda self, k: _EncPart() if k == "enc-part" else None
    # Attach __getitem__ via type wrapper
    fake = type(
        "_R", (), {"__getitem__": lambda self, k: _EncPart() if k == "enc-part" else None}
    )()

    import impacket.krb5.kerberosv5 as kv5
    from pyasn1.codec.der import decoder

    monkeypatch.setattr(kv5, "sendReceive", lambda *a, **k: b"any-bytes")
    monkeypatch.setattr(decoder, "decode", lambda data, asn1Spec=None: (fake, b""))

    session = Session(base_dir=tmp_path / "s2")
    result = ar.AsrepRoast().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        include_secrets=True,
    )
    assert result["count"] == 1
    # hashes file should be written
    assert (session.root / "asrep-roast.hashes.txt").is_file()


# --------------------------- kerberoast (impacket paths mocked) ---------------------------


def test_kerberoast_requires_impacket(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.capabilities.kerberoast as kb

    monkeypatch.setitem(sys.modules, "impacket.krb5.kerberosv5", None)
    monkeypatch.setitem(sys.modules, "impacket.krb5", None)
    with pytest.raises(RuntimeError, match="requires Impacket"):
        kb.Kerberoast().run(
            Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p"),
            Session(base_dir=tmp_path / "s"),
            AttackGraph(),
        )


def test_kerberoast_flow_with_mocked_tgs(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.capabilities.kerberoast as kb

    # LDAP returns 1 user with 2 SPNs
    class _E:
        def __init__(self) -> None:
            self.sAMAccountName = _Attr("svc")
            self.servicePrincipalName = _Attr(["HTTP/a", "MSSQL/b"])
            self.userAccountControl = _Attr(0)

    conn = _LdapConn([_E()])
    monkeypatch.setattr(kb, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))

    # TGT acquisition succeeds
    monkeypatch.setattr(kb, "get_kerberos_tgt", lambda t: ("tgt", "cipher", None, "sk"))

    # getKerberosTGS: first spn returns rc4 ticket, second raises
    calls = {"n": 0}
    import impacket.krb5.kerberosv5 as kv5

    def fake_tgs(*a: Any, **k: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            return ("tgs-obj", "cipher", None, "sk")
        raise RuntimeError("kdc error")

    monkeypatch.setattr(kv5, "getKerberosTGS", fake_tgs)

    # format_tgs_hashcat returns hashcat lines for RC4/AES
    def fake_format(spn: str, sam: str, domain: str, tgs: Any) -> str:
        return f"$krb5tgs$23$*{sam}${domain.upper()}${spn}*$aa$bb"

    monkeypatch.setattr(kb, "format_tgs_hashcat", fake_format)

    session = Session(base_dir=tmp_path / "kb")
    result = kb.Kerberoast().run(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p"),
        session,
        AttackGraph(),
        include_secrets=True,
    )
    assert result["count"] == 2
    assert any("error" in t for t in result["tickets"])
    # hashes file written
    assert (session.root / "kerberoast.hashes.txt").is_file()


def test_kerberoast_requires_credentials(tmp_path: Path) -> None:
    import adaf_attack.capabilities.kerberoast as kb

    with pytest.raises(RuntimeError, match="requires credentials"):
        kb.Kerberoast().run(
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            Session(base_dir=tmp_path / "s"),
            AttackGraph(),
        )


def test_kerberoast_format_none_keeps_raw(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.capabilities.kerberoast as kb

    class _E:
        def __init__(self) -> None:
            self.sAMAccountName = _Attr("svc")
            self.servicePrincipalName = _Attr(["HTTP/a"])
            self.userAccountControl = _Attr(0)

    monkeypatch.setattr(kb, "ldap_connect", lambda t: (_LdapConn([_E()]), "DC=corp,DC=test", None))
    monkeypatch.setattr(kb, "get_kerberos_tgt", lambda t: ("tgt", "cipher", None, "sk"))
    import impacket.krb5.kerberosv5 as kv5

    monkeypatch.setattr(kv5, "getKerberosTGS", lambda *a, **k: ("raw-ticket", "c", None, "sk"))
    monkeypatch.setattr(kb, "format_tgs_hashcat", lambda *a, **k: None)

    session = Session(base_dir=tmp_path / "kbr")
    result = kb.Kerberoast().run(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p"),
        session,
        AttackGraph(),
        include_secrets=True,
    )
    assert result["tickets"][0].get("note")


def test_kerberoast_aes_format_labels(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.capabilities.kerberoast as kb

    class _E:
        def __init__(self) -> None:
            self.sAMAccountName = _Attr("svc")
            self.servicePrincipalName = _Attr(["HTTP/a"])
            self.userAccountControl = _Attr(0)

    monkeypatch.setattr(kb, "ldap_connect", lambda t: (_LdapConn([_E()]), "DC=corp,DC=test", None))
    monkeypatch.setattr(kb, "get_kerberos_tgt", lambda t: ("tgt", "cipher", None, "sk"))
    import impacket.krb5.kerberosv5 as kv5

    monkeypatch.setattr(kv5, "getKerberosTGS", lambda *a, **k: ("tgs", "c", None, "sk"))
    monkeypatch.setattr(
        kb, "format_tgs_hashcat", lambda *a, **k: "$krb5tgs$18$*svc$CORP.TEST$HTTP/a*$aa$bb"
    )
    result = kb.Kerberoast().run(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p"),
        Session(base_dir=tmp_path / "kaes"),
        AttackGraph(),
        include_secrets=True,
    )
    assert result["tickets"][0]["format"] == "hashcat-aes"
