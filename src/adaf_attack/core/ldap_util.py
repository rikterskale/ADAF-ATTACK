"""Shared LDAP connection helpers."""

from __future__ import annotations

from typing import Any

from ldap3 import ALL, Connection, Server
from ldap3.core.exceptions import LDAPException
from rich.console import Console

from adaf_attack.core.target import Target

console = Console()


def ldap_connect(target: Target) -> tuple[Connection, str, str | None]:
    """Bind and return (connection, default_nc, config_nc)."""
    server = Server(target.dc_ip, get_info=ALL, use_ssl=target.ldaps)
    if target.username and (target.password or target.hashes):
        if target.hashes:
            console.print(
                "[yellow]Hash bind via ldap3 is limited — prefer password for full results[/yellow]"
            )
        conn = Connection(
            server,
            user=target.auth_user or target.username,
            password=target.password or "",
            authentication="NTLM",
            auto_bind=True,
        )
    else:
        console.print("[dim]Anonymous / unauthenticated bind[/dim]")
        conn = Connection(server, auto_bind=True)

    try:
        if not conn.bound:
            if not conn.bind():
                raise RuntimeError(f"LDAP bind failed: {conn.result}")
    except LDAPException as exc:
        raise RuntimeError(f"LDAP connection error: {exc}") from exc

    default_nc = server.info.other.get("defaultNamingContext", [None])[0]
    if not default_nc:
        default_nc = ",".join(f"DC={p}" for p in target.domain.split("."))

    config_nc = None
    if server.info.other.get("configurationNamingContext"):
        config_nc = server.info.other["configurationNamingContext"][0]

    return conn, default_nc, config_nc
