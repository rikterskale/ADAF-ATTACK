"""Shared LDAP connection helpers."""

from __future__ import annotations

from ldap3 import ALL, Connection, Server
from ldap3.core.exceptions import LDAPException
from rich.console import Console

from adaf_attack.core.auth import describe_auth, ldap3_bind_kwargs
from adaf_attack.core.target import Target

console = Console()


def ldap_connect(target: Target) -> tuple[Connection, str, str | None]:
    """Bind and return (connection, default_nc, config_nc).

    Uses ldap3 NTLM for password (and best-effort hash). Kerberos ticket/AES
    auth for LDAP is primarily consumed by Impacket-backed capabilities;
    this helper still records the selected auth mode for session logs.
    """
    console.print(f"[dim]Auth mode: {describe_auth(target)}[/dim]")

    server = Server(target.dc_ip, get_info=ALL, use_ssl=target.ldaps)
    kwargs = ldap3_bind_kwargs(target)

    if "user" in kwargs:
        conn = Connection(server, **kwargs)
    else:
        console.print("[dim]Anonymous / unauthenticated bind[/dim]")
        conn = Connection(server, auto_bind=True)

    try:
        if not conn.bound and not conn.bind():
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
