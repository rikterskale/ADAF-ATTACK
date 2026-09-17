"""Shared LDAP connection helpers."""

from __future__ import annotations

import ssl
from collections.abc import Iterable
from typing import Any

from ldap3 import ALL, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from rich.console import Console

from adaf_attack.core.auth import describe_auth, ldap3_bind_kwargs
from adaf_attack.core.target import Target

console = Console()


def schema_supported_attributes(conn: Any, requested: Iterable[str]) -> tuple[list[str], list[str]]:
    """Return canonical supported and unsupported LDAP attribute names.

    ldap3 validates requested attributes against the server schema before it
    sends a search. Optional AD extensions such as legacy/Windows LAPS and
    Exchange are not present in every forest, so callers must not request
    their attributes unconditionally. If schema metadata is unavailable, keep
    the original request so connections created without ``get_info=ALL``
    retain their existing behavior.
    """
    names = list(dict.fromkeys(str(name) for name in requested))
    schema = getattr(getattr(conn, "server", None), "schema", None)
    attribute_types = getattr(schema, "attribute_types", None)
    if not attribute_types:
        return names, []

    canonical: dict[str, str] = {}
    for key, info in attribute_types.items():
        key_name = str(key)
        canonical.setdefault(key_name.casefold(), key_name)
        aliases = getattr(info, "name", ())
        if isinstance(aliases, str):
            aliases = (aliases,)
        for alias in aliases or ():
            alias_name = str(alias)
            canonical[alias_name.casefold()] = alias_name

    supported = [canonical[name.casefold()] for name in names if name.casefold() in canonical]
    unsupported = [name for name in names if name.casefold() not in canonical]
    return supported, unsupported


def ldap_connect(target: Target) -> tuple[Connection, str, str | None]:
    """Bind and return (connection, default_nc, config_nc).

    Uses ldap3 NTLM for password (and best-effort hash). Kerberos ticket/AES
    auth for LDAP is primarily consumed by Impacket-backed capabilities;
    this helper still records the selected auth mode for session logs.
    """
    console.print(f"[dim]Auth mode: {describe_auth(target)}[/dim]")

    server = Server(
        target.dc_ip,
        get_info=ALL,
        use_ssl=target.ldaps,
        tls=Tls(validate=ssl.CERT_NONE) if target.ldaps or target.starttls else None,
    )
    kwargs = ldap3_bind_kwargs(target)

    if "user" in kwargs or kwargs.get("authentication") == "SASL":
        conn = Connection(server, **kwargs)
        if target.starttls or kwargs.get("authentication") == "SASL":
            try:
                conn.open()
                if target.starttls and not target.ldaps:
                    if not conn.start_tls(read_server_info=True):
                        raise RuntimeError(f"LDAP StartTLS failed: {conn.result}")
            except LDAPException as exc:
                raise RuntimeError(f"LDAP connection error: {exc}") from exc
    else:
        console.print("[dim]Anonymous / unauthenticated bind[/dim]")
        conn = Connection(server, auto_bind=not target.starttls)
        if target.starttls:
            conn.open()
            if not conn.start_tls(read_server_info=True):
                raise RuntimeError(f"LDAP StartTLS failed: {conn.result}")

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
