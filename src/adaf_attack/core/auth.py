"""Authentication helpers — NTLM password/hash and Kerberos ticket/AES paths.

Impacket is optional. When present, Kerberos TGT acquisition and hash binds
work for roast / advanced LDAP flows. ldap3 remains the default for simple
password NTLM binds so the core toolkit stays usable without [kerberos].
"""

from __future__ import annotations

import os
from typing import Any

from rich.console import Console

from adaf_attack.core.target import Target

console = Console()


def describe_auth(target: Target) -> str:
    """Human-readable auth mode for logs / doctor."""
    if target.use_kerberos or target.ccache:
        path = target.resolved_ccache() or os.environ.get("KRB5CCNAME", "KRB5CCNAME")
        return f"kerberos-ccache ({path})"
    if target.aes_key:
        return "kerberos-aes-key"
    if target.hashes:
        return "ntlm-hash / kerberos-rc4"
    if target.password and target.username:
        return "password (ntlm or kerberos)"
    if target.username:
        return "username only (incomplete)"
    return "anonymous"


def get_kerberos_tgt(target: Target) -> tuple[Any, Any, Any, Any]:
    """Acquire a TGT via Impacket. Returns (tgt, cipher, oldSessionKey, sessionKey).

    Raises RuntimeError if Impacket is missing or credentials are insufficient.
    """
    try:
        from impacket.krb5 import constants
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.types import Principal
    except ImportError as exc:
        raise RuntimeError(
            "Kerberos auth requires Impacket. Install with: pip install 'adaf-attack[kerberos]'"
        ) from exc

    if not target.username and not (target.use_kerberos or target.ccache):
        raise RuntimeError("Kerberos TGT requires --username (or a ccache with principal)")

    lmhash, nthash = target.lm_nt_hashes()
    aes_key = target.aes_key or ""

    # Prefer explicit ccache / -k
    if target.use_kerberos or target.ccache:
        ccache_path = target.resolved_ccache()
        if ccache_path:
            os.environ["KRB5CCNAME"] = ccache_path
            console.print(f"[dim]Using ccache: {ccache_path}[/dim]")
        # Empty password + useCache path inside Impacket when KRB5CCNAME set
        user = target.username or ""
        principal = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        return getKerberosTGT(
            principal,
            "",
            target.domain.upper(),
            lmhash,
            nthash,
            aes_key,
            target.dc_ip,
        )

    if not target.username:
        raise RuntimeError("Username required for password/hash/AES Kerberos auth")

    principal = Principal(
        target.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )
    return getKerberosTGT(
        principal,
        target.password or "",
        target.domain.upper(),
        lmhash,
        nthash,
        aes_key,
        target.dc_ip,
    )


def ldap3_bind_kwargs(target: Target) -> dict[str, Any]:
    """Build Connection kwargs for ldap3 NTLM password bind.

    Hash/AES/ccache binds are not fully supported by ldap3; callers that need
    those should use Impacket-backed capabilities or get_kerberos_tgt first.
    """
    kwargs: dict[str, Any] = {"auto_bind": True}
    if target.username and target.password:
        kwargs["user"] = target.auth_user or target.username
        kwargs["password"] = target.password
        kwargs["authentication"] = "NTLM"
    elif target.username and target.hashes:
        # Best-effort: some ldap3 builds accept NT hash as password with NTLM
        _lm, nt = target.lm_nt_hashes()
        kwargs["user"] = target.auth_user or target.username
        kwargs["password"] = nt
        kwargs["authentication"] = "NTLM"
        console.print(
            "[yellow]ldap3 hash bind is best-effort — prefer password or Impacket paths[/yellow]"
        )
    return kwargs
