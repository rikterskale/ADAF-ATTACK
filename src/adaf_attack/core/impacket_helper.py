"""Guarded impacket imports and shared helpers for offensive capabilities."""

from __future__ import annotations

from typing import Any


class ImpacketMissing(RuntimeError):
    """Raised when a capability requires impacket but it is not installed."""

    def __init__(self, feature: str) -> None:
        super().__init__(
            f"{feature} requires Impacket. "
            "Install with: pip install 'adaf-attack[kerberos]'"
        )


def require_impacket(feature: str) -> None:
    try:
        import impacket  # noqa: F401
    except ImportError as exc:
        raise ImpacketMissing(feature) from exc


def smb_connect(target_ip: str, target: Any) -> Any:
    """Return an SMBConnection authenticated per Target (password/hash/ccache)."""
    require_impacket("SMB")
    from impacket.smbconnection import SMBConnection

    conn = SMBConnection(target_ip, target_ip, sess_port=445)
    lm, nt = target.lm_nt_hashes()
    if target.use_kerberos or target.ccache:
        conn.kerberosLogin(
            target.username or "",
            target.password or "",
            target.domain,
            lm,
            nt,
            aesKey=target.aes_key or "",
            kdcHost=target.dc_ip,
            useCache=True,
        )
    elif target.aes_key:
        conn.kerberosLogin(
            target.username or "",
            "",
            target.domain,
            "",
            "",
            aesKey=target.aes_key,
            kdcHost=target.dc_ip,
            useCache=False,
        )
    elif target.hashes:
        conn.login(target.username or "", "", target.domain, lm, nt)
    else:
        conn.login(target.username or "", target.password or "", target.domain)
    return conn
