"""Kerberoasting capability (stub)."""

from adaf_attack.core.registry import register_capability


@register_capability(
    id="kerberoast",
    summary="Request TGS tickets for SPN-enabled accounts (Kerberoasting)",
    category="credential-access",
    tags=("kerberos", "tgs", "spn"),
)
class Kerberoast:
    """Placeholder for Kerberoasting collector."""

    pass
