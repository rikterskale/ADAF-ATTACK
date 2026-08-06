"""AS-REP roasting capability (stub)."""

from adaf_attack.core.registry import register_capability


@register_capability(
    id="asrep-roast",
    summary="Identify and roast accounts that do not require pre-authentication",
    category="credential-access",
    tags=("kerberos", "asrep", "preauth"),
)
class AsrepRoast:
    """Placeholder for AS-REP roasting collector."""

    pass
