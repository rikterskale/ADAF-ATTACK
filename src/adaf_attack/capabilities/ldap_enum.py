"""LDAP / domain enumeration capability (stub)."""

from adaf_attack.core.registry import register_capability


@register_capability(
    id="ldap-enum",
    summary="Enumerate domain users, computers, groups, trusts, and SPNs via LDAP",
    category="enumeration",
    tags=("ldap", "enum", "users", "computers", "trusts"),
)
class LdapEnum:
    """Placeholder for full LDAP enumeration collector."""

    pass
