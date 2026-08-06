"""Capability modules.

Importing this package registers all available capabilities.
"""

from adaf_attack.capabilities import (  # noqa: F401
    acl_enum,
    adcs_enum,
    asrep_roast,
    attack_paths,
    bloodhound_export,
    cert_request,
    coercion_map,
    gmsa_laps_enum,
    gpo_abuse,
    kerberoast,
    ldap_enum,
    rbcd,
    report,
    shadow_creds,
    trusts_enum,
)
