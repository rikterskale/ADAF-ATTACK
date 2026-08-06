"""Capability modules.

Importing this package registers all available capabilities.
"""

from adaf_attack.capabilities import (  # noqa: F401
    acl_enum,
    adcs_enum,
    asrep_roast,
    attack_paths,
    bloodhound_export,
    campaign_analysis,
    cert_request,
    coercion_map,
    gmsa_laps_enum,
    gpo_abuse,
    gpo_sysvol,
    kerberoast,
    ldap_enum,
    next_actions,
    pkinit_auth,
    rbcd,
    report,
    shadow_creds,
    ticket_lifecycle,
    trusts_enum,
    workflow_wrappers,
)
