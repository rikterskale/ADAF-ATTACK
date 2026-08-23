"""Build security descriptors for msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)."""

from __future__ import annotations

import logging
from typing import Any

_logger = logging.getLogger(__name__)


def _sid_to_bytes(canonical: str) -> bytes:
    parts = canonical.split("-")
    if len(parts) < 4 or parts[0] != "S":
        raise ValueError(f"Invalid SID: {canonical}")
    rev = int(parts[1])
    auth = int(parts[2])
    subs = [int(x) for x in parts[3:]]
    out = bytes([rev, len(subs)]) + auth.to_bytes(6, "big")
    for s in subs:
        out += s.to_bytes(4, "little")
    return out


def build_allowed_to_act_sd(computer_sid: str) -> bytes:
    """Create a self-relative SD allowing ``computer_sid`` to act on the target host.

    Layout is a standard self-relative SECURITY_DESCRIPTOR with a DACL containing
    one ACCESS_ALLOWED_ACE (mask 0x000F01FF) for the controlled computer SID.
    """
    sid = _sid_to_bytes(computer_sid)
    mask = (0x000F01FF).to_bytes(4, "little")
    ace_body = mask + sid
    ace_size = 4 + len(ace_body)
    ace = bytes([0x00, 0x00]) + ace_size.to_bytes(2, "little") + ace_body  # type, flags, size

    acl_size = 8 + len(ace)
    acl = (
        bytes([0x02, 0x00])  # AclRevision, Sbz1
        + acl_size.to_bytes(2, "little")
        + (1).to_bytes(2, "little")  # AceCount
        + (0).to_bytes(2, "little")  # Sbz2
        + ace
    )

    # SD: Revision, Sbz1, Control, OffsetOwner/Group/Sacl/Dacl
    control = 0x8004  # SE_DACL_PRESENT | SE_SELF_RELATIVE
    header = (
        bytes([0x01, 0x00])
        + control.to_bytes(2, "little")
        + (0).to_bytes(4, "little")  # OffsetOwner
        + (0).to_bytes(4, "little")  # OffsetGroup
        + (0).to_bytes(4, "little")  # OffsetSacl
        + (20).to_bytes(4, "little")  # OffsetDacl
    )
    return header + acl


def sid_from_ldap_value(sid_val: Any) -> str | None:
    """Normalize ldap3/impacket SID values to canonical string."""
    if sid_val is None:
        return None
    try:
        if hasattr(sid_val, "formatCanonical"):
            return str(sid_val.formatCanonical())
        if isinstance(sid_val, bytes):
            try:
                from impacket.ldap.ldaptypes import LDAP_SID

                s = LDAP_SID(sid_val)
                return str(s.formatCanonical())
            except Exception:
                _logger.debug("Could not parse binary LDAP SID", exc_info=True)
    except Exception:
        _logger.debug("Could not normalize LDAP SID value", exc_info=True)
    text = str(sid_val)
    if text.startswith("S-1-"):
        return text
    return None
