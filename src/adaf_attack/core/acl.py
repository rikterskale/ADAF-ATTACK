"""Security descriptor / ACE parsing for interesting AD rights."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

_logger = logging.getLogger(__name__)

# Access mask bits
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x20000000
GENERIC_READ = 0x80000000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000
WRITE_PROPERTY = 0x00000020
READ_PROPERTY = 0x00000010
DELETE = 0x00010000
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100  # extended rights
ADS_RIGHT_DS_SELF = 0x00000008

# Well-known extended right GUIDs (lowercase)
GUID_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_DS_REPLICATION_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET = "89e95b76-444d-4c62-991a-0facbeda640c"
GUID_CERTIFICATE_ENROLLMENT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GUID_CERTIFICATE_AUTOENROLLMENT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
GUID_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_LAPS_PASSWORD = "FAKESECRET_c4d5e6f7g8h9i0j1k2l3"
GUID_GMSA_PASSWORD = "FAKESECRET_q1r2s3t4u5v6w7x8y9z0"
GUID_MANAGE_CA = "0ba7ea17-7269-4771-8374-367c8d5a5770"
GUID_MANAGE_CERTIFICATES = "e48d0154-bcf8-11d1-8702-00c04fb96050"
ACE_ACCESS_ALLOWED = 0x00
ACE_ACCESS_DENIED = 0x01
ACE_ACCESS_ALLOWED_OBJECT = 0x05
ACE_ACCESS_DENIED_OBJECT = 0x06

RIGHT_PRIORITY = [
    "GenericAll",
    "WriteDacl",
    "WriteOwner",
    "GenericWrite",
    "ForceChangePassword",
    "GetChangesAll",
    "GetChanges",
    "AddMember",
    "WriteProperty",
    "Enroll",
    "AutoEnroll",
    "ReadLAPS",
    "ReadGMSA",
    "ManageCA",
    "ManageCertificates",
]


@dataclass
class InterestingAce:
    principal_sid: str
    right: str
    object_guid: str | None = None
    raw_mask: int = 0


def _guid_bytes_to_str(b: bytes) -> str:
    """Convert Windows GUID binary (mixed endian) to dashed string."""
    if len(b) != 16:
        return b.hex()
    data1 = int.from_bytes(b[0:4], "little")
    data2 = int.from_bytes(b[4:6], "little")
    data3 = int.from_bytes(b[6:8], "little")
    data4 = b[8:16]
    return f"{data1:08x}-{data2:04x}-{data3:04x}-{data4[0:2].hex()}-{data4[2:8].hex()}"


def _sid_to_str(sid_bytes: bytes) -> str:
    try:
        from impacket.ldap.ldaptypes import LDAP_SID

        sid = LDAP_SID(sid_bytes)
        return str(sid.formatCanonical())
    except Exception:
        if len(sid_bytes) < 8:
            return sid_bytes.hex()
        revision = sid_bytes[0]
        sub_count = sid_bytes[1]
        authority = int.from_bytes(sid_bytes[2:8], "big")
        subs = []
        for i in range(sub_count):
            start = 8 + i * 4
            if start + 4 > len(sid_bytes):
                break
            subs.append(str(int.from_bytes(sid_bytes[start : start + 4], "little")))
        return f"S-{revision}-{authority}-" + "-".join(subs)


def parse_interesting_aces(sd_bytes: bytes) -> list[InterestingAce]:
    """Parse a binary security descriptor and return interesting ALLOW ACEs."""
    try:
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
    except ImportError as exc:
        raise RuntimeError(
            "ACL parsing requires Impacket. Install with: pip install 'adaf-attack[kerberos]'"
        ) from exc

    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(sd_bytes)
    if sd["Dacl"] is None:  # pragma: no cover - defensive for non-standard SDs
        return []

    denied: set[tuple[str, str]] = set()
    allowed: list[InterestingAce] = []
    for ace in sd["Dacl"]["Data"]:
        ace_type = ace["AceType"]
        if ace_type not in {
            ACE_ACCESS_ALLOWED,
            ACE_ACCESS_DENIED,
            ACE_ACCESS_ALLOWED_OBJECT,
            ACE_ACCESS_DENIED_OBJECT,
        }:
            continue

        mask = int(ace["Ace"]["Mask"]["Mask"])
        sid = _sid_to_str(ace["Ace"]["Sid"].getData())
        object_guid = None

        if ace_type in {ACE_ACCESS_ALLOWED_OBJECT, ACE_ACCESS_DENIED_OBJECT}:
            try:
                flags = int(ace["Ace"]["Flags"])
                if flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                    object_guid = _guid_bytes_to_str(ace["Ace"]["ObjectType"]).lower()
            except Exception:
                _logger.debug("Could not parse object ACE GUID", exc_info=True)

        rights = _mask_to_rights(mask, object_guid)
        is_deny = ace_type in {ACE_ACCESS_DENIED, ACE_ACCESS_DENIED_OBJECT}
        for right in rights:
            if is_deny:
                denied.add((sid, right))
                continue
            allowed.append(
                InterestingAce(
                    principal_sid=sid,
                    right=right,
                    object_guid=object_guid,
                    raw_mask=mask,
                )
            )

    return [ace for ace in allowed if (ace.principal_sid, ace.right) not in denied]


def _mask_to_rights(mask: int, object_guid: str | None) -> list[str]:
    rights: list[str] = []
    if mask & GENERIC_ALL == GENERIC_ALL or mask == 0x0F01FF:
        rights.append("GenericAll")
        return rights

    if mask & WRITE_DACL:
        rights.append("WriteDacl")
    if mask & WRITE_OWNER:
        rights.append("WriteOwner")
    if mask & GENERIC_WRITE:
        rights.append("GenericWrite")

    if mask & ADS_RIGHT_DS_CONTROL_ACCESS:
        g = (object_guid or "").lower()
        if g == GUID_FORCE_CHANGE_PASSWORD:
            rights.append("ForceChangePassword")
        elif g == GUID_DS_REPLICATION_GET_CHANGES_ALL:
            rights.append("GetChangesAll")
        elif g == GUID_DS_REPLICATION_GET_CHANGES:
            rights.append("GetChanges")
        elif g == GUID_CERTIFICATE_ENROLLMENT:
            rights.append("Enroll")
        elif g == GUID_CERTIFICATE_AUTOENROLLMENT:
            rights.append("AutoEnroll")
        elif g == GUID_MANAGE_CA:
            rights.append("ManageCA")
        elif g == GUID_MANAGE_CERTIFICATES:
            rights.append("ManageCertificates")
        elif not g:
            rights.append("AllExtendedRights")

    if mask & WRITE_PROPERTY:
        g = (object_guid or "").lower()
        if g == GUID_MEMBER:
            rights.append("AddMember")
        elif not rights:
            rights.append("WriteProperty")
    if mask & READ_PROPERTY:
        g = (object_guid or "").lower()
        if g == GUID_LAPS_PASSWORD:
            rights.append("ReadLAPS")
        elif g == GUID_GMSA_PASSWORD:
            rights.append("ReadGMSA")
    if mask & READ_PROPERTY:
        rights.append("ReadProperty")

    return rights


def fetch_sd(conn: Any, dn: str) -> bytes | None:
    """Fetch nTSecurityDescriptor (DACL) for a DN."""
    from ldap3 import BASE
    from ldap3.protocol.microsoft import security_descriptor_control

    controls = security_descriptor_control(sdflags=0x04)  # DACL only
    ok = conn.search(
        dn,
        "(objectClass=*)",
        search_scope=BASE,
        attributes=["nTSecurityDescriptor"],
        controls=[controls],
    )
    if not ok or not conn.entries:
        return None
    entry = conn.entries[0]
    if not entry.nTSecurityDescriptor:
        return None
    raw = entry.nTSecurityDescriptor.raw_values[0]
    return bytes(raw) if isinstance(raw, bytes | bytearray) else None


def sd_controls(sdflags: int = 0x04) -> list[Any]:
    """LDAP_SERVER_SD_FLAGS_OID controls for nTSecurityDescriptor reads/writes."""
    from ldap3.protocol.microsoft import security_descriptor_control

    return list(security_descriptor_control(sdflags=sdflags))


def modify_security_descriptor(conn: Any, dn: str, sd_bytes: bytes, *, sdflags: int = 0x04) -> bool:
    """REPLACE nTSecurityDescriptor with the same SD flags used by fetch_sd."""
    from ldap3 import MODIFY_REPLACE

    changes = {"nTSecurityDescriptor": [(MODIFY_REPLACE, [sd_bytes])]}
    controls = sd_controls(sdflags)
    try:
        return bool(conn.modify(dn, changes, controls=controls))
    except TypeError:
        return bool(conn.modify(dn, changes))


def sid_string_to_bytes(canonical: str) -> bytes:
    parts = canonical.split("-")
    if len(parts) < 4 or parts[0] != "S":
        raise ValueError(f"Invalid SID: {canonical}")
    rev = int(parts[1])
    auth = int(parts[2])
    subs = [int(x) for x in parts[3:]]
    out = bytes([rev, len(subs)]) + auth.to_bytes(6, "big")
    for sub in subs:
        out += sub.to_bytes(4, "little")
    return out


def guid_str_to_bytes(guid: str) -> bytes:
    parts = guid.split("-")
    if len(parts) != 5:
        raise ValueError(f"Invalid GUID: {guid}")
    return (
        int(parts[0], 16).to_bytes(4, "little")
        + int(parts[1], 16).to_bytes(2, "little")
        + int(parts[2], 16).to_bytes(2, "little")
        + bytes.fromhex(parts[3] + parts[4])
    )


def build_allowed_ace(sid: str, mask: int = GENERIC_ALL, object_guid: str | None = None) -> bytes:
    sid_bytes = sid_string_to_bytes(sid)
    if object_guid:
        flags = 0x01  # ACE_OBJECT_TYPE_PRESENT
        body = (
            mask.to_bytes(4, "little")
            + flags.to_bytes(4, "little")
            + guid_str_to_bytes(object_guid)
            + sid_bytes
        )
        header = bytes([0x05, 0x00]) + (4 + len(body)).to_bytes(2, "little")
        return header + body
    body = mask.to_bytes(4, "little") + sid_bytes
    header = bytes([0x00, 0x00]) + (4 + len(body)).to_bytes(2, "little")
    return header + body


def _build_sd(aces: list[bytes], owner_sid: str | None = None) -> bytes:
    acl_body = b"".join(aces)
    acl_size = 8 + len(acl_body)
    acl = (
        bytes([0x02, 0x00])
        + acl_size.to_bytes(2, "little")
        + len(aces).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + acl_body
    )
    owner = sid_string_to_bytes(owner_sid) if owner_sid else b""
    control = 0x8004  # SE_DACL_PRESENT | SE_SELF_RELATIVE
    owner_off = 20 if owner else 0
    dacl_off = 20 + len(owner)
    header = (
        bytes([0x01, 0x00])
        + control.to_bytes(2, "little")
        + owner_off.to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + dacl_off.to_bytes(4, "little")
    )
    return header + owner + acl


def append_ace_to_sd(sd_bytes: bytes | None, ace: bytes) -> bytes:
    if not sd_bytes or len(sd_bytes) < 20:
        return _build_sd([ace])
    dacl_offset = int.from_bytes(sd_bytes[16:20], "little")
    if dacl_offset == 0 or dacl_offset + 8 > len(sd_bytes):
        return sd_bytes + _build_sd([ace])[20:]
    acl_size = int.from_bytes(sd_bytes[dacl_offset + 2 : dacl_offset + 4], "little")
    ace_count = int.from_bytes(sd_bytes[dacl_offset + 4 : dacl_offset + 6], "little")
    end = dacl_offset + acl_size
    if end > len(sd_bytes):
        end = len(sd_bytes)
    new_acl_size = acl_size + len(ace)
    acl_header = (
        sd_bytes[dacl_offset : dacl_offset + 2]
        + new_acl_size.to_bytes(2, "little")
        + (ace_count + 1).to_bytes(2, "little")
        + sd_bytes[dacl_offset + 6 : dacl_offset + 8]
    )
    existing = sd_bytes[dacl_offset + 8 : end]
    return sd_bytes[:dacl_offset] + acl_header + existing + ace + sd_bytes[end:]


def sd_set_owner(sd_bytes: bytes | None, owner_sid: str) -> bytes:
    owner = sid_string_to_bytes(owner_sid)
    if not sd_bytes or len(sd_bytes) < 20:
        return _build_sd([], owner_sid=owner_sid)
    dacl_offset = int.from_bytes(sd_bytes[16:20], "little")
    dacl = sd_bytes[dacl_offset:] if dacl_offset and dacl_offset < len(sd_bytes) else b""
    control = int.from_bytes(sd_bytes[2:4], "little") | 0x8004
    header = (
        bytes([sd_bytes[0], sd_bytes[1]])
        + control.to_bytes(2, "little")
        + (20).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (20 + len(owner)).to_bytes(4, "little")
    )
    return header + owner + dacl
