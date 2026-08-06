"""Security descriptor / ACE parsing for interesting AD rights."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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
        return sid.formatCanonical()
    except Exception:  # noqa: BLE001
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
        ) from exp if False else exc  # type: ignore[misc]

    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(sd_bytes)
    if sd["Dacl"] is None:
        return []

    results: list[InterestingAce] = []
    for ace in sd["Dacl"]["Data"]:
        ace_type = ace["AceType"]
        if ace_type not in (0x00, 0x05):
            continue

        mask = int(ace["Ace"]["Mask"]["Mask"])
        sid = _sid_to_str(ace["Ace"]["Sid"].getData())
        object_guid = None

        if ace_type == 0x05:
            try:
                flags = int(ace["Ace"]["Flags"])
                if flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                    object_guid = _guid_bytes_to_str(ace["Ace"]["ObjectType"]).lower()
            except Exception:  # noqa: BLE001
                pass

        rights = _mask_to_rights(mask, object_guid)
        for right in rights:
            results.append(
                InterestingAce(
                    principal_sid=sid,
                    right=right,
                    object_guid=object_guid,
                    raw_mask=mask,
                )
            )

    return results


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
        elif not g:
            rights.append("AllExtendedRights")

    if mask & WRITE_PROPERTY and not rights:
        rights.append("WriteProperty")
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
    return raw if isinstance(raw, (bytes, bytearray)) else None
