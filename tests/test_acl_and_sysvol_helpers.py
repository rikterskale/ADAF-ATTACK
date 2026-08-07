"""Unit coverage for local ACL-right and SYSVOL path parsing."""

from __future__ import annotations

from adaf_attack.capabilities.gpo_sysvol import _parse_sysvol_unc
from adaf_attack.core.acl import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    GENERIC_ALL,
    GENERIC_WRITE,
    GUID_DS_REPLICATION_GET_CHANGES,
    GUID_FORCE_CHANGE_PASSWORD,
    READ_PROPERTY,
    WRITE_DACL,
    WRITE_PROPERTY,
    _guid_bytes_to_str,
    _mask_to_rights,
    fetch_sd,
)


def test_mask_to_rights_identifies_generic_acl_and_enrollment_rights() -> None:
    assert "GenericAll" in _mask_to_rights(GENERIC_ALL, None)
    assert "WriteDacl" in _mask_to_rights(WRITE_DACL, None)
    assert "Enroll" in _mask_to_rights(
        ADS_RIGHT_DS_CONTROL_ACCESS, "0e10c968-78fb-11d2-90d4-00c04f79dc55"
    )


def test_mask_to_rights_covers_extended_write_and_read_variants() -> None:
    assert _mask_to_rights(ADS_RIGHT_DS_CONTROL_ACCESS, GUID_FORCE_CHANGE_PASSWORD) == [
        "ForceChangePassword"
    ]
    assert _mask_to_rights(ADS_RIGHT_DS_CONTROL_ACCESS, GUID_DS_REPLICATION_GET_CHANGES) == [
        "GetChanges"
    ]
    assert _mask_to_rights(ADS_RIGHT_DS_CONTROL_ACCESS, None) == ["AllExtendedRights"]
    assert _mask_to_rights(WRITE_PROPERTY, None) == ["WriteProperty"]
    assert _mask_to_rights(WRITE_PROPERTY | READ_PROPERTY, None) == [
        "WriteProperty",
        "ReadProperty",
    ]
    assert "GenericWrite" in _mask_to_rights(GENERIC_WRITE, None)


def test_guid_conversion_handles_windows_byte_order_and_invalid_lengths() -> None:
    assert _guid_bytes_to_str(bytes.fromhex("70 95 29 00 6d 24 68 11 a7 68 00 aa 00 6e 05 29")) == (
        "00299570-246d-1168-a768-00aa006e0529"
    )
    assert _guid_bytes_to_str(b"short") == "73686f7274"


def test_sysvol_unc_parser_accepts_policy_paths_and_rejects_non_unc_values() -> None:
    assert _parse_sysvol_unc("\\\\dc01\\SYSVOL\\corp.test\\Policies\\{GPO-1}") == (
        "dc01",
        "corp.test/Policies/{GPO-1}",
    )
    assert _parse_sysvol_unc("C:\\Windows\\SYSVOL") is None


class _SearchConnection:
    def __init__(self, found: bool, raw: bytes | None) -> None:
        self.found = found
        self.entries = (
            [] if raw is None else [type("Entry", (), {"nTSecurityDescriptor": _RawAttr(raw)})()]
        )

    def search(self, *args: object, **kwargs: object) -> bool:
        return self.found


class _RawAttr:
    def __init__(self, raw: bytes) -> None:
        self.raw_values = [raw]

    def __bool__(self) -> bool:
        return True


def test_fetch_sd_returns_only_successful_binary_security_descriptors() -> None:
    assert fetch_sd(_SearchConnection(False, b"ignored"), "CN=Missing") is None
    assert fetch_sd(_SearchConnection(True, None), "CN=Missing") is None
    assert fetch_sd(_SearchConnection(True, b"binary-sd"), "CN=Present") == b"binary-sd"
