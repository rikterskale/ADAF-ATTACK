"""gMSA managed password blob parser."""

import struct

from adaf_attack.capabilities.gmsa_laps_enum import _parse_managed_password_blob


def _build_blob(current: str, previous: str = "") -> bytes:
    # minimal v1 blob
    cur_b = current.encode("utf-16-le") + b"\x00\x00"
    prev_b = previous.encode("utf-16-le") + b"\x00\x00" if previous else b""
    header_len = 16
    cur_off = header_len
    prev_off = header_len + len(cur_b) if previous else 0
    body = cur_b + prev_b
    header = struct.pack("<HHI", 1, 0, header_len + len(body))
    header += struct.pack("<HHHH", cur_off, prev_off, 0, 0)
    return header + body


def test_parse_managed_password_blob() -> None:
    blob = _build_blob("SuperSecret123!", "OldSecret")
    parsed = _parse_managed_password_blob(blob)
    assert parsed is not None
    assert parsed["current_password"] == "SuperSecret123!"
    assert parsed["previous_password"] == "OldSecret"


def test_parse_empty() -> None:
    assert _parse_managed_password_blob(b"") is None
    assert _parse_managed_password_blob(b"short") is None
