"""laps-read v2 blob header parser tests."""

from __future__ import annotations

from adaf_attack.capabilities.laps_read import _decode_v2_blob


def test_v2_blob_header_extracts_ts_and_length() -> None:
    ts = (132223104000000000).to_bytes(8, "little")
    payload_len = (128).to_bytes(4, "little")
    padding = b"\x00" * 4
    payload = b"\x11" * 40
    raw = ts + payload_len + padding + payload
    parsed = _decode_v2_blob(raw)
    assert parsed["blob_len"] == len(raw)
    assert parsed["timestamp_filetime"] == 132223104000000000
    assert parsed["payload_length_declared"] == 128
    assert parsed["dpapi_ng_payload_b64"]


def test_v2_blob_too_short_returns_note() -> None:
    parsed = _decode_v2_blob(b"\x00" * 5)
    assert parsed.get("note") == "too-short"
