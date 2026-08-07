"""Password-spray lockout math tests."""

from __future__ import annotations

from adaf_attack.capabilities.password_spray import _filetime_to_dt


def test_filetime_zero_returns_none() -> None:
    assert _filetime_to_dt(0) is None
    assert _filetime_to_dt(-1) is None


def test_filetime_conversion_produces_datetime() -> None:
    # Windows FILETIME for 2020-01-01 00:00:00 UTC = 132223104000000000
    dt = _filetime_to_dt(132223104000000000)
    assert dt is not None
    assert dt.year == 2020 and dt.month == 1 and dt.day == 1
