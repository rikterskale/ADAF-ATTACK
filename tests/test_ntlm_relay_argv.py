"""ntlm-relay argv builder tests."""

from __future__ import annotations

from adaf_attack.capabilities.ntlm_relay import _build_argv
from adaf_attack.core.target import Target


def _target() -> Target:
    return Target(domain="corp.example", dc_ip="10.0.0.10")


def test_relay_argv_includes_all_targets() -> None:
    argv = _build_argv(_target(), ["10.0.0.20", "10.0.0.21"], 445, "/tmp/out", [])
    assert argv.count("-t") == 2
    assert "10.0.0.20" in argv and "10.0.0.21" in argv
    assert "-smb2support" in argv


def test_relay_argv_appends_extras() -> None:
    argv = _build_argv(_target(), ["10.0.0.20"], 445, "/tmp/out", ["--http-port", "80"])
    assert argv[-2:] == ["--http-port", "80"]
