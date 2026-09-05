"""ntlm-relay argv builder tests."""

from __future__ import annotations

from adaf_attack.capabilities.ntlm_relay import _build_argv
from adaf_attack.core.target import Target


def _target() -> Target:
    return Target(domain="corp.example", dc_ip="10.0.0.10")


def test_relay_argv_includes_all_targets() -> None:
    argv = _build_argv(
        _target(),
        ["10.0.0.20", "10.0.0.21"],
        445,
        "/tmp/out",
        [],
        targets_file="/tmp/targets.txt",
    )
    assert "-tf" in argv
    assert argv[argv.index("-tf") + 1] == "/tmp/targets.txt"
    assert "--no-smb-server" not in argv
    assert "--no-http-server" not in argv
    assert "--smb-port" in argv
    assert "-smb2support" in argv


def test_relay_argv_appends_extras() -> None:
    argv = _build_argv(
        _target(),
        ["10.0.0.20"],
        445,
        "/tmp/out",
        ["--http-port", "80"],
        targets_file="/tmp/targets.txt",
    )
    assert argv[-2:] == ["--http-port", "80"]


def test_relay_argv_rejects_scope_and_listener_overrides() -> None:
    import pytest

    for extras in (["-tf", "unapproved.txt"], ["-t", "10.0.0.99"], ["--smb-server-port", "445"]):
        with pytest.raises(RuntimeError, match="not allowed"):
            _build_argv(
                _target(),
                ["10.0.0.20"],
                445,
                "/tmp/out",
                list(extras),
                targets_file="/tmp/targets.txt",
            )


def test_relay_argv_accepts_quoted_command_extra() -> None:
    argv = _build_argv(
        _target(),
        ["10.0.0.20"],
        445,
        "/tmp/out",
        ["-c", "whoami /all"],
        targets_file="/tmp/targets.txt",
    )
    assert argv[-2:] == ["-c", "whoami /all"]
