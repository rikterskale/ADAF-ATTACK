"""Credential redaction tests for script-backed Impacket execution."""

from __future__ import annotations

from types import SimpleNamespace

from adaf_attack.capabilities import impacket_exec
from adaf_attack.core.target import Target


def test_script_exec_redacts_hash_and_aes_auth_values(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(impacket_exec.shutil, "which", lambda name: "/bin/" + name)
    monkeypatch.setattr(impacket_exec.subprocess, "run", fake_run)

    target = Target(
        domain="corp.example",
        dc_ip="10.0.0.10",
        username="alice",
        aes_key="a" * 64,
    )
    result = impacket_exec._run_script_exec(target, "server", "whoami", "atexec", 3)

    assert captured["argv"][captured["argv"].index("-aesKey") + 1] == target.aes_key
    assert target.aes_key not in result["argv"]
    assert result["argv"][result["argv"].index("-aesKey") + 1] == "[REDACTED]"
