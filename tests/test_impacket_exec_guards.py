"""impacket-exec guardrail tests (no actual execution)."""

from __future__ import annotations

import pytest
from adaf_attack.capabilities.impacket_exec import METHODS, ImpacketExec
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def test_methods_registered() -> None:
    assert METHODS == ("wmiexec", "smbexec", "dcomexec", "atexec")


def test_refuses_without_force(tmp_path) -> None:
    session = Session(base_dir=tmp_path)
    graph = AttackGraph()
    target = Target(domain="corp", dc_ip="10.0.0.10", username="a", password="b")
    with pytest.raises(RuntimeError, match="destructive"):
        ImpacketExec().run(target, session, graph, force=False, command="whoami")


def test_refuses_unknown_method(tmp_path) -> None:
    session = Session(base_dir=tmp_path)
    graph = AttackGraph()
    target = Target(domain="corp", dc_ip="10.0.0.10", username="a", password="b")
    with pytest.raises(RuntimeError, match="unknown method"):
        ImpacketExec().run(target, session, graph, force=True, method="bogus", command="whoami")
