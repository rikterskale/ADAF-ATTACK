"""Coverage for runner.execute_capability end-to-end (offline, fake capability)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import Capability, capability_registry
from adaf_attack.core.runner import RunError, execute_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _FakeRunner:
    def __init__(self, *, raises: bool = False) -> None:
        self.raises = raises
        self.calls: list[dict[str, Any]] = []

    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        include_secrets: bool = False,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if self.raises:
            raise ValueError("capability blew up")
        self.calls.append({"force": force, "include_secrets": include_secrets, **kwargs})
        graph.add_node("SID@S-1-5-21-1", "Base", sid="S-1-5-21-1")
        return {"echo": kwargs.get("echo", "hi")}


def _register(cap_id: str, **kwargs: Any) -> Capability:
    cap = Capability(id=cap_id, summary="test", **kwargs)
    capability_registry._capabilities[cap_id] = cap
    return cap


@pytest.fixture()
def cleanup_registry() -> Iterator[list[str]]:
    added: list[str] = []
    yield added
    for cap_id in added:
        capability_registry._capabilities.pop(cap_id, None)


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10")


def test_execute_unknown_capability_raises() -> None:
    with pytest.raises(RunError, match="Unknown capability"):
        execute_capability("does-not-exist", _target())


def test_execute_destructive_without_force(cleanup_registry: list[str]) -> None:
    cleanup_registry.append("t-destructive")
    _register("t-destructive", destructive=True, runner=_FakeRunner())
    with pytest.raises(RunError, match="DESTRUCTIVE"):
        execute_capability("t-destructive", _target())


def test_execute_no_runner(cleanup_registry: list[str]) -> None:
    cleanup_registry.append("t-norunner")
    _register("t-norunner", runner=None)
    with pytest.raises(RunError, match="no runner"):
        execute_capability("t-norunner", _target())


def test_execute_happy_path(cleanup_registry: list[str], tmp_path: Any) -> None:
    cleanup_registry.append("t-ok")
    runner = _FakeRunner()
    _register("t-ok", runner=runner)
    logs: list[str] = []
    out = execute_capability(
        "t-ok",
        _target(),
        workspace=tmp_path,
        log=logs.append,
        echo="value",
    )
    assert out["ok"] is True
    assert out["capability"] == "t-ok"
    assert out["result"] == {"echo": "value"}
    assert "graph_summary" in out and "interesting" in out
    assert any("Running t-ok" in line for line in logs)
    assert runner.calls[0]["echo"] == "value"
    # interesting.json artifact should have been written
    assert (out["session_path"]) and "cred_attempts" in out


def test_execute_capability_error_wrapped(cleanup_registry: list[str], tmp_path: Any) -> None:
    cleanup_registry.append("t-boom")
    _register("t-boom", runner=_FakeRunner(raises=True))
    with pytest.raises(RunError, match="capability blew up"):
        execute_capability("t-boom", _target(), workspace=tmp_path)


def test_execute_credential_resolution_failure(
    cleanup_registry: list[str], tmp_path: Any, monkeypatch: Any
) -> None:
    cleanup_registry.append("t-credfail")
    _register("t-credfail", runner=_FakeRunner())

    import adaf_attack.core.runner as runner_mod

    def boom(*a: Any, **k: Any) -> Any:
        raise ValueError("resolve exploded")

    monkeypatch.setattr(runner_mod, "_resolve_target", boom)
    with pytest.raises(RunError, match="Credential resolution failed"):
        execute_capability("t-credfail", _target(), workspace=tmp_path)


def test_execute_session_index_warning_is_logged(
    cleanup_registry: list[str], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from adaf_attack.core import runner as runner_mod

    cleanup_registry.append("t-idxwarn")
    _register("t-idxwarn", runner=_FakeRunner())

    class _BoomStore:
        def __init__(self, path: Any) -> None:
            pass

        def index_session(self, *args: Any, **kwargs: Any) -> None:
            raise OSError("disk on fire")

    monkeypatch.setattr(runner_mod, "SessionStore", _BoomStore)
    logs: list[str] = []
    out = execute_capability("t-idxwarn", _target(), workspace=tmp_path, log=logs.append)
    assert out["ok"] is True
    assert any("Session index warning" in line for line in logs)
