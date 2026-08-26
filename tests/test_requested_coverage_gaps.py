"""Behavioral coverage for the remaining low-coverage support components."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from adaf_attack.core import engagement, engineering, execution_policy, glyphs, outcomes
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.operator_table import TableColumn, adaptive_widths, copy_to_clipboard
from adaf_attack.core.registry import Capability, RiskLevel, SafetyProfile
from adaf_attack.core.session import Session, verify_event_log
from adaf_attack.core.target import Target
from adaf_attack.core.tgt_capture import KERBEROS_OID, TgtCaptureListener

runner = CliRunner()


def test_glyph_fallbacks_and_keys() -> None:
    assert glyphs.render_status("new", mode="ascii") == "[NEW] NEW"
    assert glyphs.render_status("new") == "[white][NEW] NEW[/white]"
    assert glyphs.render_severity("new", mode="ascii") == "[N] NEW"
    assert glyphs.render_severity("new") == "[white][N] NEW[/white]"
    assert glyphs.status_keys() == tuple(glyphs.STATUS_GLYPHS)
    assert glyphs.severity_keys() == tuple(glyphs.SEVERITY_GLYPHS)


def test_operator_table_width_edges_and_clipboard_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    columns = [TableColumn("A", min_width=2, max_width=3), TableColumn("B", min_width=2)]
    assert adaptive_widths(columns, [], width=1) == [2, 2]
    monkeypatch.setattr("adaf_attack.core.operator_table.os.name", "nt")
    monkeypatch.setattr("adaf_attack.core.operator_table.shutil.which", lambda name: "clip")
    seen: dict[str, Any] = {}

    def run(command: list[str], **kwargs: Any) -> None:
        seen.update(command=command, **kwargs)

    monkeypatch.setattr("adaf_attack.core.operator_table.subprocess.run", run)
    assert copy_to_clipboard("abc") == {"ok": True, "provider": "clip", "characters": 3}
    assert seen["command"] == ["clip"]


def test_operator_table_clipboard_provider_failure_and_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("adaf_attack.core.operator_table.os.name", "posix")
    monkeypatch.setattr(
        "adaf_attack.core.operator_table.shutil.which",
        lambda name: "xclip" if name == "xclip" else None,
    )
    monkeypatch.setattr(
        "adaf_attack.core.operator_table.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.SubprocessError("no")),
    )
    result = copy_to_clipboard("abc")
    assert result["ok"] is False
    assert result["reason"].startswith("No supported")
    monkeypatch.setattr(
        "adaf_attack.core.operator_table.shutil.which",
        lambda name: "pbcopy" if name == "pbcopy" else None,
    )
    monkeypatch.setattr("adaf_attack.core.operator_table.subprocess.run", lambda *a, **k: None)
    assert copy_to_clipboard("abc")["provider"] == "pbcopy"


def test_outcome_normalization_and_rollback_states(tmp_path: Path) -> None:
    assert outcomes.normalize_capability_result({"outcome": {"ok": 1}})["ok"] is True
    assert outcomes.normalize_capability_result({"return_code": 1})["ok"] is False
    assert outcomes.normalize_capability_result({"error": "bad"})["ok"] is False
    assert outcomes.normalize_capability_result(0)["ok"] is False
    graph = AttackGraph()
    for cleanup in ([], [{"status": "pending"}], [{"status": "completed"}], [{"status": "failed"}]):
        if cleanup:
            (tmp_path / "cleanup.json").write_text(json.dumps(cleanup), encoding="utf-8")
        elif (tmp_path / "cleanup.json").exists():
            (tmp_path / "cleanup.json").unlink()
        result = outcomes.build_post_execution_outcome(
            tmp_path, capability="x", result={"ok": True}, graph=graph, auth="test"
        )
        expected = (
            "failed"
            if cleanup and cleanup[0]["status"] == "failed"
            else (
                "pending"
                if cleanup and cleanup[0]["status"] == "pending"
                else "verified"
                if cleanup
                else "not-required"
            )
        )
        assert result["rollback"]["status"] == expected
    (tmp_path / "cleanup.json").write_text("{}", encoding="utf-8")
    assert outcomes._load_cleanup(tmp_path / "cleanup.json") == []
    (tmp_path / "cleanup.json").write_text("not json", encoding="utf-8")
    assert outcomes._load_cleanup(tmp_path / "cleanup.json") == []


def test_execution_policy_defensive_and_read_operation_branches() -> None:
    cap = Capability("x", "x", safety=SafetyProfile())
    object.__setattr__(cap, "safety", None)
    with pytest.raises(execution_policy.PolicyError, match="no safety profile"):
        execution_policy.enforce_execution_policy(
            execution_policy.ExecutionRequest(cap, Target("d", "h"))
        )
    mixed = Capability(
        "rbcd", "r", safety=SafetyProfile(network_side_effect=True, exposes_credentials=True)
    )
    read = execution_policy.safety_for_operation(mixed, {"operation": "read"})
    assert read.risk == RiskLevel.OBSERVE and read.network_side_effect
    assert execution_policy.safety_for_operation(mixed, {"operation": "other"}) == mixed.safety


def test_engineering_mutating_and_plugin_load_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="mutating"):
        engineering.execute_with_controls(lambda: None, mutating=True, timeout=1)
    descriptor = engineering.PluginDescriptor("ok", "module", lambda: lambda: None)
    broken = engineering.PluginDescriptor(
        "bad", "broken", lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(engineering, "discover_plugins", lambda: [descriptor, broken])
    statuses = engineering.load_plugins()
    assert [item["status"] for item in statuses] == ["loaded", "failed"]
    assert statuses[1]["error"] == "boom"

    class ModuleLike:
        __path__ = []

    monkeypatch.setattr(
        engineering,
        "discover_plugins",
        lambda: [engineering.PluginDescriptor("module", "m", lambda: ModuleLike())],
    )
    assert engineering.load_plugins()[0]["status"] == "loaded"


def test_session_cleanup_and_event_log_failures(tmp_path: Path) -> None:
    session = Session(tmp_path)
    session.register_cleanup({"kind": "rbcd", "target": "CN=x"})
    assert json.loads(session.path("cleanup.json").read_text())[0]["status"] == "pending"
    bad = session.path("cleanup.json")
    bad.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="ledger"):
        session.register_cleanup({"kind": "rbcd", "target": "CN=x"})
    assert verify_event_log(tmp_path / "missing.json")["ok"] is False
    event_path = session.path("events.jsonl")
    event_path.write_text("{}\n", encoding="utf-8")
    assert "invalid event" in verify_event_log(event_path)["error"]
    event_path.write_text("not-json\n", encoding="utf-8")
    assert verify_event_log(event_path)["error"] == "event log is unreadable"
    event_path.write_text(
        json.dumps({"event_schema_version": 2, "prev_hash": "bad"}) + "\n", encoding="utf-8"
    )
    assert "chain break" in verify_event_log(event_path)["error"]
    event_path.write_text(
        json.dumps({"event_schema_version": 2, "prev_hash": "", "event_hash": "bad"}) + "\n",
        encoding="utf-8",
    )
    assert "hash mismatch" in verify_event_log(event_path)["error"]
    event_path.unlink()
    valid = Session(tmp_path / "valid")
    valid.log("valid")
    assert verify_event_log(valid.path("events.jsonl"))["ok"] is True
    valid_events = valid.path("events.jsonl").read_text(encoding="utf-8")
    valid.path("events.jsonl").write_text("\n" + valid_events, encoding="utf-8")
    assert verify_event_log(valid.path("events.jsonl"))["ok"] is True
    with pytest.raises(ValueError, match="non-empty"):
        session.log(" ")
    with pytest.raises(ValueError, match="reserved"):
        session.log("bad", type="override")
    with pytest.raises(ValueError, match="inside"):
        session.path("..", "outside")
    assert session.vault().root == session.root / "vault"


def test_tgt_capture_fake_socket_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    listener = TgtCaptureListener(tmp_path, host="")
    assert listener.endpoint == "127.0.0.1"

    class Server:
        def settimeout(self, _: float) -> None:
            pass

        def accept(self) -> Any:
            raise OSError("closed")

        def close(self) -> None:
            pass

    listener._server = Server()  # type: ignore[assignment]
    assert listener.wait() == []
    assert listener.error == "closed"
    listener.stop()
    assert listener._server is None

    class Conn:
        def settimeout(self, _: float) -> None:
            pass

        def close(self) -> None:
            pass

        def recv(self, _: int) -> bytes:
            return b""

    listener._handle_connection(Conn(), ("bad/host", 1))  # type: ignore[arg-type]
    assert listener.captures == []
    listener._write_capture(b"abc", "bad/host")
    assert (tmp_path / "captured" / "bad_host-1.kirbi").read_bytes() == b"abc"


def test_tgt_capture_socket_options_and_connection_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeServer:
        def setsockopt(self, *_: Any) -> None:
            pass

        def bind(self, *_: Any) -> None:
            pass

        def listen(self, *_: Any) -> None:
            pass

        def settimeout(self, *_: Any) -> None:
            pass

        def close(self) -> None:
            pass

    monkeypatch.setattr("adaf_attack.core.tgt_capture.socket.socket", lambda *a: FakeServer())
    monkeypatch.setattr("adaf_attack.core.tgt_capture.socket.SO_EXCLUSIVEADDRUSE", 1, raising=False)
    listener = TgtCaptureListener(tmp_path)
    assert listener.start() is True

    class Conn:
        def settimeout(self, _: float) -> None:
            pass

        def close(self) -> None:
            pass

        def __init__(self, chunks: list[bytes]) -> None:
            self.chunks = chunks

        def recv(self, _: int) -> bytes:
            return self.chunks.pop(0) if self.chunks else b""

    for chunks in (
        [b""],
        [b"\x01\x00\x00\x00"],
        [b"\x00\x00\x00\x00"],
        [b"\x00\x00\x00\x01", b""],
        [b"\x00\x00\x00\x01", b"x"],
    ):
        listener._handle_connection(Conn(list(chunks)), ("peer", 1))  # type: ignore[arg-type]
    listener.stop()
    monkeypatch.delattr("adaf_attack.core.tgt_capture.socket.SO_EXCLUSIVEADDRUSE", raising=False)
    fallback = TgtCaptureListener(tmp_path)
    assert fallback.start() is True
    fallback.stop()
    monkeypatch.setattr(
        "adaf_attack.core.tgt_capture.socket.socket",
        lambda *a: (_ for _ in ()).throw(OSError("socket")),
    )
    failed = TgtCaptureListener(tmp_path)
    assert failed.start() is False and "bind failed" in (failed.error or "")


def test_tgt_capture_timeout_and_successful_handler(tmp_path: Path) -> None:
    listener = TgtCaptureListener(tmp_path, timeout=1)

    class Conn:
        def settimeout(self, _: float) -> None:
            pass

        def close(self) -> None:
            pass

    class Server:
        def __init__(self) -> None:
            self.calls = 0

        def settimeout(self, _: float) -> None:
            pass

        def accept(self) -> Any:
            self.calls += 1
            if self.calls == 1:
                raise TimeoutError()
            return Conn(), ("peer", 1)

        def close(self) -> None:
            pass

    listener._server = Server()  # type: ignore[assignment]
    listener._handle_connection = lambda conn, addr: None  # type: ignore[method-assign]
    assert listener.wait() == []

    listener = TgtCaptureListener(tmp_path, timeout=1)

    class GoodConn:
        def settimeout(self, _: float) -> None:
            pass

        def close(self) -> None:
            pass

        def __init__(self) -> None:
            self.chunks = [b"\x00\x00\x00\x0d", KERBEROS_OID + b"\x6e\x00"]

        def recv(self, _: int) -> bytes:
            return self.chunks.pop(0)

    listener._handle_connection(GoodConn(), ("peer", 1))  # type: ignore[arg-type]
    assert listener.captures
    listener = TgtCaptureListener(tmp_path, timeout=1)

    class ErrorServer(Server):
        def accept(self) -> Any:
            if self.calls == 0:
                self.calls += 1
                return Conn(), ("peer", 1)
            raise OSError("accept failed")

    listener._server = ErrorServer()  # type: ignore[assignment]
    listener._handle_connection = lambda conn, addr: (_ for _ in ()).throw(
        OSError("handler failed")
    )  # type: ignore[method-assign]
    assert listener.wait() == []
    assert listener.error == "accept failed"


def test_coverage_cli_completion_modes(tmp_path: Path) -> None:
    output = runner.invoke(
        __import__("adaf_attack.cli", fromlist=["app"]).app,
        ["--format", "json", "completions", "bash", "--output-dir", str(tmp_path)],
    )
    assert output.exit_code == 0, output.output
    assert (tmp_path / "adaf-attack.bash").exists()
    all_json = runner.invoke(
        __import__("adaf_attack.cli", fromlist=["app"]).app,
        ["--format", "json", "completions", "bash", "--all"],
    )
    assert all_json.exit_code == 0
    assert "scripts" in json.loads(all_json.output)
    all_human = runner.invoke(
        __import__("adaf_attack.cli", fromlist=["app"]).app, ["completions", "bash", "--all"]
    )
    assert all_human.exit_code == 0 and "# ---- bash ----" in all_human.output


def test_ux_search_handles_unreadable_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from adaf_attack.core import ux

    session = tmp_path / "session"
    session.mkdir()
    (session / "graph.json").write_text('{"nodes": [], "edges": []}', encoding="utf-8")
    monkeypatch.setattr(
        type(session), "iterdir", lambda _self: (_ for _ in ()).throw(OSError("gone"))
    )
    result = ux.unified_search("x", session=session)
    assert not any(item["type"] == "evidence" for item in result["results"])


def _approval_token(payload: dict[str, Any], key: str = "secret") -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = (
        base64.urlsafe_b64encode(hmac.new(key.encode(), encoded.encode(), hashlib.sha256).digest())
        .decode()
        .rstrip("=")
    )
    return f"{encoded}.{signature}"


def test_engagement_validation_and_approval_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def write(value: Any, name: str = "p.yaml") -> Path:
        p = tmp_path / name
        p.write_text(json.dumps(value), encoding="utf-8")
        return p

    base = {
        "engagement_id": "E",
        "target": {"domain": "d", "dc_ip": "h"},
        "allowed_capabilities": ["ldap-enum"],
        "phases": [],
    }
    cases = [
        ([1], "root must be a mapping"),
        ({**base, "target": [1]}, "target must be a mapping"),
        ({**base, "allowed_capabilities": [1]}, "allowed_capabilities must be a list"),
        ({**base, "phases": {}}, "phases must be a list"),
        ({**base, "allowed_targets": [1]}, "allowed_targets must be a list"),
        ({**base, "phases": ["bad"]}, "Phase 0 must be a mapping"),
        ({**base, "phases": [{"capabilities": [1]}]}, "capabilities must be a list"),
        ({**base, "phases": [{"options": []}]}, "options must be a mapping"),
        ({**base, "phases": [{"options": {"force": True}}]}, "reserved execution fields"),
        ({**base, "phases": [{"capabilities": ["other"]}]}, "not allowed by engagement scope"),
        ({**base, "phases": [{"options": {"host": "other"}}]}, "outside allowed_targets"),
    ]
    for value, message in cases:
        with pytest.raises(engagement.EngagementError, match=message):
            engagement.load_plan(write(value, str(len(message)) + ".yaml"))
    engagement._validate_phase_targets({"ignored": "anything", "host": "HOST."}, ("host",))
    engagement._validate_phase_targets({"host": ["", "host"]}, ("host",))
    engagement._validate_approved_parameters(
        {"ignored": "anything", "host": ["", "host"]}, ["host"]
    )
    monkeypatch.setenv("ADAF_APPROVAL_HMAC_KEY", "secret")
    good = {
        "engagement_id": "E",
        "capabilities": ["x"],
        "targets": ["host"],
        "exp": int(datetime.now(UTC).timestamp()) + 100,
    }
    with pytest.raises(engagement.EngagementError, match="scope fields"):
        engagement.verify_scoped_approval(
            _approval_token({**good, "targets": "host"}),
            engagement_id="E",
            dc_ip="host",
            capability="x",
        )
    with pytest.raises(engagement.EngagementError, match="expiry is malformed"):
        engagement.verify_scoped_approval(
            _approval_token({**good, "exp": "bad"}), engagement_id="E", dc_ip="host", capability="x"
        )
    params = {"host": "host"}
    with pytest.raises(engagement.EngagementError, match="does not match"):
        engagement.verify_scoped_approval(
            _approval_token(good),
            engagement_id="E",
            dc_ip="host",
            capability="x",
            parameters=params,
        )
    digest = engagement.parameters_digest(params)
    assert (
        engagement.verify_scoped_approval(
            _approval_token({**good, "parameters_sha256": digest}),
            engagement_id="E",
            dc_ip="host",
            capability="x",
            parameters=params,
        )["engagement_id"]
        == "E"
    )
    with pytest.raises(engagement.EngagementError, match="does not permit phase target"):
        engagement.verify_scoped_approval(
            _approval_token({**good, "parameters_sha256": digest}),
            engagement_id="E",
            dc_ip="host",
            capability="x",
            parameters={"host": "other"},
        )


def test_engagement_run_unavailable_and_runerror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = engagement.EngagementPlan(
        "E", "d", "h", ("ldap-enum",), ({"capabilities": ["ldap-enum"], "options": []},), ("h",)
    )
    with pytest.raises(engagement.EngagementError, match="options must be a mapping"):
        engagement.run_engagement(plan, workspace=tmp_path)
    plan = engagement.EngagementPlan(
        "E", "d", "h", ("ldap-enum",), ({"capabilities": ["missing"], "options": {}},), ("h",)
    )
    with pytest.raises(engagement.EngagementError, match="not allowed"):
        engagement.run_engagement(plan, workspace=tmp_path)
    plan = engagement.EngagementPlan(
        "E", "d", "h", ("ldap-enum",), ({"capabilities": ["ldap-enum"], "options": {}},), ("h",)
    )
    import adaf_attack.core.runner as runner_mod

    monkeypatch.setattr(
        runner_mod,
        "execute_capability",
        lambda *a, **k: (_ for _ in ()).throw(runner_mod.RunError("boom")),
    )
    with pytest.raises(engagement.EngagementError, match="Phase 'unnamed' failed"):
        engagement.run_engagement(plan, workspace=tmp_path)
