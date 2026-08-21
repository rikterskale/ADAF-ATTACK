"""Tests for the in-workflow TGT capture listener (core.tgt_capture)."""

from __future__ import annotations

import socket
import struct
import time
from typing import Any

import pytest

import adaf_attack.capabilities.joined_workflows as joined_workflows
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.tgt_capture import (
    KERBEROS_OID,
    TgtCaptureListener,
    _extract_apreq,
    _read_exact,
)
from tests.gate_helpers import target


def _apreq(content: bytes = b"\x00\x01\x02") -> bytes:
    return bytes([0x6E, len(content)]) + content


def _smb_blob(apreq_bytes: bytes) -> bytes:
    """NetBIOS session header + minimal SMB2 session-setup with SPNEGO blob."""
    token = KERBEROS_OID + apreq_bytes
    spnego = b"a1" + bytes([len(token) + 2]) + b"\x30" + bytes([len(token)]) + token
    smb2 = struct.pack("<HH", 0xFE53, 64) + b"\x00" * 60 + spnego
    return bytes([0]) + len(smb2).to_bytes(3, "big") + smb2


def test_extract_apreq_variants() -> None:
    assert _extract_apreq(b"\xde\xad\xbe\xef") is None
    assert _extract_apreq(KERBEROS_OID + b"\x6d\x01\x02") is None  # wrong tag
    assert _extract_apreq(KERBEROS_OID) is None  # truncated before tag
    assert _extract_apreq(KERBEROS_OID + b"\x6e") is None  # truncated length
    assert _extract_apreq(KERBEROS_OID + b"\x6e\x84") is None  # reserved length form
    assert _extract_apreq(KERBEROS_OID + b"\x6e\x85\x01") is None  # truncated long length
    assert _extract_apreq(KERBEROS_OID + b"\x6e\x82\x04\x00" + b"\xaa" * 2) is None
    long_form = b"\x6e\x82\x00\x03" + b"\xbb" * 3
    assert _extract_apreq(KERBEROS_OID + long_form) == long_form
    short = _apreq()
    assert _extract_apreq(KERBEROS_OID + short + b"trailing") == short


def test_listener_capture_roundtrip(tmp_path: Any) -> None:
    listener = TgtCaptureListener(tmp_path, host="127.0.0.1", port=44591, timeout=5.0)
    assert listener.start() is True
    sock = socket.create_connection(("127.0.0.1", 44591), timeout=3)
    sock.sendall(_smb_blob(_apreq()))
    captures = listener.wait()
    sock.close()
    listener.stop()
    assert len(captures) == 1
    assert captures[0]["host"] == "127.0.0.1"
    assert captures[0]["size"] > 0
    doc = listener.summary()
    assert doc["performed"] is True and doc["count"] == 1


class _FakeSock:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    def recv(self, _n: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class _ErrSock:
    def recv(self, _n: int) -> bytes:
        raise OSError("reset")


def test_read_exact_variants() -> None:
    assert _read_exact(_FakeSock([b"ab", b"cd"]), 4) == b"abcd"
    assert _read_exact(_FakeSock([b"a"]), 2) is None
    assert _read_exact(_FakeSock([b"a", b""]), 2) is None
    assert _read_exact(_ErrSock(), 1) is None


def test_listener_bind_error(tmp_path: Any) -> None:
    first = TgtCaptureListener(tmp_path, port=44592)
    assert first.start() is True
    second = TgtCaptureListener(tmp_path / "other", port=44592)
    try:
        assert second.start() is False
        assert second.error is not None
        assert "bind failed" in second.summary()["error"]
    finally:
        first.stop()
        second.stop()


def test_listener_garbage_and_empty_payload(tmp_path: Any) -> None:
    listener = TgtCaptureListener(tmp_path, host="127.0.0.1", port=44593, timeout=2.0)
    assert listener.start() is True
    try:
        for blob in (
            bytes([0]) + (5).to_bytes(3, "big") + b"\xaa" * 5,
            bytes([1]) + (2).to_bytes(3, "big") + b"\xbb\xbb",
            bytes([0]) + (0).to_bytes(3, "big"),
        ):
            sock = socket.create_connection(("127.0.0.1", 44593), timeout=3)
            sock.sendall(blob)
            sock.shutdown(socket.SHUT_WR)
            time.sleep(0.1)
            sock.close()
        assert listener.wait() == []
        assert listener.summary()["count"] == 0
    finally:
        listener.stop()


def test_listener_accept_oserror_and_handler_error(tmp_path: Any) -> None:
    listener = TgtCaptureListener(tmp_path, host="127.0.0.1", port=44594, timeout=2.0)
    assert listener.start() is True
    server = listener._server
    try:
        if server is not None:
            server.close()  # force OSError from settimeout/accept inside wait()
        assert listener.wait() == []
        assert listener.error is not None
        listener.stop()

        class _Raising(TgtCaptureListener):
            def _handle_connection(self, conn: socket.socket, addr: Any) -> None:
                raise OSError("handler failed")

        raising = _Raising(tmp_path / "r", host="127.0.0.1", port=44594, timeout=2.0)
        assert raising.start() is True
        sock = socket.create_connection(("127.0.0.1", 44594), timeout=3)
        sock.sendall(_smb_blob(_apreq()))
        sock.close()
        assert raising.wait() == []
        assert raising.error == "handler failed"
        raising.stop()
    finally:
        listener.stop()


def test_listener_truncated_payload(tmp_path: Any) -> None:
    listener = TgtCaptureListener(tmp_path, host="127.0.0.1", port=44595, timeout=2.0)
    assert listener.start() is True
    try:
        sock = socket.create_connection(("127.0.0.1", 44595), timeout=3)
        sock.sendall(bytes([0]) + (64).to_bytes(3, "big") + b"partial")
        sock.shutdown(socket.SHUT_WR)
        time.sleep(0.1)
        sock.close()
        assert listener.wait() == []
    finally:
        listener.stop()


def test_workflow_capture_success(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Hunt:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "count": 1,
                "principals": [{"unconstrained": True, "dns": "dc01.corp.test"}],
            }

    coerce_kwargs: dict[str, Any] = {}

    class _Coerce:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            coerce_kwargs.update(kwargs)

            class _FakeConn:
                def settimeout(self, _: float) -> None:
                    return None

                def close(self) -> None:
                    return None

            listener._write_capture(b"\x6e\x03abc", "10.0.0.5")
            return {"ok": True}

    monkeypatch.setattr(joined_workflows, "UnconstrainedDelegation", _Hunt)
    monkeypatch.setattr(joined_workflows, "Coerce", _Coerce)
    session = Session(base_dir=tmp_path)
    graph = AttackGraph()
    listener = TgtCaptureListener(session.path("captured"), timeout=1.0)
    monkeypatch.setattr(joined_workflows, "TgtCaptureListener", lambda *_a, **_k: listener)
    result = joined_workflows.UnconstTgtDumpWorkflow().run(
        target(), session, graph, force=True, capture=True
    )
    assert result["capture"]["count"] == 1
    assert result["capture"]["files"][0].endswith("10.0.0.5-1.kirbi")
    assert coerce_kwargs["listener"].endswith(f":{listener.port}")


def test_workflow_capture_timeout_still_ok(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Hunt:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"count": 1, "principals": [{"unconstrained": True, "dns": "dc"}]}

    class _Coerce:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

    monkeypatch.setattr(joined_workflows, "UnconstrainedDelegation", _Hunt)
    monkeypatch.setattr(joined_workflows, "Coerce", _Coerce)
    session = Session(base_dir=tmp_path)
    result = joined_workflows.UnconstTgtDumpWorkflow().run(
        target(), session, AttackGraph(), force=True, capture=True, capture_timeout=0.05
    )
    assert result["capture"]["performed"] is True
    assert result["capture"]["count"] == 0


def test_workflow_capture_bind_failure_falls_back(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Hunt:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"count": 1, "principals": [{"unconstrained": True, "dns": "dc"}]}

    seen: dict[str, Any] = {}

    class _Coerce:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            seen.update(kwargs)
            return {"ok": True}

    monkeypatch.setattr(joined_workflows, "UnconstrainedDelegation", _Hunt)
    monkeypatch.setattr(joined_workflows, "Coerce", _Coerce)

    class _BrokenListener(TgtCaptureListener):
        def start(self) -> bool:
            self.error = "boom"
            return False

    monkeypatch.setattr(joined_workflows, "TgtCaptureListener", _BrokenListener)
    session = Session(base_dir=tmp_path)
    result = joined_workflows.UnconstTgtDumpWorkflow().run(
        target(), session, AttackGraph(), force=True, capture=True
    )
    assert result["capture"]["performed"] is True
    assert result["capture"]["error"] == "boom"


def test_workflow_capture_without_host(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Hunt:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"count": 0, "principals": []}

    monkeypatch.setattr(joined_workflows, "UnconstrainedDelegation", _Hunt)
    session = Session(base_dir=tmp_path)
    result = joined_workflows.UnconstTgtDumpWorkflow().run(
        target(), session, AttackGraph(), force=True, capture=True
    )
    assert result["capture"] == {"performed": True, "count": 0}
    assert result["coerce"] == {"skipped": "no_unconstrained_host"}
