"""Stable CLI output and error contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ActionableError(Exception):
    """A user-facing failure with a stable code and remediation."""

    code: str
    message: str
    remediation: str
    exit_code: int = 1
    details: dict[str, Any] | None = None

    def payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["ok"] = False
        payload.pop("exit_code")
        return {"error": payload}


ERROR_CATALOG: dict[str, tuple[str, str]] = {
    "UNKNOWN_CAPABILITY": (
        "The requested capability is not registered.",
        "Run `adaf-attack capability-help` to see supported capability IDs.",
    ),
    "DESTRUCTIVE_CONFIRMATION_REQUIRED": (
        "This capability can modify a target and requires explicit confirmation.",
        "Review `adaf-attack plan <capability> ...`, then re-run with --force if authorized.",
    ),
    "CAPABILITY_UNAVAILABLE": (
        "The capability is registered but has no runnable implementation.",
        "Choose another capability or install the release that provides this implementation.",
    ),
    "GRAPH_NOT_FOUND": (
        "The requested graph file does not exist.",
        "Pass a valid --graph path or run an enumeration capability to create graph.json.",
    ),
    "RUN_FAILED": (
        "The capability could not complete.",
        "Review the message and session events; correct the target, credentials, or prerequisite and retry.",
    ),
}


def error_for(code: str, *, message: str | None = None, details: dict[str, Any] | None = None) -> ActionableError:
    default_message, remediation = ERROR_CATALOG[code]
    return ActionableError(code, message or default_message, remediation, details=details)
