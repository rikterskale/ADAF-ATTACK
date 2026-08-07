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
    "USER_ABORTED": (
        "The interactive confirmation was declined.",
        "Re-run with --yes when the destructive action is authorized.",
    ),
    "ENGAGEMENT_PLAN_INVALID": (
        "The engagement plan YAML is invalid.",
        "Correct the YAML scope and validate again.",
    ),
    "ENGAGEMENT_RUN_BLOCKED": (
        "The engagement plan could not run against the requested target.",
        "Review target scope, authorization, and phase configuration.",
    ),
    "ENGAGEMENT_PACKAGE_FAILED": (
        "The engagement evidence package could not be created.",
        "Use an existing session and a valid redaction profile.",
    ),
    "SESSION_NOT_FOUND": (
        "One or more session directories do not exist.",
        "Pass an existing session directory created by a prior authorized run.",
    ),
    "BLOODHOUND_FILE_NOT_FOUND": (
        "The BloodHound JSON file does not exist.",
        "Pass a valid JSON export with --bloodhound.",
    ),
    "FOREST_CAMPAIGN_FAILED": (
        "The forest campaign could not be composed from these sessions.",
        "Pass completed, authorized session directories.",
    ),
    "CAMPAIGN_RUN_FAILED": (
        "The campaign run failed before completion.",
        "Validate the campaign plans, scopes, and approval-token mapping.",
    ),
    "FIXTURE_AUTHORIZATION_REQUIRED": (
        "Fixture validation requires explicit confirmation that fixtures are authorized.",
        "Re-run with --authorized-fixtures only for isolated, authorized test data.",
    ),
    "FIXTURE_DIRECTORY_NOT_FOUND": (
        "The fixture directory does not exist.",
        "Pass an existing directory containing JSON fixtures.",
    ),
    "UNKNOWN_WORKFLOW_PROFILE": (
        "The requested workflow profile is not defined.",
        "Run `adaf-attack workflow-profiles` to list valid profile names.",
    ),
    "INTERACTIVE_MODE_DISABLED": (
        "An interactive command was invoked with --non-interactive.",
        "Use a non-interactive command such as `adaf-attack capability-help` or `adaf-attack plan`.",
    ),
    "TUI_DEPENDENCY_MISSING": (
        "Textual is required for the interactive shell.",
        "Install TUI support: pip install 'adaf-attack[tui]'.",
    ),
    "CONFIG_KEY_INVALID": (
        "The config key is not recognized.",
        "Run `adaf-attack config keys` to list allowed keys.",
    ),
}


def error_for(
    code: str, *, message: str | None = None, details: dict[str, Any] | None = None
) -> ActionableError:
    default_message, remediation = ERROR_CATALOG[code]
    return ActionableError(code, message or default_message, remediation, details=details)
