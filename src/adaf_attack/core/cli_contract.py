"""Stable CLI output and error contracts."""

from __future__ import annotations

import re
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
    suggested_command: str | None = None

    def payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["ok"] = False
        payload.pop("exit_code")
        if not payload.get("suggested_command"):
            payload.pop("suggested_command", None)
        return {"error": payload}


ERROR_CATALOG: dict[str, tuple[str, ...]] = {
    "UNKNOWN_CAPABILITY": (
        "The requested capability is not registered.",
        "Run `adaf-attack capability-help` to see supported capability IDs.",
        "adaf-attack capability-help",
    ),
    "DESTRUCTIVE_CONFIRMATION_REQUIRED": (
        "This capability can modify a target and requires explicit confirmation.",
        "Review `adaf-attack plan <capability> ...`, then re-run with --force if authorized.",
        "adaf-attack plan <capability> -d <domain> --dc-ip <dc>",
    ),
    "CAPABILITY_UNAVAILABLE": (
        "The capability is registered but has no runnable implementation.",
        "Choose another capability or install the release that provides this implementation.",
    ),
    "GRAPH_NOT_FOUND": (
        "The requested graph file does not exist.",
        "Pass a valid --graph path or run an enumeration capability to create graph.json.",
        "adaf-attack run ldap-enum -d <domain> --dc-ip <dc>",
    ),
    "RUN_FAILED": (
        "The capability could not complete.",
        "Review the message and session events; correct the target, credentials, or prerequisite and retry.",
    ),
    "USER_ABORTED": (
        "The interactive confirmation was declined.",
        "Re-run with --yes when the destructive action is authorized.",
        "adaf-attack run <capability> ... --force --yes",
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
        "adaf-attack sessions --limit 10",
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
    "WORKFLOW_STATE_INVALID": (
        "The persisted guided-workflow state could not be read.",
        "Inspect workflow-state.json in the workspace, or start a new workflow in a clean workspace.",
        "adaf-attack workflow status --workspace <workspace>",
    ),
    "WORKFLOW_TRANSITION_INVALID": (
        "The guided-workflow engine rejected this transition or action.",
        "Run `adaf-attack workflow next` to see the ranked, allowed next actions.",
        "adaf-attack workflow next --workspace <workspace>",
    ),
    "INTERACTIVE_MODE_DISABLED": (
        "An interactive command was invoked with --non-interactive.",
        "Use a non-interactive command such as `adaf-attack capability-help` or `adaf-attack plan`.",
        "adaf-attack capability-help",
    ),
    "TUI_DEPENDENCY_MISSING": (
        "Textual is required for the interactive shell.",
        "Install TUI support: pip install 'adaf-attack[tui]'.",
        "pip install 'adaf-attack[tui]'",
    ),
    "CONFIG_KEY_INVALID": (
        "The config key is not recognized.",
        "Run `adaf-attack config keys` to list allowed keys.",
        "adaf-attack config keys",
    ),
    "CONFIG_WRITE_FAILED": (
        "The per-user configuration could not be written.",
        "Choose a writable config directory, check permissions, then run `adaf-attack doctor --explain`.",
        "adaf-attack doctor --explain",
    ),
    "AUTHENTICATION_FAILED": (
        "The target rejected the supplied authentication material.",
        "Verify the username, secret source, clock, DNS, and required authentication extra; do not put passwords in shell history.",
        "adaf-attack doctor --profile live-ad --domain <domain> --dc-ip <dc>",
    ),
    "TARGET_UNREACHABLE": (
        "The target could not be reached from this operator environment.",
        "Verify DNS, routing, firewall rules, the private lab network, and the DC address before retrying.",
        "adaf-attack doctor --profile live-ad --domain <domain> --dc-ip <dc>",
    ),
    "REQUIRED_INPUT_MISSING": (
        "The capability is missing a required input.",
        "Run capability-help for the capability and provide the named option or -P parameter.",
        "adaf-attack capability-help <capability>",
    ),
    "INPUT_FILE_INVALID": (
        "An input file or artifact could not be read or is not in the expected format.",
        "Check that the path exists, is readable, and matches the documented JSON/YAML/artifact format.",
        "adaf-attack doctor --explain",
    ),
    "PERMISSION_DENIED": (
        "The operating system denied access to a file, directory, or protected operation.",
        "Choose a writable workspace/config path or use the documented elevated operation only when authorized.",
        "adaf-attack paths",
    ),
    "SUPPORT_BUNDLE_WRITE_FAILED": (
        "The redacted support bundle could not be written.",
        "Choose a writable output directory and rerun the support-bundle command.",
        "adaf-attack support-bundle --output <writable-path>",
    ),
    "UNKNOWN_PROFILE": (
        "The requested profile is not saved.",
        "Run `adaf-attack profile list` to see saved profiles.",
        "adaf-attack profile list",
    ),
    "INVALID_OPSEC_PROFILE": (
        "The opsec profile value is not recognized.",
        "Choose stealth, balanced, or loud.",
        "adaf-attack profile set lab --opsec balanced",
    ),
    "DEMO_FIXTURES_MISSING": (
        "Demo session fixtures are not available in this install.",
        "Run from a source checkout or reinstall with fixtures present.",
        "adaf-attack doctor",
    ),
    "UNSUPPORTED_SHELL": (
        "The requested shell is not supported for completions.",
        "Choose bash, zsh, fish, or powershell.",
        "adaf-attack completions bash",
    ),
}


_ERROR_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "AUTHENTICATION_FAILED",
        (
            "ldap bind failed",
            "all credentials failed",
            "authentication failed",
            "invalid credentials",
            "logon failure",
        ),
    ),
    (
        "TARGET_UNREACHABLE",
        (
            "connection refused",
            "timed out",
            "timeout",
            "network is unreachable",
            "name or service not known",
            "could not connect",
            "connection error",
        ),
    ),
    ("PERMISSION_DENIED", ("permission denied", "access is denied", "operation not permitted")),
    (
        "INPUT_FILE_INVALID",
        (
            "file not found",
            "not found:",
            "path is not a directory",
            "invalid json",
            "invalid yaml",
            "artifact not found",
            "could not read",
        ),
    ),
    (
        "REQUIRED_INPUT_MISSING",
        ("pass -p", "required", "username required", "provide -p", "requires --"),
    ),
)


def classify_run_error(message: str) -> str:
    """Return the most actionable catalog code for a runner failure."""
    lowered = re.sub(r"\s+", " ", message.lower())
    for code, patterns in _ERROR_PATTERNS:
        if any(pattern in lowered for pattern in patterns):
            return code
    return "RUN_FAILED"


def error_for(
    code: str,
    *,
    message: str | None = None,
    details: dict[str, Any] | None = None,
    suggested_command: str | None = None,
) -> ActionableError:
    entry = ERROR_CATALOG[code]
    default_message = entry[0]
    remediation = entry[1]
    catalog_cmd = entry[2] if len(entry) > 2 else None
    return ActionableError(
        code,
        message or default_message,
        remediation,
        details=details,
        suggested_command=suggested_command or catalog_cmd,
    )
