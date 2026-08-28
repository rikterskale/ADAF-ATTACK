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
    "FIRST_DESTRUCTIVE_USE_CONFIRMATION_REQUIRED": (
        "The first destructive use of this capability in the workspace needs acknowledgement.",
        "Review the plan, then re-run with --i-understand when authorized.",
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
        "Review the message and session events, run `adaf-attack doctor --explain`, "
        "and create a redacted support bundle before requesting help.",
        "adaf-attack support-bundle --output adaf-support-bundle.json",
    ),
    "USER_ABORTED": (
        "The interactive confirmation was declined.",
        "Re-run with --yes when the destructive action is authorized.",
        "adaf-attack run <capability> ... --force --yes",
    ),
    "APPROVAL_VERIFIER_INSECURE": (
        "The built-in HMAC approval verifier is not permitted when ADAF_ATTACK_ENV=prod.",
        "Deploy an asymmetric JWKS verifier for production, or set ADAF_APPROVAL_HMAC_ACKNOWLEDGE_PROD=1 to explicitly accept the shared-secret verifier for this engagement.",
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
    "UNKNOWN_FINDING": (
        "The requested finding was not found in the session.",
        "Run `adaf-attack session show --session <dir>` to list finding IDs.",
        "adaf-attack session show --session <dir>",
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
        "Verify DNS, routing, firewall rules, and the authorized DC address before retrying.",
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
    "INVALID_PROFILE": (
        "The supplied profile fields are invalid.",
        "Correct the profile fields and try again.",
        "adaf-attack profile list",
    ),
    "INVALID_OPSEC_PROFILE": (
        "The opsec profile value is not recognized.",
        "Choose stealth, balanced, or loud.",
        "adaf-attack profile set engagement --opsec balanced",
    ),
    "DEMO_FIXTURES_MISSING": (
        "Demo session fixtures are not available in this install.",
        "Run from a source checkout or reinstall with fixtures present.",
        "adaf-attack doctor",
    ),
    "QUICKSTART_WORKSPACE_EXISTS": (
        "The selected quickstart workspace already contains a demo session.",
        "Choose an empty workspace path; quickstart will not overwrite an existing session.",
        "adaf-attack quickstart --workspace ./quickstart-2",
    ),
    "QUICKSTART_WRITE_FAILED": (
        "The quickstart demo session could not be created.",
        "Choose a writable workspace and rerun quickstart.",
        "adaf-attack paths",
    ),
    "QUICKSTART_READINESS_BLOCKED": (
        "The local installation is not ready for the offline quickstart.",
        "Follow the first blocking doctor check, then rerun the user-readiness profile.",
        "adaf-attack doctor --profile user-readiness --explain",
    ),
    "UNKNOWN_ERROR_CODE": (
        "The requested error code is not in the catalog.",
        "Run `adaf-attack errors` to list supported error codes.",
        "adaf-attack errors",
    ),
    "UNSUPPORTED_SHELL": (
        "The requested shell is not supported for completions.",
        "Choose bash, zsh, fish, or powershell.",
        "adaf-attack completions bash",
    ),
    "GUIDE_ADVANCE_UNSAFE": (
        "The current guide step cannot be auto-advanced.",
        "Copy and run the suggested command after review; live or destructive steps stay manual.",
        "adaf-attack guide",
    ),
    "APPROVAL_TOKEN_EXPIRED": (
        "The approval token is expired or not yet valid.",
        "Request a fresh scoped token for this engagement ID, then re-run with --approval-token.",
        "adaf-attack guide",
    ),
    "APPROVAL_TOKEN_INVALID": (
        "The approval token was rejected for this engagement.",
        "Confirm --engagement-id matches the token, then re-run with a valid --approval-token.",
        "adaf-attack guide",
    ),
    "PYTHON_UNSUPPORTED": (
        "The active Python version is outside the supported 3.11-3.14 range.",
        "Create a venv with Python 3.11, 3.12, 3.13, or 3.14, then reinstall the approved wheel.",
        "adaf-attack doctor --profile user-readiness --explain",
    ),
    "VENV_REQUIRED": (
        "A virtual environment is required (system Python is externally managed or unprotected).",
        "Run `python -m venv .venv`, activate it, then install the approved wheel into that venv.",
        "adaf-attack doctor --profile user-readiness --explain",
    ),
    "PATH_NOT_FOUND": (
        "The adaf-attack entry point is not on PATH for this shell.",
        "Open a new terminal after install, or invoke the venv Scripts/bin path directly.",
        "adaf-attack doctor --profile user-readiness --explain",
    ),
    "EXECUTION_POLICY_BLOCKED": (
        "PowerShell execution policy or SmartScreen blocked the installer script.",
        "Use the narrowest approved CurrentUser RemoteSigned policy, Unblock-File the script, then retry.",
        "adaf-attack doctor --profile user-readiness --explain",
    ),
    "PROXY_TLS_FAILED": (
        "pip could not validate TLS through the organization proxy or custom CA.",
        "Configure the approved CA with pip --cert or pip.ini, or use an air-gapped wheelhouse with --no-index.",
        "adaf-attack doctor --explain",
    ),
    "EXTRA_MISSING": (
        "An optional extra required for this surface is not installed.",
        "Install the documented extra (for example pip install 'adaf-attack[tui]') and rerun doctor.",
        "adaf-attack doctor --profile operator --explain",
    ),
    "SECRET_IN_OUTPUT": (
        "A secret or credential value appeared in a redacted operator surface.",
        "Do not share the output; rotate the exposed secret if it was real, then regenerate a redacted support bundle.",
        "adaf-attack support-bundle --output adaf-support-bundle.json",
    ),
    "VERSION_SKEW": (
        "Installed package metadata does not match adaf_attack.__version__.",
        "Reinstall the approved wheel into a clean venv so metadata and runtime version agree, then rerun doctor.",
        "adaf-attack doctor --profile user-readiness --explain",
    ),
    "INSTALLER_FAILURE": (
        "The platform installer could not complete.",
        "Rerun the Windows or Kali installer with -Json/--json, then follow the remediation field.",
        "adaf-attack doctor --profile user-readiness --explain",
    ),
    "INSTALLER_OWNERSHIP": (
        "The installer refused to modify an unowned or conflicting environment.",
        "Uninstall the installer-owned environment first, or choose a dedicated venv/shim path.",
        "adaf-attack doctor --profile user-readiness --explain",
    ),
    "KALI_REQUIRED": (
        "The Kali installer was run on a non-Kali host.",
        "Use the generic Linux or macOS wheel install path on this platform.",
        "adaf-attack doctor --profile user-readiness --explain",
    ),
    "UNOWNED_VENV": (
        "The installer refused to remove or modify an unowned virtual environment.",
        "Choose a dedicated ADAF-ATTACK venv or uninstall the matching installer-owned environment.",
        "bash scripts/install-kali.sh --help",
    ),
    "UNSAFE_VENV": (
        "The installer refused an unsafe virtual environment path.",
        "Choose a dedicated project virtual environment under your home or project directory.",
        "bash scripts/install-kali.sh --help",
    ),
    "INVALID_UNINSTALL_OPTION": (
        "An uninstall-only installer option was used without --uninstall.",
        "Rerun with --uninstall, or remove the wipe option.",
        "bash scripts/install-kali.sh --help",
    ),
    "SUDO_REQUIRED": (
        "Installing Kali system packages requires sudo.",
        "Re-run with sudo for system deps, or pass --skip-system-deps when packages are already provisioned.",
        "bash scripts/install-kali.sh --help",
    ),
    "PYTHON_NOT_FOUND": (
        "The selected Python interpreter was not found on PATH.",
        "Install Python 3.11-3.14 or pass an absolute --python / -Python path.",
        "adaf-attack doctor --profile user-readiness --explain",
    ),
    "UNSUPPORTED_EXTRAS": (
        "The installer extras value is not supported.",
        "Choose base, tui, kerberos, reports, full, or the documented Certipy separate environment.",
        "bash scripts/install-kali.sh --help",
    ),
    "INSTALLER_ARGUMENT": (
        "The installer received an unknown or invalid argument.",
        "Run the installer --help / -? and retry with documented flags.",
        "bash scripts/install-kali.sh --help",
    ),
}


_ERROR_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "APPROVAL_TOKEN_EXPIRED",
        (
            "approval token has expired",
            "token expired",
            "approval expired",
            "exp claim",
            "not yet valid",
            "expiry is malformed",
        ),
    ),
    (
        "APPROVAL_TOKEN_INVALID",
        (
            "approval token signature is invalid",
            "invalid approval token",
            "approval token rejected",
            "token signature invalid",
            "approval token scope",
            "approval token does not permit",
            "approval token does not match",
            "approval token format",
            "scoped approval rejected",
        ),
    ),
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
        (
            "pass -p",
            "provide -p",
            "required -p",
            "username required",
            "requires --",
            "required input",
            "missing required",
            "required option",
            "required parameter",
        ),
    ),
    (
        "PYTHON_UNSUPPORTED",
        ("python 3.10", "unsupported python", "requires python 3.11"),
    ),
    (
        "VENV_REQUIRED",
        ("externally-managed-environment", "pep 668", "break-system-packages"),
    ),
    (
        "PROXY_TLS_FAILED",
        ("ssl: certificate_verify_failed", "certificate verify failed", "proxyerror"),
    ),
    (
        "EXTRA_MISSING",
        ("no module named 'textual'", "no module named 'reportlab'", "certipy is not installed"),
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
