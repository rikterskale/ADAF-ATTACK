"""Central execution-policy checks shared by every operator interface."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adaf_attack.core.registry import (
    ApprovalPolicy,
    Capability,
    RiskLevel,
    RollbackClass,
    SafetyProfile,
    default_safety_profile,
)
from adaf_attack.core.target import Target


class PolicyError(RuntimeError):
    """Raised when an execution request does not satisfy its safety profile."""


@dataclass(frozen=True)
class ExecutionRequest:
    capability: Capability
    target: Target
    safety: SafetyProfile | None = None
    force: bool = False
    acknowledged: bool = True
    approval_token: str | None = None


def enforce_execution_policy(request: ExecutionRequest) -> None:
    """Enforce capability-owned approval requirements.

    Interactive first-use acknowledgement is normally handled by the CLI/TUI
    and represented by ``acknowledged``. Library callers must still provide
    the explicit force flag for every profile that requires it.
    """
    safety = request.safety or request.capability.safety
    if safety is None:  # Defensive for third-party Capability implementations.
        raise PolicyError(f"Capability '{request.capability.id}' has no safety profile")
    if safety.requires_force and not request.force:
        label = "DESTRUCTIVE" if safety.risk.value == "destructive" else "approved side-effect"
        raise PolicyError(
            f"Capability '{request.capability.id}' is {label} and requires explicit authorization via --force."
        )
    if safety.requires_ack and not request.acknowledged:
        raise PolicyError(
            f"Capability '{request.capability.id}' requires an operator acknowledgement."
        )
    if safety.approval.value == "scoped_token" and not request.approval_token:
        raise PolicyError(f"Capability '{request.capability.id}' requires a scoped approval token.")


def safety_for_operation(capability: Capability, parameters: dict[str, Any]) -> SafetyProfile:
    """Return an operation-specific profile for mixed read/write capabilities.

    Capability modules can extend this function when a single runner exposes
    both observation and mutation operations. The registry profile remains the
    fail-closed fallback.
    """
    profile = capability.safety
    if profile is None:  # pragma: no cover - Capability normalizes this in __post_init__.
        raise PolicyError(f"Capability '{capability.id}' has no safety profile")
    operation = str(parameters.get("operation", "")).strip().lower()
    if capability.id in {"credential-inventory", "shadow-creds", "gpo-sysvol", "rbcd"}:
        write_requested = bool(
            parameters.get("write_target")
            or parameters.get("set_on")
            or parameters.get("set_from")
            or parameters.get("payload")
            or parameters.get("gpo")
            or parameters.get("cn")
            or operation in {"purge", "delete", "clear", "write", "set", "stage"}
            or parameters.get("_force")
        )
        read_operations = {
            "",
            "enum",
            "enumerate",
            "read",
            "list",
            "inspect",
            "search",
            "inventory",
            "export",
            "mark",
        }
        if write_requested:
            return default_safety_profile(True)
        if operation in read_operations:
            return SafetyProfile(
                risk=RiskLevel.OBSERVE,
                approval=ApprovalPolicy.NONE,
                rollback=RollbackClass.NONE,
                network_side_effect=profile.network_side_effect,
                modifies_directory=False,
                exposes_credentials=profile.exposes_credentials,
                requires_target_scope=profile.requires_target_scope,
            )
    return profile
