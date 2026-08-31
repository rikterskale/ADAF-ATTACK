"""Capability registry and operator safety metadata.

Capabilities are registered at import time. The legacy ``destructive`` flag
is retained for compatibility, but new code should use :class:`SafetyProfile`.
The safety profile is authoritative for execution policy and is owned by the
capability registration rather than by engagement input.
"""

from __future__ import annotations

import importlib
import pkgutil
from builtins import list as builtin_list
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, cast

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class CapabilityRunner(Protocol):
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        include_secrets: bool = False,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]: ...


class RiskLevel(StrEnum):
    """Operator-visible risk class for a capability or operation."""

    OBSERVE = "observe"
    SENSITIVE = "sensitive"
    SIDE_EFFECT = "side_effect"
    DESTRUCTIVE = "destructive"


class ApprovalPolicy(StrEnum):
    """Approval required before the capability may execute."""

    NONE = "none"
    CONFIRM = "confirm"
    FORCE_AND_ACK = "force_and_ack"
    SCOPED_TOKEN = "scoped_token"


class RollbackClass(StrEnum):
    """How much cleanup the toolkit can guarantee after execution."""

    NONE = "none"
    MANUAL = "manual"
    AUTOMATIC = "automatic"


@dataclass(frozen=True)
class SafetyProfile:
    """Machine-readable safety contract for one capability.

    ``destructive`` is not synonymous with dangerous. For example,
    authentication coercion may not mutate LDAP state but still causes a
    network side effect and may expose credentials.
    """

    risk: RiskLevel = RiskLevel.OBSERVE
    approval: ApprovalPolicy = ApprovalPolicy.NONE
    rollback: RollbackClass = RollbackClass.NONE
    network_side_effect: bool = False
    modifies_directory: bool = False
    exposes_credentials: bool = False
    requires_target_scope: bool = True

    @property
    def requires_force(self) -> bool:
        return self.approval in {
            ApprovalPolicy.FORCE_AND_ACK,
            ApprovalPolicy.SCOPED_TOKEN,
        }

    @property
    def requires_ack(self) -> bool:
        return self.approval == ApprovalPolicy.FORCE_AND_ACK

    @property
    def is_mutating(self) -> bool:
        # A network side effect is not necessarily an LDAP mutation, but it
        # still cannot be safely retried or abandoned while the worker runs.
        return (
            self.modifies_directory
            or self.network_side_effect
            or self.risk == RiskLevel.DESTRUCTIVE
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "risk": self.risk.value,
            "approval": self.approval.value,
            "rollback": self.rollback.value,
            "network_side_effect": self.network_side_effect,
            "modifies_directory": self.modifies_directory,
            "exposes_credentials": self.exposes_credentials,
            "requires_target_scope": self.requires_target_scope,
            "requires_force": self.requires_force,
            "requires_ack": self.requires_ack,
        }


def default_safety_profile(destructive: bool) -> SafetyProfile:
    """Convert legacy registrations to an explicit safety profile."""
    if destructive:
        return SafetyProfile(
            risk=RiskLevel.DESTRUCTIVE,
            approval=ApprovalPolicy.FORCE_AND_ACK,
            rollback=RollbackClass.MANUAL,
            network_side_effect=True,
            modifies_directory=True,
        )
    return SafetyProfile()


KNOWN_ENVIRONMENTS = frozenset({"offline", "live-read-only", "live-mutating"})
_OFFLINE_CATEGORIES = frozenset({"analysis", "export"})


def infer_environment(
    *,
    environment: str = "unknown",
    destructive: bool = False,
    category: str = "general",
    tags: tuple[str, ...] = (),
    safety: SafetyProfile | None = None,
) -> str:
    """Resolve operator-facing environment when registration omits it.

    ``unknown`` is not a catalog value. Infer from safety and category so the
    generated capability catalog never ships blank Environment cells.
    """
    if environment in KNOWN_ENVIRONMENTS:
        return environment
    if destructive or (
        safety is not None
        and (
            safety.modifies_directory
            or safety.network_side_effect
            or safety.requires_force
            or safety.risk in {RiskLevel.DESTRUCTIVE, RiskLevel.SIDE_EFFECT}
        )
    ):
        return "live-mutating"
    if category in _OFFLINE_CATEGORIES or "vault" in tags:
        return "offline"
    return "live-read-only"


@dataclass(frozen=True)
class Capability:
    id: str
    summary: str
    destructive: bool = False
    category: str = "general"
    tags: tuple[str, ...] = field(default_factory=tuple)
    maturity: str = "implemented"
    environment: str = "unknown"
    tools: tuple[str, ...] = field(default_factory=tuple)
    fixture: str | None = None
    runner: CapabilityRunner | None = None
    safety: SafetyProfile | None = None
    auth_modes: tuple[str, ...] = field(default_factory=tuple)
    requires_username_list: bool = False
    active_authentication: bool = False
    noise_level: str = "unspecified"
    data_sensitivity: str = "metadata"

    def __post_init__(self) -> None:
        if self.safety is None:
            object.__setattr__(self, "safety", default_safety_profile(self.destructive))
        elif self.safety.risk == RiskLevel.DESTRUCTIVE and not self.destructive:
            # Keep legacy callers and downstream documentation in sync with
            # explicit profiles. The profile remains the source of truth.
            object.__setattr__(self, "destructive", True)
        resolved = infer_environment(
            environment=self.environment,
            destructive=self.destructive,
            category=self.category,
            tags=self.tags,
            safety=self.safety,
        )
        if resolved != self.environment:
            object.__setattr__(self, "environment", resolved)

    @property
    def requires_force(self) -> bool:
        return bool(self.safety and self.safety.requires_force)

    @property
    def requires_ack(self) -> bool:
        return bool(self.safety and self.safety.requires_ack)


class CapabilityRegistry:
    def __init__(self) -> None:
        self._capabilities: dict[str, Capability] = {}

    def register(self, cap: Capability) -> None:
        if cap.id in self._capabilities:
            raise ValueError(f"Capability already registered: {cap.id}")
        self._capabilities[cap.id] = cap

    def get(self, capability_id: str) -> Capability | None:
        return self._capabilities.get(capability_id)

    def list(self) -> list[Capability]:
        return sorted(self._capabilities.values(), key=lambda c: c.id)

    def ids(self) -> builtin_list[str]:
        return sorted(self._capabilities.keys())


capability_registry = CapabilityRegistry()


def load_builtin_capabilities() -> None:
    """Import built-in capability modules so their decorators can register them."""
    importlib.import_module("adaf_attack.capabilities")


def register_capability(
    id: str,  # noqa: A002  # stable decorator keyword used by third-party capabilities
    summary: str,
    *,
    destructive: bool = False,
    safety: SafetyProfile | None = None,
    category: str = "general",
    tags: tuple[str, ...] = (),
    maturity: str = "implemented",
    environment: str = "unknown",
    tools: tuple[str, ...] = (),
    fixture: str | None = None,
    auth_modes: tuple[str, ...] = (),
    requires_username_list: bool = False,
    active_authentication: bool = False,
    noise_level: str = "unspecified",
    data_sensitivity: str = "metadata",
) -> Callable[[type], type]:
    """Decorator that registers a capability class implementing .run()."""

    def decorator(cls: type) -> type:
        instance = cls()
        runner = cast(CapabilityRunner, instance) if hasattr(instance, "run") else None
        profile = safety or default_safety_profile(destructive)
        _ensure_capability_documentation(cls, summary, profile)
        capability_registry.register(
            Capability(
                id=id,
                summary=summary,
                destructive=destructive,
                safety=profile,
                category=category,
                tags=tags,
                maturity=maturity,
                environment=environment,
                tools=tools,
                fixture=fixture,
                runner=runner,
                auth_modes=auth_modes,
                requires_username_list=requires_username_list,
                active_authentication=active_authentication,
                noise_level=noise_level,
                data_sensitivity=data_sensitivity,
            )
        )
        return cls

    return decorator


def _ensure_capability_documentation(cls: type, summary: str, safety: SafetyProfile) -> None:
    """Give every registered runner a discoverable operator contract.

    Capabilities are intentionally lightweight classes and historically many
    omitted method docstrings.  Registration is the one place that knows the
    safety and persistence contract, so it supplies a stable baseline while
    preserving any detailed author-written documentation.
    """
    if not cls.__doc__:
        cls.__doc__ = f"{summary}."
    run_method = getattr(cls, "run", None)
    if run_method is None or run_method.__doc__:
        return
    rollback = safety.rollback.value
    mutation = (
        "may contact or modify the authorized target" if safety.is_mutating else "is read-only"
    )
    run_method.__doc__ = (
        f"{summary}.\n\n"
        "Parameters: ``target: Target``, ``session: Session``, ``graph: AttackGraph``, "
        "``include_secrets: bool``, ``force: bool``, and capability-specific ``**kwargs: Any`` "
        "from repeated ``-P key=value`` options.\n\n"
        f"The runner writes its capability result and event log under the session workspace; "
        f"it {mutation}. Rollback coverage is ``{rollback}`` and is recorded by the capability "
        "when applicable."
    )


def registration_gaps() -> dict[str, list[str]]:
    """Report capability modules that are not represented in the registry.

    This is intentionally a diagnostic helper rather than an import-time
    assertion: third-party entry points may be unavailable in an offline
    installation, while built-in module drift should remain test-visible.
    """
    package = importlib.import_module("adaf_attack.capabilities")
    module_names = {
        info.name
        for info in pkgutil.iter_modules(package.__path__)
        if info.name not in {"__init__", "capability_catalog"}
    }
    registered_modules = {
        cap.runner.__class__.__module__.rsplit(".", 1)[-1]
        for cap in capability_registry.list()
        if cap.runner is not None
    }
    return {
        "unregistered_modules": sorted(module_names - registered_modules),
        "orphaned_registry_modules": sorted(registered_modules - module_names),
    }
