"""Capability registry.

Capabilities are registered at import time. There are no lab_certified or
containment gates — only a lightweight `destructive` flag that requires
`--force` at execution time.
"""

from __future__ import annotations

from builtins import list as builtin_list
from collections.abc import Callable
from dataclasses import dataclass, field
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


@dataclass(frozen=True)
class Capability:
    id: str
    summary: str
    destructive: bool = False
    category: str = "general"
    tags: tuple[str, ...] = field(default_factory=tuple)
    runner: CapabilityRunner | None = None


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


def register_capability(
    id: str,
    summary: str,
    *,
    destructive: bool = False,
    category: str = "general",
    tags: tuple[str, ...] = (),
) -> Callable[[type], type]:
    """Decorator that registers a capability class implementing .run()."""

    def decorator(cls: type) -> type:
        instance = cls()
        runner = cast(CapabilityRunner, instance) if hasattr(instance, "run") else None
        capability_registry.register(
            Capability(
                id=id,
                summary=summary,
                destructive=destructive,
                category=category,
                tags=tags,
                runner=runner,
            )
        )
        return cls

    return decorator
