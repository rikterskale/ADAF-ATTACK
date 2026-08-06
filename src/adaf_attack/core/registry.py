"""Capability registry.

Capabilities are registered at import time. There are no lab_certified or
containment gates — only a lightweight `destructive` flag that requires
`--force` at execution time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class Capability:
    id: str
    summary: str
    destructive: bool = False
    category: str = "general"
    # Future: entrypoint callable, required tools, etc.
    tags: tuple[str, ...] = field(default_factory=tuple)


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

    def ids(self) -> list[str]:
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
    """Decorator helper for future capability classes."""

    def decorator(cls: type) -> type:
        capability_registry.register(
            Capability(
                id=id,
                summary=summary,
                destructive=destructive,
                category=category,
                tags=tags,
            )
        )
        return cls

    return decorator
