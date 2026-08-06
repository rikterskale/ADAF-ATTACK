"""Target / engagement identity models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Target:
    """A single Active Directory target endpoint."""

    domain: str
    dc_ip: str
    username: str | None = None
    password: str | None = None
    hashes: str | None = None  # LM:NT or just NT
    ldaps: bool = False
    port: int | None = None

    @property
    def auth_user(self) -> str | None:
        if not self.username:
            return None
        if "\\" in self.username or "@" in self.username:
            return self.username
        return f"{self.domain}\\{self.username}"
