"""Target / connection context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Target:
    """Connection parameters for an AD target."""

    domain: str
    dc_ip: str
    username: Optional[str] = None
    password: Optional[str] = None
    hashes: Optional[str] = None  # LM:NT or just NT
    ldaps: bool = False
    port: Optional[int] = None

    @property
    def auth_user(self) -> str | None:
        if not self.username:
            return None
        if "\\" in self.username or "@" in self.username:
            return self.username
        return f"{self.domain}\\{self.username}"

    @property
    def ldap_server(self) -> str:
        scheme = "ldaps" if self.ldaps else "ldap"
        port = self.port or (636 if self.ldaps else 389)
        return f"{scheme}://{self.dc_ip}:{port}"
