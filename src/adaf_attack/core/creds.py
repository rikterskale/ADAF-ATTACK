"""Multi-credential store and rotation helpers."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

from adaf_attack.core.target import Target


@dataclass
class Credential:
    """One set of domain credentials."""

    username: str
    domain: str | None = None
    password: str | None = None
    hashes: str | None = None
    aes_key: str | None = None
    ccache: str | None = None
    use_kerberos: bool = False
    label: str | None = None
    tags: list[str] = field(default_factory=list)

    def has_secrets(self) -> bool:
        return bool(self.password or self.hashes or self.aes_key or self.ccache or self.use_kerberos)

    def to_target(self, dc_ip: str, domain: str | None = None, *, ldaps: bool = False) -> Target:
        return Target(
            domain=(domain or self.domain or "").strip(),
            dc_ip=dc_ip,
            username=self.username,
            password=self.password,
            hashes=self.hashes,
            aes_key=self.aes_key,
            ccache=self.ccache,
            use_kerberos=self.use_kerberos,
            ldaps=ldaps,
        )


@dataclass
class CredentialSet:
    """Ordered multi-credential bag for rotation / failover."""

    credentials: list[Credential] = field(default_factory=list)
    source: str | None = None

    def __len__(self) -> int:
        return len(self.credentials)

    def __iter__(self) -> Iterator[Credential]:
        return iter(self.credentials)

    def labels(self) -> list[str]:
        return [c.label or c.username for c in self.credentials]

    def by_label(self, label: str) -> Credential | None:
        for c in self.credentials:
            if (c.label or c.username) == label:
                return c
        return None

    def rotate(self, start: int = 0) -> Iterator[Credential]:
        """Yield credentials starting at index, wrapping once through the set."""
        n = len(self.credentials)
        if n == 0:
            return
        for i in range(n):
            yield self.credentials[(start + i) % n]

    def to_targets(
        self,
        dc_ip: str,
        domain: str | None = None,
        *,
        ldaps: bool = False,
    ) -> list[Target]:
        return [c.to_target(dc_ip, domain=domain or c.domain, ldaps=ldaps) for c in self.credentials]

    def dump_redacted(self) -> list[dict[str, Any]]:
        out = []
        for c in self.credentials:
            d = asdict(c)
            if d.get("password"):
                d["password"] = "***"
            if d.get("hashes"):
                d["hashes"] = "***"
            if d.get("aes_key"):
                d["aes_key"] = "***"
            out.append(d)
        return out


def load_credentials_json(path: str | Path) -> CredentialSet:
    """Load credentials from a JSON file.

    Accepted shapes:
      {"credentials": [ {...}, ... ]}
      [ {...}, ... ]

    Each entry: username (required), domain?, password?, hashes?, aes_key?,
    ccache?, use_kerberos?, label?, tags?
    """
    p = Path(path).expanduser()
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        items = data.get("credentials") or data.get("creds") or []
    elif isinstance(data, list):
        items = data
    else:
        raise ValueError(f"Unsupported credentials JSON shape in {p}")

    creds: list[Credential] = []
    for raw in items:
        if not isinstance(raw, dict) or not raw.get("username"):
            continue
        creds.append(
            Credential(
                username=str(raw["username"]),
                domain=raw.get("domain"),
                password=raw.get("password"),
                hashes=raw.get("hashes"),
                aes_key=raw.get("aes_key"),
                ccache=raw.get("ccache"),
                use_kerberos=bool(raw.get("use_kerberos", False)),
                label=raw.get("label"),
                tags=list(raw.get("tags") or []),
            )
        )
    return CredentialSet(credentials=creds, source=str(p))


def first_working_target(
    cred_set: CredentialSet,
    dc_ip: str,
    domain: str,
    *,
    ldaps: bool = False,
    probe: Any = None,
) -> Target | None:
    """Try each credential; optional probe(target) -> bool selects first success.

    Without probe, returns the first credential that has secrets.
    """
    for cred in cred_set:
        if not cred.has_secrets() and not probe:
            continue
        t = cred.to_target(dc_ip, domain=domain or cred.domain, ldaps=ldaps)
        if probe is None:
            return t
        try:
            if probe(t):
                return t
        except Exception:  # noqa: BLE001
            continue
    return None
