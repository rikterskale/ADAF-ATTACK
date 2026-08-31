"""Target / engagement identity models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Target:
    """A single Active Directory target endpoint.

    Auth modes (first match wins for Kerberos-capable ops):
      1. use_kerberos / ccache  — ticket cache (KRB5CCNAME or explicit path)
      2. aes_key               — AES128/256 key for Kerberos
      3. hashes                — LM:NT or bare NT (pass-the-hash / Kerberos RC4)
      4. password              — cleartext password (NTLM or Kerberos)
      5. none                  — anonymous LDAP bind where allowed
    """

    domain: str
    dc_ip: str
    username: str | None = None
    password: str | None = None
    hashes: str | None = None  # LM:NT or just NT
    aes_key: str | None = None  # hex AES128 or AES256 key
    ccache: str | None = None  # path to ccache (or rely on KRB5CCNAME)
    use_kerberos: bool = False  # prefer Kerberos (-k style) when tickets present
    ldaps: bool = False
    starttls: bool = False
    port: int | None = None

    @property
    def auth_user(self) -> str | None:
        if not self.username:
            return None
        if "\\" in self.username or "@" in self.username:
            return self.username
        return f"{self.domain}\\{self.username}"

    @property
    def has_credentials(self) -> bool:
        return bool(
            self.password or self.hashes or self.aes_key or self.ccache or self.use_kerberos
        )

    def missing_fields(self, *, require_credentials: bool = False) -> list[str]:
        """Return fields an operator must supply before a requested operation.

        The model intentionally permits partial targets for offline planning
        and anonymous enumeration. Callers that are about to contact a live
        target can request credential validation without duplicating these
        checks in every capability.
        """
        missing: list[str] = []
        if not self.domain.strip():
            missing.append("domain")
        if not self.dc_ip.strip():
            missing.append("dc_ip")
        if require_credentials and not self.has_credentials:
            missing.append("credentials")
        return missing

    def validate(self, *, require_credentials: bool = False) -> None:
        """Raise a concise error when required target context is incomplete."""
        missing = self.missing_fields(require_credentials=require_credentials)
        if missing:
            raise ValueError("Target is missing: " + ", ".join(missing))

    def as_dict(self, *, include_secrets: bool = False) -> dict[str, object]:
        """Return operator context without exposing secrets by default."""
        result: dict[str, object] = {
            "domain": self.domain,
            "dc_ip": self.dc_ip,
            "username": self.username,
            "auth_user": self.auth_user,
            "use_kerberos": self.use_kerberos,
            "ldaps": self.ldaps,
            "port": self.port,
            "has_credentials": self.has_credentials,
        }
        if include_secrets:
            result.update(
                {
                    "password": self.password,
                    "hashes": self.hashes,
                    "aes_key": self.aes_key,
                    "ccache": self.ccache,
                }
            )
        return result

    def lm_nt_hashes(self) -> tuple[str, str]:
        """Return (lmhash, nthash) strings suitable for Impacket."""
        if not self.hashes:
            return "", ""
        parts = self.hashes.split(":")
        if len(parts) == 2:
            return parts[0], parts[1]
        return "", parts[0]

    def resolved_ccache(self) -> str | None:
        if self.ccache:
            return str(Path(self.ccache).expanduser())
        return None
