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
            self.password
            or self.hashes
            or self.aes_key
            or self.ccache
            or self.use_kerberos
        )

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
