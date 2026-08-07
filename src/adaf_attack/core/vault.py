"""Session-scoped credential-material vault with redacted public metadata."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from cryptography.fernet import Fernet, InvalidToken

from adaf_attack.core.redaction import redact


class VaultError(RuntimeError):
    pass


@dataclass(frozen=True)
class VaultItem:
    name: str
    kind: str
    secret: bool
    metadata: dict[str, Any]


class SessionVault:
    """Store material by reference; secrets require an operator-supplied key."""

    def __init__(self, session_root: Path, key: str | None = None) -> None:
        self.root = session_root / "vault"
        self.root.mkdir(exist_ok=True)
        self.index_path = self.root / "index.json"
        self._key = key or os.environ.get("ADAF_SESSION_VAULT_KEY")

    def _index(self) -> dict[str, Any]:
        if not self.index_path.exists():
            return {"version": 1, "items": {}}
        loaded = json.loads(self.index_path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise VaultError("Vault index is malformed")
        return cast(dict[str, Any], loaded)

    def _save(self, index: dict[str, Any]) -> None:
        self.index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")

    def put(
        self,
        name: str,
        kind: str,
        value: Any,
        *,
        secret: bool,
        metadata: dict[str, Any] | None = None,
    ) -> VaultItem:
        if "/" in name or "\\" in name:
            raise VaultError("Vault item names cannot contain path separators")
        index = self._index()
        public = redact(metadata or {}, profile="operator")
        record = {"kind": kind, "secret": secret, "metadata": public}
        if secret:
            if not self._key:
                raise VaultError("Set ADAF_SESSION_VAULT_KEY before storing secret material")
            try:
                cipher = Fernet(self._key.encode())
            except Exception as exc:  # noqa: BLE001
                raise VaultError("ADAF_SESSION_VAULT_KEY must be a Fernet key") from exc
            payload = json.dumps(value, default=str).encode("utf-8")
            (self.root / f"{name}.vault").write_bytes(cipher.encrypt(payload))
            record["file"] = f"{name}.vault"
        else:
            record["value"] = value
        index["items"][name] = record
        self._save(index)
        return VaultItem(name, kind, secret, public)

    def get(self, name: str) -> Any:
        record = self._index().get("items", {}).get(name)
        if not record:
            raise VaultError(f"Vault item not found: {name}")
        if not record.get("secret"):
            return record.get("value")
        if not self._key:
            raise VaultError("Set ADAF_SESSION_VAULT_KEY before reading secret material")
        try:
            raw = Fernet(self._key.encode()).decrypt((self.root / record["file"]).read_bytes())
            return json.loads(raw)
        except (InvalidToken, OSError, json.JSONDecodeError) as exc:
            raise VaultError("Unable to decrypt vault item") from exc

    def list(self) -> list[VaultItem]:
        return [
            VaultItem(name, item["kind"], bool(item["secret"]), item.get("metadata") or {})
            for name, item in sorted(self._index().get("items", {}).items())
        ]
