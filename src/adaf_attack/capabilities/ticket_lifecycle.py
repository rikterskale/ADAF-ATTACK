"""Offline ticket and certificate artifact lifecycle helpers."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from adaf_attack.capabilities.pkinit_auth import _pfx_from_pem
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


@register_capability(
    id="ticket-lifecycle",
    summary="Inventory or import ticket/certificate artifacts into the session vault",
    category="credential-access",
    tags=("ccache", "pfx", "pem", "vault"),
)
class TicketLifecycle:
    def run(
        self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any
    ) -> dict[str, Any]:
        operation = str(kwargs.get("operation") or "inventory")
        artifact = kwargs.get("artifact")
        vault = session.vault()
        if operation == "inventory":
            files = [p.name for p in sorted(session.root.glob("*.ccache"))]
            files += [p.name for p in sorted(session.root.glob("*.pfx"))]
            return {
                "operation": operation,
                "artifacts": files,
                "vault": [item.name for item in vault.list()],
            }
        if operation == "import-ccache":
            source = Path(str(artifact or ""))
            if not source.is_file():
                raise RuntimeError("artifact must name an existing ccache file")
            destination = session.path(f"imported-{source.name}")
            shutil.copy2(source, destination)
            vault.put(
                "tgt",
                "ccache",
                {"path": str(destination)},
                secret=True,
                metadata={"source": source.name},
            )
            session.log("ticket-lifecycle.import", kind="ccache", path=str(destination))
            return {"operation": operation, "ccache": str(destination), "vault_item": "tgt"}
        if operation == "import-pfx":
            source = Path(str(artifact or ""))
            if not source.is_file():
                raise RuntimeError("artifact must name an existing PFX file")
            destination = session.path(f"imported-{source.name}")
            shutil.copy2(source, destination)
            vault.put(
                "certificate",
                "pfx",
                {"path": str(destination)},
                secret=True,
                metadata={"source": source.name},
            )
            session.log("ticket-lifecycle.import", kind="pfx", path=str(destination))
            return {"operation": operation, "pfx": str(destination), "vault_item": "certificate"}
        if operation == "pem-to-pfx":
            if not artifact or "," not in str(artifact):
                raise RuntimeError("artifact must be '<key.pem>,<cert.pem>'")
            key_name, cert_name = str(artifact).split(",", 1)
            pem_key_path, pem_cert_path = Path(key_name), Path(cert_name)
            if not pem_key_path.is_file() or not pem_cert_path.is_file():
                raise RuntimeError("key or certificate file not found")
            destination = session.path("converted.pfx")
            destination.write_bytes(
                _pfx_from_pem(pem_key_path.read_bytes(), pem_cert_path.read_bytes())
            )
            vault.put(
                "certificate",
                "pfx",
                {"path": str(destination)},
                secret=True,
                metadata={"converted_from": [key.name, cert.name]},
            )
            return {"operation": operation, "pfx": str(destination), "vault_item": "certificate"}
        if operation == "export-ccache":
            value = vault.get("tgt")
            source = Path(str(value.get("path") or ""))
            if not source.is_file():
                raise RuntimeError("Vault TGT does not reference an available ccache")
            destination = session.path("exported.ccache")
            shutil.copy2(source, destination)
            return {"operation": operation, "ccache": str(destination)}
        if operation == "export-pfx":
            value = vault.get("certificate")
            source = Path(str(value.get("path") or ""))
            if not source.is_file():
                raise RuntimeError("Vault certificate does not reference an available PFX")
            destination = session.path("exported.pfx")
            shutil.copy2(source, destination)
            return {"operation": operation, "pfx": str(destination)}
        if operation == "pfx-to-pem":
            source = Path(str(artifact or ""))
            if not source.is_file():
                raise RuntimeError("artifact must name an existing PFX file")
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                NoEncryption,
                PrivateFormat,
                pkcs12,
            )

            private_key, certificate, _cas = pkcs12.load_key_and_certificates(
                source.read_bytes(), None
            )
            if private_key is None or certificate is None:
                raise RuntimeError("PFX does not contain both a private key and certificate")
            key_path, cert_path = (
                session.path("converted.key.pem"),
                session.path("converted.cert.pem"),
            )
            key_path.write_bytes(
                private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )
            cert_path.write_bytes(certificate.public_bytes(Encoding.PEM))
            return {"operation": operation, "key": str(key_path), "cert": str(cert_path)}
        raise RuntimeError(f"Unsupported operation: {operation}")
