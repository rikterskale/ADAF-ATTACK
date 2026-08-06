"""Execute recorded, force-gated session rollbacks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ldap3 import MODIFY_DELETE, MODIFY_REPLACE

from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.target import Target


def execute_cleanup(session: Path, target: Target) -> dict[str, Any]:
    """Apply pending LDAP-backed cleanup actions in a recorded session."""
    path = session / "cleanup.json"
    entries = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []
    conn, _base, _cfg = ldap_connect(target)
    try:
        for item in entries:
            if item.get("status") != "pending":
                continue
            if item.get("kind") == "computer-identity":
                ok = conn.modify(
                    item["target"],
                    {item["attribute"]: [(MODIFY_REPLACE, item.get("previous", []))]},
                )
            elif item.get("kind") == "shadow-credential":
                artifact = Path(str(item["artifact"]))
                value = artifact.read_text(encoding="utf-8").strip()
                ok = conn.modify(
                    item["target"],
                    {"msDS-KeyCredentialLink": [(MODIFY_DELETE, [value])]},
                )
            elif item.get("kind") == "rbcd":
                previous = [bytes.fromhex(value) for value in item.get("previous", [])]
                ok = conn.modify(
                    item["target"],
                    {
                        "msDS-AllowedToActOnBehalfOfOtherIdentity": [
                            (MODIFY_REPLACE, previous)
                        ]
                    },
                )
            elif item.get("kind") == "acl":
                previous = bytes.fromhex(item["previous_hex"])
                ok = conn.modify(
                    item["target"],
                    {"nTSecurityDescriptor": [(MODIFY_REPLACE, [previous])]},
                )
            elif item.get("kind") == "gpo-link":
                ok = conn.modify(
                    item["target"],
                    {"gPLink": [(MODIFY_REPLACE, [item.get("previous", "")])]},
                )
            else:
                continue
            item["status"] = "completed" if ok else "failed"
            item["result"] = str(conn.result)
    finally:
        conn.unbind()

    path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return {
        "entries": entries,
        "completed": sum(item.get("status") == "completed" for item in entries),
    }
