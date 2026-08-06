"""Execute recorded, force-gated session rollbacks."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from ldap3 import MODIFY_REPLACE
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.target import Target

def execute_cleanup(session: Path, target: Target) -> dict[str, Any]:
    path = session / "cleanup.json"
    entries = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []
    conn, _base, _cfg = ldap_connect(target)
    for item in entries:
        if item.get("status") != "pending" or item.get("kind") != "computer-identity": continue
        ok = conn.modify(item["target"], {item["attribute"]: [(MODIFY_REPLACE, item.get("previous", []))]})
        item["status"] = "completed" if ok else "failed"; item["result"] = str(conn.result)
    conn.unbind(); path.write_text(json.dumps(entries, indent=2)+"\n", encoding="utf-8")
    return {"entries": entries, "completed": sum(x.get("status")=="completed" for x in entries)}
