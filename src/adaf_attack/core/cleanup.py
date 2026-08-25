"""Execute recorded, force-gated session rollbacks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ldap3 import MODIFY_DELETE, MODIFY_REPLACE

from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.rollback import classification_for_kind
from adaf_attack.core.target import Target


def _session_artifact(session: Path, value: Any) -> Path:
    """Resolve a recorded artifact without permitting access outside session."""
    root = session.resolve()
    artifact = Path(str(value or "")).expanduser()
    candidate = artifact if artifact.is_absolute() else session / artifact
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("Rollback artifact must remain inside the session") from exc
    return resolved


def execute_cleanup(session: Path, target: Target) -> dict[str, Any]:
    """Apply pending LDAP-backed cleanup actions in a recorded session."""
    path = session / "cleanup.json"
    entries = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []
    advisory = 0
    unsupported = 0
    conn, _base, _cfg = ldap_connect(target)
    try:
        for item in entries:
            if item.get("status") != "pending":
                continue
            kind = item.get("kind")
            classification = classification_for_kind(str(kind or ""))
            item.setdefault("classification", classification)
            if classification == "advisory":
                item["result"] = "Manual review required; no automatic rollback handler"
                advisory += 1
                continue
            if classification == "unsupported":
                item["result"] = "Unsupported cleanup kind; manual review required"
                unsupported += 1
                continue
            if kind == "computer-identity":
                ok = conn.modify(
                    item["target"],
                    {item["attribute"]: [(MODIFY_REPLACE, item.get("previous", []))]},
                )
            elif kind in {"shadow-credential", "keycred-write", "shadow-creds"}:
                artifact = _session_artifact(session, item["artifact"])
                value = artifact.read_text(encoding="utf-8").strip()
                ok = conn.modify(
                    item["target"],
                    {"msDS-KeyCredentialLink": [(MODIFY_DELETE, [value])]},
                )
            elif kind == "rbcd":
                previous = [bytes.fromhex(value) for value in item.get("previous", [])]
                ok = conn.modify(
                    item["target"],
                    {"msDS-AllowedToActOnBehalfOfOtherIdentity": [(MODIFY_REPLACE, previous)]},
                )
            elif kind == "acl":
                previous_bytes = bytes.fromhex(item["previous_hex"])
                ok = conn.modify(
                    item["target"],
                    {"nTSecurityDescriptor": [(MODIFY_REPLACE, [previous_bytes])]},
                )
            elif kind == "gpo-link":
                ok = conn.modify(
                    item["target"],
                    {"gPLink": [(MODIFY_REPLACE, [item.get("previous", "")])]},
                )
            elif kind == "template-mod":
                artifact = _session_artifact(session, item.get("artifact"))
                if not artifact.is_file():
                    item["status"] = "failed"
                    item["result"] = "Missing template-mod rollback artifact"
                    continue
                payload = json.loads(artifact.read_text(encoding="utf-8"))
                attrs = payload.get("attrs") or {}
                changes = {
                    key: [(MODIFY_REPLACE, value if isinstance(value, list) else [value])]
                    for key, value in attrs.items()
                }
                ok = conn.modify(item["target"], changes) if changes else False
            elif kind == "ldap-attribute":
                previous = list(item.get("previous") or [])
                if item.get("encoding") == "hex":
                    previous = [
                        bytes.fromhex(value) if isinstance(value, str) else value
                        for value in previous
                    ]
                ok = conn.modify(
                    item["target"],
                    {item["attribute"]: [(MODIFY_REPLACE, previous)]},
                )
            elif kind == "ldap-add-value":
                values = list(item.get("values") or [])
                if item.get("value") is not None and not values:
                    values = [item["value"]]
                if item.get("encoding") == "hex":
                    values = [
                        bytes.fromhex(value) if isinstance(value, str) else value
                        for value in values
                    ]
                ok = conn.modify(
                    item["target"],
                    {item["attribute"]: [(MODIFY_DELETE, values)]},
                )
            elif kind == "ldap-object":
                ok = bool(conn.delete(item["target"]))
            elif kind == "gpo-sysvol":
                relative_path = str(item.get("target", "")).replace("/", "\\")
                normalized_path = relative_path.lower()
                if (
                    not relative_path
                    or ".." in relative_path.split("\\")
                    or "\\policies\\" not in normalized_path
                    or "\\machine\\" not in normalized_path
                ):
                    item["status"] = "failed"
                    item["result"] = "Refusing invalid staged SYSVOL cleanup path"
                    continue
                from adaf_attack.capabilities.gpo_sysvol import _smb_connect

                smb = _smb_connect(target, str(item.get("host") or target.dc_ip))
                try:
                    smb.deleteFile("SYSVOL", relative_path)
                    ok = True
                finally:
                    smb.logoff()
            elif kind == "local-artifact":
                artifact = _session_artifact(session, item.get("artifact"))
                if not artifact.is_file():
                    item["status"] = "failed"
                    item["result"] = "Missing local rollback artifact"
                    continue
                artifact.unlink()
                ok = True
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
        "advisory": advisory,
        "unsupported": unsupported,
    }
