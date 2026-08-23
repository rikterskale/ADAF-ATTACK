"""Coercion surface map — detect Spooler / EFSRPC / related listeners (no coerce by default)."""

from __future__ import annotations

import json
import socket
from typing import Any

from ldap3 import SUBTREE
from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

# Named pipes / ports commonly associated with coercion
# Detect-only: TCP connect / SMB pipe peek style checks where possible
SPOOLER_PIPE = r"\pipe\spoolss"
EFSRPC_PIPE = r"\pipe\efsrpc"  # also lsarpc used by PetitPotam variants


def _tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _smb_pipe_check(host: str, target: Target) -> dict[str, Any]:
    """Best-effort pipe availability via Impacket SMB if present."""
    out: dict[str, Any] = {"spooler": None, "efsrpc": None, "method": None}
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        out["method"] = "tcp-only"
        return out

    out["method"] = "impacket-smb"
    lm, nt = target.lm_nt_hashes()
    try:
        smb = SMBConnection(host, host, timeout=3)
        if target.hashes:
            smb.login(
                target.username or "", target.password or "", target.domain, lmhash=lm, nthash=nt
            )
        elif target.username and target.password:
            smb.login(target.username, target.password, target.domain)
        else:
            try:
                smb.login("", "")  # null
            except Exception:
                out["error"] = "SMB login failed"
                return out

        # list paths / try open pipe
        for name, pipe in ("spooler", "spoolss"), ("efsrpc", "efsrpc"):
            try:
                tid = smb.connectTree("IPC$")
                fid = smb.openFile(tid, pipe)
                smb.closeFile(tid, fid)
                out[name] = True
            except Exception:
                out[name] = False
        smb.logoff()
    except Exception as exc:
        out["error"] = str(exc)
    return out


@register_capability(
    id="coercion-map",
    summary="Map coercion surfaces (Spooler/EFSRPC) on domain computers — detect only",
    category="discovery",
    tags=("coercion", "petitpotam", "printerbug", "spooler", "efsrpc"),
)
class CoercionMap:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        include_secrets: bool = False,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        max_hosts = int(kwargs.get("max_hosts") or kwargs.get("max_objects") or 50)
        console.print(
            f"[bold]Coercion map[/bold] → {target.domain}  (detect only, max_hosts={max_hosts})"
        )

        conn, base_dn, _cfg = ldap_connect(target)
        conn.search(
            base_dn,
            "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "dNSHostName", "distinguishedName"],
            size_limit=max_hosts,
        )

        hosts: list[dict[str, Any]] = []
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            dns = str(entry.dNSHostName) if entry.dNSHostName else None
            if not sam:
                continue
            host = dns or sam.rstrip("$")
            hosts.append({"sam": sam, "dns": dns, "host": host})
        conn.unbind()

        findings = []
        spooler_open = 0
        efsrpc_open = 0

        for h in hosts:
            host = h["host"]
            row: dict[str, Any] = {"sam": h["sam"], "host": host, "tcp_445": _tcp_open(host, 445)}
            if row["tcp_445"] and target.has_credentials:
                pipes = _smb_pipe_check(host, target)
                row.update(pipes)
            elif row["tcp_445"]:
                row["spooler"] = None
                row["efsrpc"] = None
                row["method"] = "tcp-445-open-no-creds"
            else:
                row["spooler"] = False
                row["efsrpc"] = False
                row["method"] = "tcp-445-closed"

            if row.get("spooler") is True:
                spooler_open += 1
                node = f"COMPUTER@{h['sam'].upper()}@{target.domain.upper()}"
                graph.add_node(node, "Computer", sam=h["sam"], spooler=True)
                graph.add_edge(node, node, "SpoolerOpen")
            if row.get("efsrpc") is True:
                efsrpc_open += 1
                node = f"COMPUTER@{h['sam'].upper()}@{target.domain.upper()}"
                graph.add_node(node, "Computer", sam=h["sam"], efsrpc=True)
                graph.add_edge(node, node, "EfsrpcOpen")

            findings.append(row)
            mark = []
            if row.get("spooler"):
                mark.append("SPOOLER")
            if row.get("efsrpc"):
                mark.append("EFSRPC")
            tag = ",".join(mark) if mark else row.get("method")
            console.print(f"  {host}  445={row['tcp_445']}  {tag}")

        result = {
            "domain": target.domain,
            "hosts_checked": len(findings),
            "spooler_open": spooler_open,
            "efsrpc_open": efsrpc_open,
            "hosts": findings,
            "note": "Detect only — no coercion authentication traffic was sent.",
        }
        out_path = session.path("coercion-map.json")
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "coercion-map.complete",
            hosts=len(findings),
            spooler=spooler_open,
            efsrpc=efsrpc_open,
        )
        console.print(
            f"[green]Done[/green]  hosts={len(findings)}  "
            f"spooler={spooler_open}  efsrpc={efsrpc_open}"
        )
        console.print(f"Results → {out_path}")
        return result
