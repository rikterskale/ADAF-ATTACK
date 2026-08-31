"""Credential-free, read-only network and directory posture capabilities."""

from __future__ import annotations

import json
import socket
from typing import Any

from ldap3 import ALL, BASE, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPException

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

_POSTURE_PORTS = {
    53: "dns",
    88: "kerberos",
    135: "rpc",
    389: "ldap",
    443: "https",
    445: "smb",
    636: "ldaps",
}


def _tcp_probe(host: str, port: int, timeout: float) -> dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"port": port, "service": _POSTURE_PORTS[port], "reachable": True}
    except (OSError, TimeoutError) as exc:
        return {
            "port": port,
            "service": _POSTURE_PORTS[port],
            "reachable": False,
            "error": type(exc).__name__,
        }


@register_capability(
    id="passive-discovery",
    summary="Probe common AD service endpoints without credentials or authentication",
    category="enumeration",
    tags=("unauthenticated", "network", "posture"),
    environment="live-read-only",
    auth_modes=("anonymous",),
    noise_level="low",
    data_sensitivity="endpoint-metadata",
)
class PassiveDiscovery:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        **kwargs: Any,
    ) -> dict[str, Any]:
        timeout = max(0.1, min(float(kwargs.get("timeout") or 1.5), 10.0))
        ports = kwargs.get("ports")
        selected = [int(item) for item in str(ports).split(",")] if ports else list(_POSTURE_PORTS)
        selected = [port for port in selected if port in _POSTURE_PORTS]
        results = [_tcp_probe(target.dc_ip, port, timeout) for port in selected]
        reachable = [item for item in results if item["reachable"]]
        payload = {
            "ok": True,
            "host": target.dc_ip,
            "authentication": "anonymous",
            "results": results,
            "reachable_services": [item["service"] for item in reachable],
        }
        session.log("passive-discovery.complete", reachable=len(reachable))
        session.path("passive-discovery.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
        return payload


@register_capability(
    id="external-exposure",
    summary="Assess externally reachable AD service exposure using low-noise connection checks",
    category="enumeration",
    tags=("unauthenticated", "external-exposure", "posture"),
    environment="live-read-only",
    auth_modes=("anonymous",),
    noise_level="low",
    data_sensitivity="endpoint-metadata",
)
class ExternalExposure:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        **kwargs: Any,
    ) -> dict[str, Any]:
        timeout = max(0.1, min(float(kwargs.get("timeout") or 1.5), 10.0))
        checks = [_tcp_probe(target.dc_ip, port, timeout) for port in (88, 389, 443, 445, 636)]
        signals = []
        for check in checks:
            if check["reachable"]:
                signals.append(
                    {
                        "service": check["service"],
                        "severity": "review",
                        "message": f"{check['service']} is reachable at the target endpoint",
                    }
                )
        payload = {
            "ok": True,
            "host": target.dc_ip,
            "authentication": "anonymous",
            "checks": checks,
            "signals": signals,
            "next_step": "Validate exposure against approved network-boundary documentation.",
        }
        session.log("external-exposure.complete", signals=len(signals))
        session.path("external-exposure.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
        return payload


@register_capability(
    id="anonymous-ldap-probe",
    summary="Measure anonymous LDAP bind and limited directory-read capabilities",
    category="enumeration",
    tags=("unauthenticated", "ldap", "posture"),
    environment="live-read-only",
    auth_modes=("anonymous",),
    noise_level="low",
    data_sensitivity="directory-metadata",
)
class AnonymousLdapProbe:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        **kwargs: Any,
    ) -> dict[str, Any]:
        server = Server(target.dc_ip, get_info=ALL, use_ssl=target.ldaps)
        checks: list[dict[str, Any]] = []
        conn: Connection | None = None
        try:
            conn = Connection(server, auto_bind=True)
            checks.append({"name": "anonymous_bind", "allowed": bool(conn.bound)})
            default_nc = server.info.other.get("defaultNamingContext", [None])[0]
            if not default_nc:
                default_nc = ",".join(f"DC={part}" for part in target.domain.split("."))
            probes = (
                ("naming_context", BASE, "(objectClass=*)"),
                ("users", SUBTREE, "(objectCategory=person)"),
                ("computers", SUBTREE, "(objectCategory=computer)"),
                ("groups", SUBTREE, "(objectCategory=group)"),
            )
            for name, scope, query in probes:
                try:
                    ok = conn.search(
                        default_nc,
                        query,
                        search_scope=scope,
                        attributes=["distinguishedName"],
                        size_limit=1,
                    )
                    checks.append(
                        {"name": name, "readable": bool(ok), "entries": len(conn.entries)}
                    )
                except LDAPException as exc:
                    checks.append({"name": name, "readable": False, "error": type(exc).__name__})
            payload = {
                "ok": True,
                "authentication": "anonymous",
                "default_naming_context": default_nc,
                "checks": checks,
            }
        except (LDAPException, OSError) as exc:
            payload = {
                "ok": False,
                "authentication": "anonymous",
                "checks": checks,
                "error": type(exc).__name__,
            }
        finally:
            if conn is not None:
                conn.unbind()
        session.log("anonymous-ldap-probe.complete", ok=payload["ok"])
        session.path("anonymous-ldap-probe.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
        return payload
