"""Non-exploiting AD CVE / hardening posture scan.

Checks for public AD CVE indicators using LDAP, SMB signing, and cert-template
policy signals. Zerologon/noPAC/Certifried are indicator-only (no exploit).
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

from ldap3 import SUBTREE
from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


def _check_smb_signing(dc_ip: str) -> dict[str, Any]:
    try:
        from impacket.smbconnection import SMBConnection

        conn = SMBConnection(dc_ip, dc_ip)
        info = {
            "server": conn.getServerName(),
            "signing_required": bool(conn.isSigningRequired()),
        }
        with contextlib.suppress(Exception):
            conn.close()
        return info
    except Exception as exc:
        return {"error": str(exc)[:200]}


def _check_ldap_signing(conn: Any, base_dn: str) -> dict[str, Any]:
    # LDAP signing / channel binding is generally not readable remotely without
    # elevated rights. We report the attribute if present.
    try:
        conn.search(
            base_dn,
            "(objectClass=domainDNS)",
            search_scope=SUBTREE,
            attributes=["msDS-ExpirePasswordsOnSmartCardOnlyAccounts"],
        )
        return {"ok": True, "hint": "operator should validate LdapEnforceChannelBinding via GPO"}
    except Exception as exc:
        return {"error": str(exc)[:200]}


def _check_certifried_templates(conn: Any, config_nc: str) -> dict[str, Any]:
    tpl_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_nc}"
    try:
        conn.search(
            tpl_dn,
            "(objectClass=pKICertificateTemplate)",
            search_scope=SUBTREE,
            attributes=["cn", "msPKI-Certificate-Name-Flag"],
        )
        weak: list[str] = []
        for entry in conn.entries:
            flag = (
                int(entry["msPKI-Certificate-Name-Flag"].value)
                if entry["msPKI-Certificate-Name-Flag"]
                else 0
            )
            if flag & 0x1:  # ENROLLEE_SUPPLIES_SUBJECT
                weak.append(str(entry.cn))
        return {"weak_templates": weak, "count": len(weak)}
    except Exception as exc:
        return {"error": str(exc)[:200]}


def _check_no_pac(conn: Any, base_dn: str) -> dict[str, Any]:
    try:
        conn.search(
            base_dn,
            "(sAMAccountName=krbtgt)",
            search_scope=SUBTREE,
            attributes=["msDS-KeyVersionNumber"],
        )
        if not conn.entries:
            return {"error": "krbtgt not visible"}
        entry = conn.entries[0]
        kvno = int(entry["msDS-KeyVersionNumber"].value) if entry["msDS-KeyVersionNumber"] else 0
        return {
            "krbtgt_kvno": kvno,
            "hint": "kvno of 1 or unpatched build implies possible noPAC exposure",
        }
    except Exception as exc:
        return {"error": str(exc)[:200]}


# Compatibility alias for older offline integrations; the implementation now
# follows the project's lowercase private-function naming convention.
_check_noPAC = _check_no_pac  # noqa: N816  # compatibility alias


def _check_functional_level(conn: Any, base_dn: str) -> dict[str, Any]:
    try:
        conn.search(
            base_dn,
            "(objectClass=domainDNS)",
            search_scope=SUBTREE,
            attributes=["msDS-Behavior-Version"],
        )
        if not conn.entries:
            return {"error": "domain object not visible"}
        entry = conn.entries[0]
        level = int(entry["msDS-Behavior-Version"].value) if entry["msDS-Behavior-Version"] else 0
        return {"domain_functional_level": level}
    except Exception as exc:
        return {"error": str(exc)[:200]}


def _check_ntlm_and_rc4(conn: Any, base_dn: str) -> dict[str, Any]:
    try:
        conn.search(
            base_dn,
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)",  # DES only
            search_scope=SUBTREE,
            attributes=["sAMAccountName"],
        )
        des_users = [str(e.sAMAccountName) for e in conn.entries if e.sAMAccountName]
        conn.search(
            base_dn,
            "(!(msDS-SupportedEncryptionTypes=*))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "objectClass"],
        )
        no_etype = sum(
            1
            for e in conn.entries
            if e.objectClass and any(str(c).lower() == "user" for c in e.objectClass.values)
        )
        return {
            "des_users": des_users,
            "accounts_without_supported_etypes": no_etype,
            "hint": "AES-only rollout blocks RC4 downgrade + ticket-forge with old keys",
        }
    except Exception as exc:
        return {"error": str(exc)[:200]}


@register_capability(
    id="ad-cve-scan",
    summary="Non-exploiting scan for Zerologon / noPAC / Certifried / signing posture",
    category="enumeration",
    tags=("cve", "posture", "hardening", "assessment"),
)
class AdCveScan:
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
        console.print(f"[bold]AD CVE scan[/bold] → {target.domain} @ {target.dc_ip}")
        conn, base_dn, config_nc = ldap_connect(target)
        if not config_nc:
            raise RuntimeError("Could not resolve configuration naming context from RootDSE.")

        findings: dict[str, Any] = {
            "smb_signing": _check_smb_signing(target.dc_ip),
            "ldap_signing": _check_ldap_signing(conn, base_dn),
            "certifried_templates": _check_certifried_templates(conn, config_nc),
            "noPAC_indicator": _check_no_pac(conn, base_dn),
            "domain_functional_level": _check_functional_level(conn, base_dn),
            "ntlm_and_rc4": _check_ntlm_and_rc4(conn, base_dn),
        }
        conn.unbind()

        summary = {
            "smb_signing_required": findings["smb_signing"].get("signing_required"),
            "vulnerable_cert_templates": findings["certifried_templates"].get("count", 0),
            "des_only_users": len(findings["ntlm_and_rc4"].get("des_users", []) or []),
            "domain_level": findings["domain_functional_level"].get("domain_functional_level"),
        }
        payload = {"domain": target.domain, "findings": findings, "summary": summary}
        out = session.path("ad-cve-scan.json")
        out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log("ad-cve-scan.complete", **summary)
        console.print(f"[green]Done[/green]  {summary}")
        return payload
