"""AD CS enumeration — CAs, templates, ESC1 candidates + enrollment rights."""

from __future__ import annotations

import json
from typing import Any

from ldap3 import LEVEL
from rich.console import Console

from adaf_attack.core.acl import fetch_sd, parse_interesting_aces
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMART_CARD = "1.3.6.1.4.1.311.20.2.2"
EKU_ANY = "2.5.29.37.0"

TEMPLATE_ATTRS = [
    "cn",
    "displayName",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-RA-Signature",
    "pKIExtendedKeyUsage",
    "nTSecurityDescriptor",
]
CA_ATTRS = ["cn", "dNSHostName", "cACertificateDN", "certificateTemplates"]


def _int_attr(entry: Any, name: str) -> int:
    val = getattr(entry, name, None)
    if val is None or val.value is None:
        return 0
    try:
        return int(val.value)
    except (TypeError, ValueError):
        return 0


def _list_attr(entry: Any, name: str) -> list[str]:
    val = getattr(entry, name, None)
    if not val:
        return []
    raw = val.value if hasattr(val, "value") else val
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw]
    return [str(raw)]


def _analyze_template(entry: Any) -> dict[str, Any]:
    name_flags = _int_attr(entry, "msPKI-Certificate-Name-Flag")
    enroll_flags = _int_attr(entry, "msPKI-Enrollment-Flag")
    ra_sig = _int_attr(entry, "msPKI-RA-Signature")
    ekus = _list_attr(entry, "pKIExtendedKeyUsage")

    enrollee_supplies = bool(name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    requires_manager = bool(enroll_flags & CT_FLAG_PEND_ALL_REQUESTS)
    client_auth = (
        not ekus or EKU_CLIENT_AUTH in ekus or EKU_ANY in ekus or EKU_SMART_CARD in ekus
    )
    esc1_candidate = (
        enrollee_supplies and client_auth and not requires_manager and ra_sig == 0
    )

    return {
        "cn": str(entry.cn) if entry.cn else None,
        "display_name": str(entry.displayName) if entry.displayName else None,
        "name_flags": name_flags,
        "enrollment_flags": enroll_flags,
        "ra_signatures_required": ra_sig,
        "ekus": ekus,
        "enrollee_supplies_subject": enrollee_supplies,
        "requires_manager_approval": requires_manager,
        "client_auth_eku": client_auth,
        "esc1_candidate": esc1_candidate,
        "dn": str(entry.entry_dn),
    }


@register_capability(
    id="adcs-enum",
    summary="Enumerate AD CS CAs/templates, ESC1 candidates, and enrollment rights",
    category="enumeration",
    tags=("adcs", "pki", "esc1", "templates", "enroll"),
)
class AdcsEnum:
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
        console.print(f"[bold]ADCS enum[/bold] → {target.domain} @ {target.dc_ip}")

        conn, default_nc, config_nc = ldap_connect(target)
        if not config_nc:
            conn.unbind()
            raise RuntimeError("Could not resolve configurationNamingContext")

        pki_base = f"CN=Public Key Services,CN=Services,{config_nc}"
        templates_base = f"CN=Certificate Templates,{pki_base}"
        enrollment_base = f"CN=Enrollment Services,{pki_base}"

        result: dict[str, Any] = {
            "domain": target.domain,
            "config_nc": config_nc,
            "cas": [],
            "templates": [],
            "esc1_candidates": [],
            "esc1_with_enroll_principals": [],
        }

        # CAs
        try:
            conn.search(
                enrollment_base,
                "(objectClass=pKIEnrollmentService)",
                search_scope=LEVEL,
                attributes=CA_ATTRS,
            )
            for entry in conn.entries:
                ca = {
                    "cn": str(entry.cn) if entry.cn else None,
                    "dns": str(entry.dNSHostName) if entry.dNSHostName else None,
                    "cert_dn": str(entry.cACertificateDN) if entry.cACertificateDN else None,
                    "templates": _list_attr(entry, "certificateTemplates"),
                }
                result["cas"].append(ca)
                ca_id = f"CA@{(ca['cn'] or 'UNKNOWN').upper()}@{target.domain.upper()}"
                graph.add_node(ca_id, "CA", **{k: v for k, v in ca.items() if v is not None})
                console.print(f"  CA: [cyan]{ca['cn']}[/cyan]  ({ca['dns']})")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]CA enumeration limited: {exc}[/yellow]")

        # Templates + enrollment rights
        try:
            conn.search(
                templates_base,
                "(objectClass=pKICertificateTemplate)",
                search_scope=LEVEL,
                attributes=TEMPLATE_ATTRS,
            )
            for entry in conn.entries:
                tmpl = _analyze_template(entry)
                enroll_principals: list[dict[str, str]] = []

                # Proof of enrollment rights via DACL
                sd = fetch_sd(conn, tmpl["dn"])
                if sd:
                    try:
                        for ace in parse_interesting_aces(sd):
                            if ace.right in ("Enroll", "AutoEnroll", "GenericAll", "AllExtendedRights"):
                                enroll_principals.append(
                                    {
                                        "sid": ace.principal_sid,
                                        "right": ace.right,
                                    }
                                )
                                tmpl_id = f"TEMPLATE@{(tmpl['cn'] or 'UNKNOWN').upper()}"
                                src = f"SID@{ace.principal_sid}"
                                graph.add_node(src, "Base", sid=ace.principal_sid)
                                graph.add_edge(src, tmpl_id, ace.right)
                    except RuntimeError:
                        raise
                    except Exception as exc:  # noqa: BLE001
                        console.print(f"  [yellow]SD parse {tmpl['cn']}: {exc}[/yellow]")

                tmpl["enroll_principals"] = enroll_principals
                tmpl["enroll_principal_count"] = len(enroll_principals)
                result["templates"].append(tmpl)

                tmpl_id = f"TEMPLATE@{(tmpl['cn'] or 'UNKNOWN').upper()}"
                graph.add_node(
                    tmpl_id,
                    "CertTemplate",
                    cn=tmpl["cn"],
                    esc1_candidate=tmpl["esc1_candidate"],
                    enrollee_supplies_subject=tmpl["enrollee_supplies_subject"],
                )

                if tmpl["esc1_candidate"]:
                    result["esc1_candidates"].append(tmpl["cn"])
                    graph.add_edge(tmpl_id, tmpl_id, "ESC1Candidate")
                    if enroll_principals:
                        result["esc1_with_enroll_principals"].append(
                            {
                                "template": tmpl["cn"],
                                "enroll_principals": enroll_principals,
                            }
                        )
                        graph.add_edge(tmpl_id, tmpl_id, "ESC1Enrollable")
                        console.print(
                            f"  [red]ESC1 + enroll rights[/red]: {tmpl['cn']}  "
                            f"principals={len(enroll_principals)}"
                        )
                    else:
                        console.print(
                            f"  [yellow]ESC1 candidate (no enroll ACE resolved)[/yellow]: {tmpl['cn']}"
                        )
                else:
                    console.print(
                        f"  Template: {tmpl['cn']}  enroll_aces={len(enroll_principals)}"
                    )
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]Template enumeration limited: {exc}[/yellow]")

        conn.unbind()

        out_path = session.path("adcs-enum.json")
        out_path.write_text(json.dumps(result, indent=2, default=str))
        graph.save(session.path("graph.json"))
        session.log(
            "adcs-enum.complete",
            cas=len(result["cas"]),
            templates=len(result["templates"]),
            esc1=len(result["esc1_candidates"]),
            esc1_enrollable=len(result["esc1_with_enroll_principals"]),
        )

        console.print(
            f"[green]Done[/green]  CAs={len(result['cas'])}  "
            f"templates={len(result['templates'])}  "
            f"ESC1={len(result['esc1_candidates'])}  "
            f"ESC1+enroll={len(result['esc1_with_enroll_principals'])}"
        )
        console.print(f"Results → {out_path}")
        return result
