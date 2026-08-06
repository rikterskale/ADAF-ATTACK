"""AD CS enumeration — CAs, templates, ESC1–ESC8 candidates + enrollment rights."""

from __future__ import annotations

import json
from typing import Any

from ldap3 import LEVEL
from rich.console import Console

from adaf_attack.core.acl import fetch_sd, parse_interesting_aces
from adaf_attack.core.adcs_analyze import analyze_template_flags, is_web_enrollment_endpoint
from adaf_attack.core.esc6_probe import probe_esc6
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
CT_FLAG_PUBLISH_TO_DS = 0x00000008
CT_FLAG_AUTO_ENROLLMENT = 0x00000020
CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
CT_FLAG_USER_INTERACTION_REQUIRED = 0x00000100
CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001  # name-flag neighbour; kept for clarity

EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMART_CARD = "1.3.6.1.4.1.311.20.2.2"
EKU_ANY = "2.5.29.37.0"
EKU_PKINIT_CLIENT = "1.3.6.1.5.2.3.4"
EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_CERTIFICATE_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"  # enrollment agent
EKU_PRIVATE_KEY_ARCHIVAL = None  # signalled via schema flags more than EKU

TEMPLATE_ATTRS = [
    "cn",
    "displayName",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-RA-Signature",
    "msPKI-RA-Application-Policies",
    "pKIExtendedKeyUsage",
    "nTSecurityDescriptor",
    "msPKI-Certificate-Application-Policy",
    "msPKI-Minimal-Key-Size",
]
CA_ATTRS = [
    "cn",
    "dNSHostName",
    "cACertificateDN",
    "certificateTemplates",
    "nTSecurityDescriptor",
    "msPKI-Enrollment-Servers",
]


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
    if isinstance(raw, list | tuple):
        return [str(x) for x in raw]
    return [str(raw)]


def _client_auth_eku(ekus: list[str]) -> bool:
    if not ekus:
        return True  # empty EKU → any purpose
    interesting = {EKU_CLIENT_AUTH, EKU_ANY, EKU_SMART_CARD, EKU_PKINIT_CLIENT, EKU_SMARTCARD_LOGON}
    return bool(set(ekus) & interesting)


def _analyze_template(entry: Any) -> dict[str, Any]:
    """Thin LDAP-entry adapter over pure analyze_template_flags."""
    name_flags = _int_attr(entry, "msPKI-Certificate-Name-Flag")
    enroll_flags = _int_attr(entry, "msPKI-Enrollment-Flag")
    ra_sig = _int_attr(entry, "msPKI-RA-Signature")
    ekus = _list_attr(entry, "pKIExtendedKeyUsage")
    app_policies = _list_attr(entry, "msPKI-Certificate-Application-Policy")
    flags = analyze_template_flags(
        name_flags=name_flags,
        enrollment_flags=enroll_flags,
        ra_signatures=ra_sig,
        ekus=ekus,
        application_policies=app_policies,
    )
    return {
        "cn": str(entry.cn) if entry.cn else None,
        "display_name": str(entry.displayName) if entry.displayName else None,
        "name_flags": name_flags,
        "enrollment_flags": enroll_flags,
        "ra_signatures_required": ra_sig,
        "ekus": ekus,
        "application_policies": app_policies,
        "ra_application_policies": _list_attr(entry, "msPKI-RA-Application-Policies"),
        "enrollee_supplies_subject": flags["enrollee_supplies_subject"],
        "requires_manager_approval": flags["requires_manager_approval"],
        "client_auth_eku": flags["client_auth_eku"],
        "esc1_candidate": flags["esc1_candidate"],
        "esc2_candidate": flags["esc2_candidate"],
        "esc3_agent_template": flags["esc3_agent_template"],
        "esc3_requires_ra": flags["esc3_requires_ra"],
        "esc_tags": flags["esc_tags"],
        "dn": str(entry.entry_dn),
    }


@register_capability(
    id="adcs-enum",
    summary="Enumerate AD CS CAs/templates, ESC1–ESC8 signals, and enrollment rights",
    category="enumeration",
    tags=("adcs", "pki", "esc1", "esc2", "esc3", "esc4", "esc8", "templates", "enroll"),
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
            "esc2_candidates": [],
            "esc3_agent_templates": [],
            "esc3_ra_required_templates": [],
            "esc4_acl_templates": [],
            "esc7_ca_acl": [],
            "esc8_web_enrollment": [],
            "esc9_candidates": [],
            "esc10_candidates": [],
            "esc11_candidates": [],
            "esc13_candidates": [],
            "esc1_with_enroll_principals": [],
            "notes": {
                "ESC5": "Check CA server computer object ACL separately (not in this pass)",
                "ESC6": "EDITF_ATTRIBUTESUBJECTALTNAME2 requires RPC/CA config inspection",
                "ESC9": "No-security-extension assessment requires template flag and mapping validation.",
                "ESC10": "Weak certificate mapping assessment requires DC mapping-policy validation.",
                "ESC11": "RPC encryption policy requires CA interface validation.",
                "ESC13": "OID group-link assessment requires issuance-policy object validation.",
            },
        }

        # CAs + ESC7 / ESC8 signals
        try:
            conn.search(
                enrollment_base,
                "(objectClass=pKIEnrollmentService)",
                search_scope=LEVEL,
                attributes=CA_ATTRS,
            )
            for entry in conn.entries:
                ca: dict[str, Any] = {
                    "cn": str(entry.cn) if entry.cn else None,
                    "dns": str(entry.dNSHostName) if entry.dNSHostName else None,
                    "cert_dn": str(entry.cACertificateDN) if entry.cACertificateDN else None,
                    "templates": _list_attr(entry, "certificateTemplates"),
                    "enrollment_servers": _list_attr(entry, "msPKI-Enrollment-Servers"),
                    "manage_principals": [],
                }
                ca_id = f"CA@{(ca['cn'] or 'UNKNOWN').upper()}@{target.domain.upper()}"
                graph.add_node(
                    ca_id,
                    "CA",
                    **{k: v for k, v in ca.items() if v is not None and k != "manage_principals"},
                )

                # ESC8: HTTP enrollment endpoints
                for srv in ca["enrollment_servers"]:
                    if is_web_enrollment_endpoint(srv):
                        result["esc8_web_enrollment"].append({"ca": ca["cn"], "endpoint": srv})
                        graph.add_edge(ca_id, ca_id, "ESC8WebEnrollment", endpoint=srv)
                        console.print(f"  [red]ESC8 web enrollment[/red]: {ca['cn']} → {srv}")

                # ESC7: ManageCA / ManageCertificates rights on CA object
                sd = fetch_sd(conn, str(entry.entry_dn))
                if sd:
                    try:
                        for ace in parse_interesting_aces(sd):
                            if ace.right in (
                                "GenericAll",
                                "WriteDacl",
                                "WriteOwner",
                                "ManageCA",
                                "ManageCertificates",
                                "AllExtendedRights",
                            ):
                                ca["manage_principals"].append(
                                    {"sid": ace.principal_sid, "right": ace.right}
                                )
                                src = f"SID@{ace.principal_sid}"
                                graph.add_node(src, "Base", sid=ace.principal_sid)
                                graph.add_edge(src, ca_id, ace.right)
                                if ace.right in ("ManageCA", "ManageCertificates", "GenericAll"):
                                    result["esc7_ca_acl"].append(
                                        {
                                            "ca": ca["cn"],
                                            "sid": ace.principal_sid,
                                            "right": ace.right,
                                        }
                                    )
                                    graph.add_edge(src, ca_id, "ESC7")
                    except Exception as exc:  # noqa: BLE001
                        console.print(f"  [yellow]CA SD parse {ca['cn']}: {exc}[/yellow]")

                result["cas"].append(ca)
                console.print(f"  CA: [cyan]{ca['cn']}[/cyan]  ({ca['dns']})")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]CA enumeration limited: {exc}[/yellow]")

        # ESC5-ish: dangerous ACLs on other PKI container objects (AIA, CDP, NTAuth, KRA)
        result.setdefault("esc5_pki_acl", [])
        try:
            pki_objects = [
                f"CN=AIA,{pki_base}",
                f"CN=CDP,{pki_base}",
                f"CN=NTAuthCertificates,{pki_base}",
                f"CN=KRA,{pki_base}",
                f"CN=OID,{pki_base}",
            ]
            for dn in pki_objects:
                sd = fetch_sd(conn, dn)
                if not sd:
                    continue
                try:
                    for ace in parse_interesting_aces(sd):
                        if ace.right in (
                            "GenericAll",
                            "WriteDacl",
                            "WriteOwner",
                            "GenericWrite",
                            "WriteProperty",
                        ):
                            result["esc5_pki_acl"].append(
                                {"dn": dn, "sid": ace.principal_sid, "right": ace.right}
                            )
                            src = f"SID@{ace.principal_sid}"
                            graph.add_node(src, "Base", sid=ace.principal_sid)
                            graph.add_edge(src, f"PKI@{dn}", "ESC5", right=ace.right)
                except Exception:  # noqa: BLE001
                    pass
            if result["esc5_pki_acl"]:
                console.print(f"  [red]ESC5 PKI ACL hits[/red]: {len(result['esc5_pki_acl'])}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]ESC5 PKI ACL scan limited: {exc}[/yellow]")

        # ESC6 note — full detection needs RPC (certutil / CA config)
        result["notes"]["ESC6"] = (
            "EDITF_ATTRIBUTESUBJECTALTNAME2 is a CA policy flag; detect via "
            "certutil -config CA -getreg policy\\EditFlags or Impacket RPC. "
            "Not readable from LDAP alone."
        )

        # Templates + enrollment rights + ESC1-4
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
                acl_dangerous: list[dict[str, str]] = []

                sd = fetch_sd(conn, tmpl["dn"])
                if sd:
                    try:
                        for ace in parse_interesting_aces(sd):
                            if ace.right in (
                                "Enroll",
                                "AutoEnroll",
                                "GenericAll",
                                "AllExtendedRights",
                            ):
                                enroll_principals.append(
                                    {"sid": ace.principal_sid, "right": ace.right}
                                )
                                tmpl_id = f"TEMPLATE@{(tmpl['cn'] or 'UNKNOWN').upper()}"
                                src = f"SID@{ace.principal_sid}"
                                graph.add_node(src, "Base", sid=ace.principal_sid)
                                graph.add_edge(src, tmpl_id, ace.right)
                            if ace.right in (
                                "GenericAll",
                                "WriteDacl",
                                "WriteOwner",
                                "GenericWrite",
                                "WriteProperty",
                            ):
                                acl_dangerous.append({"sid": ace.principal_sid, "right": ace.right})
                    except RuntimeError:
                        raise
                    except Exception as exc:  # noqa: BLE001
                        console.print(f"  [yellow]SD parse {tmpl['cn']}: {exc}[/yellow]")

                tmpl["enroll_principals"] = enroll_principals
                tmpl["enroll_principal_count"] = len(enroll_principals)
                tmpl["dangerous_acl"] = acl_dangerous
                result["templates"].append(tmpl)

                tmpl_id = f"TEMPLATE@{(tmpl['cn'] or 'UNKNOWN').upper()}"
                graph.add_node(
                    tmpl_id,
                    "CertTemplate",
                    cn=tmpl["cn"],
                    esc1_candidate=tmpl["esc1_candidate"],
                    esc2_candidate=tmpl["esc2_candidate"],
                    enrollee_supplies_subject=tmpl["enrollee_supplies_subject"],
                    esc_tags=tmpl["esc_tags"],
                )

                if tmpl["esc1_candidate"]:
                    result["esc1_candidates"].append(tmpl["cn"])
                    graph.add_edge(tmpl_id, tmpl_id, "ESC1")
                    if enroll_principals:
                        result["esc1_with_enroll_principals"].append(
                            {"template": tmpl["cn"], "enroll_principals": enroll_principals}
                        )
                        graph.add_edge(tmpl_id, tmpl_id, "ESC1Enrollable")
                        console.print(
                            f"  [red]ESC1 + enroll[/red]: {tmpl['cn']}  "
                            f"principals={len(enroll_principals)}"
                        )
                    else:
                        console.print(f"  [yellow]ESC1 candidate[/yellow]: {tmpl['cn']}")

                if tmpl["esc2_candidate"] and not tmpl["esc1_candidate"]:
                    result["esc2_candidates"].append(tmpl["cn"])
                    graph.add_edge(tmpl_id, tmpl_id, "ESC2")
                    console.print(f"  [red]ESC2[/red]: {tmpl['cn']}")

                if tmpl["esc3_agent_template"]:
                    result["esc3_agent_templates"].append(tmpl["cn"])
                    graph.add_edge(tmpl_id, tmpl_id, "ESC3Agent")
                    console.print(f"  [red]ESC3 agent template[/red]: {tmpl['cn']}")

                if tmpl["esc3_requires_ra"]:
                    result["esc3_ra_required_templates"].append(tmpl["cn"])
                    graph.add_edge(tmpl_id, tmpl_id, "ESC3RequiresRA")

                if acl_dangerous:
                    result["esc4_acl_templates"].append(
                        {"template": tmpl["cn"], "aces": acl_dangerous}
                    )
                    graph.add_edge(tmpl_id, tmpl_id, "ESC4")
                    console.print(f"  [red]ESC4 ACL[/red]: {tmpl['cn']}  aces={len(acl_dangerous)}")

                if not tmpl["esc_tags"] and not acl_dangerous:
                    console.print(f"  Template: {tmpl['cn']}  enroll_aces={len(enroll_principals)}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]Template enumeration limited: {exc}[/yellow]")

        # ESC6 probe (certutil local and/or Impacket remote registry)
        ca_hosts = [c.get("dns") for c in result["cas"] if c.get("dns")]
        ca_hosts = [h for h in ca_hosts if h]
        if not ca_hosts:
            ca_hosts = [target.dc_ip]
        console.print("[dim]ESC6 probe (EditFlags / ATTRIBUTESUBJECTALTNAME2)…[/dim]")
        esc6 = probe_esc6(target, ca_hostnames=ca_hosts)
        result["esc6"] = esc6
        if esc6.get("resolved"):
            if esc6.get("esc6"):
                console.print("  [red]ESC6 CONFIRMED[/red] — EDITF_ATTRIBUTESUBJECTALTNAME2 set")
                for ca in result["cas"]:
                    ca_id = f"CA@{(ca.get('cn') or 'UNKNOWN').upper()}@{target.domain.upper()}"
                    graph.add_edge(ca_id, ca_id, "ESC6")
            else:
                console.print("  [green]ESC6 not set[/green] (EditFlags checked)")
        else:
            console.print(f"  [yellow]ESC6 unresolved[/yellow]: {esc6.get('note', '')[:80]}")

        conn.unbind()

        out_path = session.path("adcs-enum.json")

        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "adcs-enum.complete",
            cas=len(result["cas"]),
            templates=len(result["templates"]),
            esc1=len(result["esc1_candidates"]),
            esc2=len(result["esc2_candidates"]),
            esc3=len(result["esc3_agent_templates"]),
            esc4=len(result["esc4_acl_templates"]),
            esc7=len(result["esc7_ca_acl"]),
            esc8=len(result["esc8_web_enrollment"]),
            esc6=result.get("esc6", {}).get("esc6"),
        )

        console.print(
            f"[green]Done[/green]  CAs={len(result['cas'])}  "
            f"templates={len(result['templates'])}  "
            f"ESC1={len(result['esc1_candidates'])}  "
            f"ESC2={len(result['esc2_candidates'])}  "
            f"ESC3={len(result['esc3_agent_templates'])}  "
            f"ESC4={len(result['esc4_acl_templates'])}  "
            f"ESC7={len(result['esc7_ca_acl'])}  "
            f"ESC8={len(result['esc8_web_enrollment'])}"
        )
        console.print(f"Results → {out_path}")
        return result
