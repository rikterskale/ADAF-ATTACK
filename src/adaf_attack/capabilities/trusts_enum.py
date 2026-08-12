"""Deep trust enumeration, SID filtering analysis, and cross-domain path ranking."""

from __future__ import annotations

import json
from typing import Any, cast

from ldap3 import SUBTREE
from rich.console import Console
from rich.table import Table

from adaf_attack.core.confidence import score_chain
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

TRUST_DIR = {
    0: "Disabled",
    1: "Inbound (trusted domain can access us)",
    2: "Outbound (we can access trusted domain)",
    3: "Bidirectional",
}

TRUST_TYPE = {
    1: "Windows Downtown / Downlevel",
    2: "Windows Uplevel (AD)",
    3: "MIT / Kerberos realm",
    4: "DCE",
}

TRUST_ATTR_FLAGS = [
    (0x00000001, "NON_TRANSITIVE"),
    (0x00000002, "UPLEVEL_ONLY"),
    (0x00000004, "QUARANTINED_DOMAIN"),  # SID filtering enabled
    (0x00000008, "FOREST_TRANSITIVE"),
    (0x00000010, "CROSS_ORGANIZATION"),
    (0x00000020, "WITHIN_FOREST"),
    (0x00000040, "TREAT_AS_EXTERNAL"),
    (0x00000080, "USES_RC4_ENCRYPTION"),
    (0x00000200, "CROSS_ORGANIZATION_NO_TGT_DELEGATION"),
    (0x00000400, "PIM_TRUST"),
    (0x00000800, "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"),
]

TRUST_ATTRS = [
    "name",
    "flatName",
    "trustPartner",
    "trustDirection",
    "trustType",
    "trustAttributes",
    "securityIdentifier",
    "whenCreated",
    "whenChanged",
    "distinguishedName",
]


def _decode_attributes(value: int) -> list[str]:
    return [name for bit, name in TRUST_ATTR_FLAGS if value & bit]


def _attack_paths_for_trust(t: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive concrete cross-domain attack path candidates from trust attributes."""
    paths: list[dict[str, Any]] = []
    direction = t["direction"]
    sid_filtering = t["sid_filtering"]
    within_forest = t["within_forest"]
    forest_trust = t["forest_transitive"]
    partner = t.get("partner") or t.get("name") or "unknown"

    if direction in (1, 3) and not sid_filtering and not within_forest:
        conf = score_chain(terminal_relation="TrustedBy", path_length=1, edge_kinds=["TrustedBy"])
        paths.append(
            {
                "id": "sid-history-inbound",
                "partner": partner,
                "summary": "Inbound/bidirectional external trust without SID filtering",
                "technique": "T1134.005",
                "required_privileges": [
                    "Compromise principal in partner domain",
                    "Ability to inject SID history / extra SIDs into a PAC",
                ],
                "confidence": conf["confidence"],
                "confidence_rank": conf["confidence_rank"],
                "impact": "Potential privilege escalation into the local domain via forged extra SIDs",
            }
        )

    if forest_trust and direction in (1, 3):
        conf = score_chain(terminal_relation="TrustedBy", path_length=1, edge_kinds=["TrustedBy"])
        paths.append(
            {
                "id": "forest-trust-inbound",
                "partner": partner,
                "summary": "Forest-transitive trust with inbound path",
                "technique": "T1482",
                "required_privileges": [
                    "Foothold in partner forest",
                    "Review selective authentication / SID filtering posture",
                ],
                "confidence": "medium" if sid_filtering else conf["confidence"],
                "confidence_rank": 2 if sid_filtering else conf["confidence_rank"],
                "impact": "Cross-forest authentication path; scope depends on selective auth",
            }
        )

    if direction in (2, 3) and not within_forest:
        paths.append(
            {
                "id": "outbound-resource-access",
                "partner": partner,
                "summary": "Outbound trust enables local principals to authenticate to partner",
                "technique": "T1482",
                "required_privileges": ["Valid credentials in local domain"],
                "confidence": "medium",
                "confidence_rank": 2,
                "impact": "Lateral movement into partner domain resources",
            }
        )

    if "USES_RC4_ENCRYPTION" in t.get("attributes", []):
        paths.append(
            {
                "id": "trust-rc4",
                "partner": partner,
                "summary": "Trust permits RC4 encryption",
                "technique": "T1558",
                "required_privileges": ["Ability to observe or request tickets across the trust"],
                "confidence": "low",
                "confidence_rank": 1,
                "impact": "Weaker crypto on inter-domain tickets",
            }
        )

    return paths


def _analyze_trust(entry: Any, local_domain: str) -> dict[str, Any]:
    direction = int(entry.trustDirection.value) if entry.trustDirection else 0
    ttype = int(entry.trustType.value) if entry.trustType else 0
    attrs_raw = int(entry.trustAttributes.value) if entry.trustAttributes else 0
    flags = _decode_attributes(attrs_raw)

    partner = str(entry.trustPartner) if entry.trustPartner else None
    sid_filtering = "QUARANTINED_DOMAIN" in flags or "TREAT_AS_EXTERNAL" in flags
    within_forest = "WITHIN_FOREST" in flags
    forest_trust = "FOREST_TRANSITIVE" in flags
    transitive = "NON_TRANSITIVE" not in flags

    risk_notes = []
    if direction in (1, 3) and not sid_filtering and not within_forest:
        risk_notes.append(
            "Inbound/bidirectional trust without SID filtering (SID history attacks possible)"
        )
    if "USES_RC4_ENCRYPTION" in flags:
        risk_notes.append("RC4 allowed on trust")
    if forest_trust and direction in (1, 3):
        risk_notes.append("Forest trust with inbound path — review selective authentication")

    trust = {
        "name": str(entry.name) if entry.name else None,
        "flat_name": str(entry.flatName) if entry.flatName else None,
        "partner": partner,
        "direction": direction,
        "direction_label": TRUST_DIR.get(direction, f"Unknown({direction})"),
        "type": ttype,
        "type_label": TRUST_TYPE.get(ttype, f"Unknown({ttype})"),
        "attributes_raw": attrs_raw,
        "attributes": flags,
        "sid_filtering": sid_filtering,
        "within_forest": within_forest,
        "forest_transitive": forest_trust,
        "transitive": transitive,
        "when_created": str(entry.whenCreated) if entry.whenCreated else None,
        "when_changed": str(entry.whenChanged) if entry.whenChanged else None,
        "dn": str(entry.distinguishedName) if entry.distinguishedName else None,
        "risk_notes": risk_notes,
        "local_domain": local_domain,
    }
    trust["attack_paths"] = _attack_paths_for_trust(trust)
    return trust


@register_capability(
    id="trusts-enum",
    summary="Deep trust enumeration with SID-filtering attack-path analysis",
    category="enumeration",
    tags=("trusts", "forest", "sid-filtering", "cross-domain"),
)
class TrustsEnum:
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
        console.print(f"[bold]Trusts deep-dive[/bold] → {target.domain} @ {target.dc_ip}")

        conn, base_dn, _config = ldap_connect(target)
        domain_id = f"DOMAIN@{target.domain.upper()}"
        graph.add_node(domain_id, "Domain", name=target.domain, dn=base_dn)

        conn.search(
            base_dn,
            "(objectClass=trustedDomain)",
            search_scope=SUBTREE,
            attributes=TRUST_ATTRS,
        )

        trusts = []
        all_paths: list[dict[str, Any]] = []
        for entry in conn.entries:
            t = _analyze_trust(entry, target.domain)
            trusts.append(t)
            all_paths.extend(t.get("attack_paths") or [])

            if t["partner"]:
                partner_id = f"DOMAIN@{t['partner'].upper()}"
                graph.add_node(
                    partner_id,
                    "Domain",
                    name=t["partner"],
                    flat_name=t["flat_name"],
                )
                graph.add_edge(
                    domain_id,
                    partner_id,
                    "TrustedBy",
                    direction=t["direction"],
                    direction_label=t["direction_label"],
                    sid_filtering=t["sid_filtering"],
                    within_forest=t["within_forest"],
                    forest_transitive=t["forest_transitive"],
                    attributes=t["attributes"],
                )
                if t["direction"] in (1, 3):
                    graph.add_edge(
                        partner_id,
                        domain_id,
                        "SameForestTrust" if t["within_forest"] else "ExternalTrust",
                        sid_filtering=t["sid_filtering"],
                    )

        conn.unbind()

        table = Table(title="Trusts", show_header=True, header_style="bold")
        table.add_column("Partner")
        table.add_column("Direction")
        table.add_column("Type")
        table.add_column("SID filter")
        table.add_column("Paths")
        table.add_column("Flags / notes")

        for t in trusts:
            notes = ", ".join(t["attributes"][:4])
            if t["risk_notes"]:
                notes = f"[red]{t['risk_notes'][0]}[/red]"
            table.add_row(
                t["partner"] or "?",
                t["direction_label"].split("(")[0].strip(),
                t["type_label"],
                "yes" if t["sid_filtering"] else "[red]no[/red]",
                str(len(t.get("attack_paths") or [])),
                notes,
            )

        console.print(table)

        # Rank paths: higher confidence first
        all_paths.sort(key=lambda p: (-int(p.get("confidence_rank") or 0), p.get("id") or ""))

        result = {
            "domain": target.domain,
            "count": len(trusts),
            "trusts": trusts,
            "attack_paths": all_paths,
            "inbound_without_sid_filter": [
                t["partner"]
                for t in trusts
                if t["direction"] in (1, 3) and not t["sid_filtering"] and not t["within_forest"]
            ],
        }

        out_path = session.path("trusts-enum.json")
        out_path.write_text(json.dumps(result, indent=2, default=str))
        graph.save(session.path("graph.json"))

        session.log(
            "trusts-enum.complete",
            count=len(trusts),
            attack_paths=len(all_paths),
        )
        console.print(
            f"[green]Done[/green]  trusts={len(trusts)}  "
            f"inbound-no-sid-filter={len(cast(list[Any], result['inbound_without_sid_filter']))}  "
            f"attack_paths={len(all_paths)}"
        )
        console.print(f"Results → {out_path}")
        return result
