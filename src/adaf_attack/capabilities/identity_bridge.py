"""Hybrid identity signals and BloodHound graph round-trip helpers.

hybrid-signals is strictly observational: it surfaces on-prem attributes that
indicate hybrid identity posture without requiring Entra / Graph permissions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ldap3 import SUBTREE

from adaf_attack.core.bloodhound import import_bloodhound, save_bloodhound, save_bloodhound_zip
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

HYBRID_USER_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "description",
    "servicePrincipalName",
    "userPrincipalName",
    "mail",
    "proxyAddresses",
    "msDS-cloudExtensionAttribute1",
    "msDS-ExternalDirectoryObjectId",
    "msDS-DeviceObjectVersion",
    "msDS-ConsistencyGuid",
    "msExchRecipientTypeDetails",
    "msExchRemoteRecipientType",
    "onPremisesSamAccountName",
]


@register_capability(
    id="bloodhound-import",
    summary="Import BloodHound-compatible JSON, enrich locally, and re-export",
    category="export",
    tags=("bloodhound", "import", "round-trip"),
)
class BloodhoundImport:
    def run(
        self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any
    ) -> dict[str, Any]:
        artifact = Path(str(kwargs.get("artifact") or ""))
        if not artifact.is_file():
            raise RuntimeError("bloodhound-import requires --artifact <BloodHound JSON>")
        result: dict[str, Any] = import_bloodhound(artifact, graph)
        graph.save(session.path("graph.json"))
        json_path = session.path("bloodhound-enriched.json")
        zip_path = session.path("bloodhound-enriched.zip")
        save_bloodhound(graph, json_path, target.domain)
        save_bloodhound_zip(graph, zip_path, target.domain)
        result.update(
            {"source": str(artifact), "json_path": str(json_path), "zip_path": str(zip_path)}
        )
        session.log("bloodhound-import.complete", **result)
        return result


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


@register_capability(
    id="hybrid-signals",
    summary="Detect on-prem hybrid identity / Entra-adjacent signals (read-only)",
    category="enumeration",
    tags=("hybrid", "entra", "azure-ad-connect", "pta", "phs", "synced"),
)
class HybridSignals:
    def run(
        self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any
    ) -> dict[str, Any]:
        conn, base_dn, _cfg = ldap_connect(target)
        signals: list[dict[str, Any]] = []
        synced_accounts: list[dict[str, str]] = []
        cloud_linked: list[dict[str, str]] = []
        infra_principals: list[dict[str, str]] = []

        max_objects = int(kwargs.get("max_objects") or 3000)
        conn.search(
            base_dn,
            "(|(objectClass=user)(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))",
            search_scope=SUBTREE,
            attributes=HYBRID_USER_ATTRS,
            size_limit=max_objects,
        )

        infra_markers = {
            "azure ad connect": "Azure AD Connect",
            "adconnect": "Azure AD Connect",
            "aad connect": "Azure AD Connect",
            "pass-through authentication": "PTA",
            "passthroughauthentication": "PTA",
            "seamless sso": "Seamless SSO",
            "azureadkerberos": "Azure AD Kerberos",
            "password hash sync": "PHS",
        }

        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            dn_attr = getattr(entry, "distinguishedName", None)
            desc_attr = getattr(entry, "description", None)
            dn = str(dn_attr) if dn_attr else ""
            desc = str(desc_attr) if desc_attr else ""
            spns = _list_attr(entry, "servicePrincipalName")
            text = " ".join([desc, *spns, dn]).lower()

            for needle, label in infra_markers.items():
                if needle in text:
                    row = {"principal": sam, "signal": label, "dn": dn}
                    signals.append(row)
                    infra_principals.append(row)

            # Cloud directory object id / consistency guid → synced or cloud-linked
            ext_id = getattr(entry, "msDS-ExternalDirectoryObjectId", None)
            consistency = getattr(entry, "msDS-ConsistencyGuid", None)
            if (ext_id and ext_id.value) or (consistency and consistency.value):
                cloud_linked.append(
                    {
                        "principal": sam,
                        "signal": "CloudDirectoryObjectLink",
                        "has_external_directory_id": str(bool(ext_id and ext_id.value)),
                        "has_consistency_guid": str(bool(consistency and consistency.value)),
                    }
                )
                signals.append({"principal": sam, "signal": "CloudDirectoryObjectLink", "dn": dn})

            # Exchange remote recipient / hybrid mailbox indicators
            remote_type = getattr(entry, "msExchRemoteRecipientType", None)
            recipient_details = getattr(entry, "msExchRecipientTypeDetails", None)
            if remote_type and remote_type.value is not None:
                synced_accounts.append(
                    {
                        "principal": sam,
                        "signal": "ExchangeRemoteRecipient",
                        "remote_recipient_type": str(remote_type.value),
                    }
                )
                signals.append({"principal": sam, "signal": "ExchangeRemoteRecipient", "dn": dn})
            elif recipient_details and recipient_details.value is not None:
                # Large bit flags; presence alone is a weak hybrid hint
                try:
                    val = int(recipient_details.value)
                    if val > 0:
                        synced_accounts.append(
                            {
                                "principal": sam,
                                "signal": "ExchangeRecipientDetails",
                                "recipient_type_details": str(val),
                            }
                        )
                except (TypeError, ValueError):
                    pass

            # UPN / proxyAddresses with onmicrosoft.com or #EXT#
            upn_attr = getattr(entry, "userPrincipalName", None)
            upn = str(upn_attr) if upn_attr else ""
            proxies = _list_attr(entry, "proxyAddresses")
            joined = " ".join([upn, *proxies]).lower()
            if "onmicrosoft.com" in joined or "#ext#" in joined:
                cloud_linked.append(
                    {"principal": sam, "signal": "CloudProxyOrUPN", "upn": upn[:120]}
                )
                signals.append({"principal": sam, "signal": "CloudProxyOrUPN", "dn": dn})

        conn.unbind()

        # Graph edges (observational only)
        entra_node = f"ENTRA@{target.domain.upper()}"
        graph.add_node(entra_node, "Cloud", name="EntraID", observational=True)
        for signal in signals[:200]:
            source = f"IDENTITY@{signal['principal'].upper()}@{target.domain.upper()}"
            graph.add_node(
                source,
                "Base",
                sam=signal["principal"],
                hybrid_signal=signal["signal"],
            )
            graph.add_edge(
                source,
                entra_node,
                "PossibleEntraPivot",
                signal=signal["signal"],
            )

        # Posture summary for operators
        posture = {
            "azure_ad_connect_hint": any(s["signal"] == "Azure AD Connect" for s in signals),
            "pta_hint": any(s["signal"] == "PTA" for s in signals),
            "phs_hint": any(s["signal"] == "PHS" for s in signals),
            "seamless_sso_hint": any(s["signal"] == "Seamless SSO" for s in signals),
            "cloud_linked_principals": len(cloud_linked),
            "synced_or_exchange_hybrid": len(synced_accounts),
            "infra_principals": len(infra_principals),
        }

        result: dict[str, Any] = {
            "domain": target.domain,
            "signals": signals[:500],
            "count": len(signals),
            "posture": posture,
            "cloud_linked_sample": cloud_linked[:50],
            "synced_sample": synced_accounts[:50],
            "infra_sample": infra_principals[:20],
            "note": (
                "Read-only on-prem signals only. No Entra Graph calls are made. "
                "Treat markers as review paths, not confirmed cloud compromise."
            ),
        }
        session.path("hybrid-signals.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        graph.save(session.path("graph.json"))
        session.log(
            "hybrid-signals.complete",
            count=len(signals),
            cloud_linked=len(cloud_linked),
            infra=len(infra_principals),
        )
        return result
