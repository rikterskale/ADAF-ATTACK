"""AS-REQ username validator.

Sends a Kerberos AS-REQ per candidate and classifies the KDC error to
determine whether the account exists — without incrementing badPwdCount.
Valid users return KDC_ERR_PREAUTH_REQUIRED (or KDC_ERR_ETYPE_NOSUPP);
unknown users return KDC_ERR_C_PRINCIPAL_UNKNOWN. AS-REP roastable users
(no pre-auth) return an AS-REP directly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.impacket_helper import require_impacket
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

_CODE_MAP = {
    "KDC_ERR_C_PRINCIPAL_UNKNOWN": ("unknown", False),
    "KDC_ERR_PREAUTH_REQUIRED": ("valid", True),
    "KDC_ERR_PREAUTH_FAILED": ("valid", True),
    "KDC_ERR_CLIENT_REVOKED": ("locked_or_disabled", True),
    "KDC_ERR_ETYPE_NOSUPP": ("valid", True),
    "KDC_ERR_WRONG_REALM": ("valid", True),
}


def _classify_kdc_error(text: str) -> tuple[str, bool, str | None]:
    for code, (state, valid) in _CODE_MAP.items():
        if code in text:
            return state, valid, code
    return "error", False, None


def _probe_user(username: str, domain: str, dc_ip: str) -> dict[str, Any]:
    """Attempt an AS-REQ; interpret KDC error / AS-REP to classify the user."""
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT
    from impacket.krb5.types import Principal

    principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    try:
        # Empty password + empty hashes triggers a pre-auth-less AS-REQ.
        tgt, _cipher, _old, _sk = getKerberosTGT(principal, "", domain.upper(), "", "", "", dc_ip)
    except KerberosError as exc:
        state, valid, code = _classify_kdc_error(str(exc))
        record: dict[str, Any] = {
            "user": username,
            "state": state,
            "valid": valid,
        }
        if code:
            record["kdc_error"] = code
        else:
            record["kdc_error"] = str(exc)[:200]
        return record
    except Exception as exc:
        state, valid, code = _classify_kdc_error(str(exc))
        return {
            "user": username,
            "state": state,
            "valid": valid,
            "kdc_error": code or str(exc)[:200],
        }
    # AS-REQ succeeded → account has no pre-auth → AS-REP roastable.
    return {
        "user": username,
        "state": "asreproastable",
        "valid": True,
        "no_preauth": True,
        "as_rep_bytes": len(bytes(tgt)) if tgt is not None else 0,
    }


@register_capability(
    id="asreq-userhunt",
    summary="Validate usernames via Kerberos AS-REQ without incrementing badPwdCount",
    category="enumeration",
    tags=("kerberos", "as-req", "user-enum", "asrep-roast"),
    auth_modes=("anonymous",),
    requires_username_list=True,
    noise_level="low",
    data_sensitivity="directory-metadata",
)
class AsreqUserhunt:
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
        require_impacket("asreq-userhunt")
        userlist_path = kwargs.get("users") or kwargs.get("userlist")
        if not userlist_path:
            raise RuntimeError("Pass -P users=<path-to-user-list>.")
        path = Path(str(userlist_path)).expanduser()
        if not path.is_file():
            raise RuntimeError(f"user list not found: {path}")
        candidates = [
            line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
        ]

        console.print(f"[bold]AS-REQ user hunt[/bold]  candidates={len(candidates)}")

        results: list[dict[str, Any]] = []
        for user in candidates:
            record = _probe_user(user, target.domain, target.dc_ip)
            results.append(record)
            state = record.get("state", "?")
            color = "green" if record.get("valid") else "dim"
            console.print(f"  [{color}]{state:>18}[/{color}]  {user}")
            if record.get("valid"):
                node = f"USER@{user.upper()}@{target.domain.upper()}"
                graph.add_node(node, "User", sam=user, source="asreq")
                graph.add_edge(node, node, "AsReqValid")
                if record.get("no_preauth"):
                    graph.add_edge(node, node, "AsRepRoastable")

        valid = [r for r in results if r.get("valid")]
        asreproastable = [r for r in results if r.get("no_preauth")]
        payload = {
            "domain": target.domain,
            "count": len(results),
            "valid": len(valid),
            "asreproastable": len(asreproastable),
            "entries": results,
        }
        out = session.path("asreq-userhunt.json")
        out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "asreq-userhunt.complete",
            count=len(results),
            valid=len(valid),
        )
        console.print(
            f"[green]Done[/green]  valid={len(valid)}  asreproastable={len(asreproastable)}"
        )
        return payload
