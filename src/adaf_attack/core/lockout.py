"""PDC-emulator and PSO-aware lockout policy helpers for spray capabilities."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ldap3 import BASE, SUBTREE

from adaf_attack.core.ldap_ops import ldap_filter_value


def _ldap_attr(entry: Any, name: str) -> Any:
    """Return an LDAP attribute value without assuming ldap3 Entry layout."""
    attr: Any = None
    try:
        attr = entry[name]
    except Exception:
        attr = getattr(entry, name, None)
    if attr is None:
        return None
    try:
        if not attr:
            return None
    except Exception:
        pass
    return getattr(attr, "value", attr)


def filetime_to_dt(ft: int) -> datetime | None:
    if not ft or ft <= 0:
        return None
    return datetime.fromtimestamp(ft / 10_000_000 - 11644473600, tz=UTC)


def read_domain_lockout_policy(conn: Any, base_dn: str) -> dict[str, int]:
    conn.search(
        base_dn,
        "(objectClass=domainDNS)",
        search_scope=BASE,
        attributes=["lockoutThreshold", "lockoutObservationWindow", "minPwdLength"],
    )
    if not conn.entries or _ldap_attr(conn.entries[0], "lockoutThreshold") is None:
        conn.search(
            base_dn,
            "(objectClass=domain)",
            search_scope=SUBTREE,
            attributes=["lockoutThreshold", "lockoutObservationWindow", "minPwdLength"],
        )
    policy = {"lockout_threshold": 0, "observation_window_seconds": 0}
    if conn.entries:
        entry = conn.entries[0]
        threshold = _ldap_attr(entry, "lockoutThreshold")
        if threshold is not None:
            policy["lockout_threshold"] = int(threshold)
        window = _ldap_attr(entry, "lockoutObservationWindow")
        if window is not None:
            policy["observation_window_seconds"] = int(abs(int(window)) / 10_000_000)
    return policy


def locate_pdc_emulator(conn: Any, base_dn: str) -> str:
    """Return the PDC emulator DNS host name. Refuse when it cannot be determined."""
    conn.search(
        base_dn,
        "(objectClass=domainDNS)",
        search_scope=BASE,
        attributes=["fSMORoleOwner"],
    )
    role = _ldap_attr(conn.entries[0], "fSMORoleOwner") if conn.entries else None
    if not role:
        raise RuntimeError(
            "Unable to locate the PDC emulator (fSMORoleOwner). "
            "Password sprays must read badPwdCount from the PDC."
        )
    ntds_dn = str(role)
    server_dn = ntds_dn.split(",", 1)[1] if "," in ntds_dn else ntds_dn
    conn.search(server_dn, "(objectClass=*)", search_scope=BASE, attributes=["dNSHostName"])
    host = _ldap_attr(conn.entries[0], "dNSHostName") if conn.entries else None
    if host:
        return str(host)
    raise RuntimeError(
        "PDC emulator NTDS object has no dNSHostName; refusing lockout-sensitive spray."
    )


def domain_has_pso(conn: Any, base_dn: str) -> bool:
    conn.search(
        base_dn,
        "(objectClass=msDS-PasswordSettings)",
        search_scope=SUBTREE,
        attributes=["cn"],
        size_limit=1,
    )
    return bool(conn.entries)


def account_lockout_state(
    conn: Any, base_dn: str, sam: str, *, require_pso: bool
) -> tuple[int, datetime | None, int | None]:
    """Return (badPwdCount, badPasswordTime, pso_threshold)."""
    conn.search(
        base_dn,
        f"(sAMAccountName={ldap_filter_value(sam)})",
        search_scope=SUBTREE,
        attributes=["badPwdCount", "badPasswordTime", "msDS-ResultantPSO"],
    )
    if not conn.entries:
        raise RuntimeError(f"Account not found for lockout check: {sam}")
    entry = conn.entries[0]
    bad_raw = _ldap_attr(entry, "badPwdCount")
    bad = int(bad_raw) if bad_raw is not None else 0
    ts_raw = _ldap_attr(entry, "badPasswordTime")
    ts = filetime_to_dt(int(ts_raw)) if ts_raw is not None else None
    pso_threshold: int | None = None
    pso_dn = _ldap_attr(entry, "msDS-ResultantPSO")
    if pso_dn is not None:
        pso_dn = str(pso_dn)
    if require_pso and not pso_dn:
        raise RuntimeError(
            f"Fine-grained password policy exists but msDS-ResultantPSO is unreadable for {sam}"
        )
    if pso_dn:
        conn.search(
            pso_dn,
            "(objectClass=*)",
            search_scope=BASE,
            attributes=["msDS-LockoutThreshold"],
        )
        pso_lockout = _ldap_attr(conn.entries[0], "msDS-LockoutThreshold") if conn.entries else None
        if pso_lockout is None:
            raise RuntimeError(f"Unable to read PSO lockoutThreshold for {sam}")
        pso_threshold = int(pso_lockout)
    return bad, ts, pso_threshold


def effective_lockout_threshold(domain_threshold: int, pso_threshold: int | None) -> int:
    if pso_threshold is None:
        return domain_threshold
    if pso_threshold <= 0:
        return pso_threshold
    if domain_threshold <= 0:
        return pso_threshold
    return min(domain_threshold, pso_threshold)
