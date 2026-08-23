"""Shared LDAP lookup, mutation, evidence, and force-gate helpers."""

from __future__ import annotations

import json
from typing import Any

from ldap3 import SUBTREE, Connection, Server
from ldap3.utils.conv import escape_filter_chars

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def require_force(capability_id: str, force: bool) -> None:
    if not force:
        raise RuntimeError(f"{capability_id} is destructive and requires --force")


def require_param(kwargs: dict[str, Any], *names: str) -> str:
    for name in names:
        value = kwargs.get(name)
        if value:
            return str(value)
    joined = ", ".join(names)
    raise RuntimeError(f"Missing required parameter: {joined}")


def sam_variants(sam: str) -> list[str]:
    text = sam.strip()
    if not text:
        return []
    variants = [text]
    if text.endswith("$"):
        variants.append(text[:-1])
    else:
        variants.append(text + "$")
    return list(dict.fromkeys(variants))


def ldap_filter_value(value: Any) -> str:
    """Escape an untrusted scalar before placing it in an LDAP filter."""
    return str(escape_filter_chars(str(value)))


def attr_value(entry: Any, name: str) -> Any:
    if entry is None:
        return None
    attr = getattr(entry, name, None)
    if attr is None and "-" in name:
        attr = getattr(entry, name.replace("-", "_"), None)
    if attr is None and hasattr(entry, "__getitem__"):
        try:
            attr = entry[name]
        except Exception:
            attr = None
    if attr is None:
        return None
    if hasattr(attr, "value"):
        return attr.value
    return attr


def attr_values(entry: Any, name: str) -> list[Any]:
    raw = attr_value(entry, name)
    if raw is None:
        attr = getattr(entry, name, None)
        if attr is not None and hasattr(attr, "values") and attr.values:
            raw = list(attr.values)
        elif attr is not None and hasattr(attr, "raw_values") and attr.raw_values:
            raw = list(attr.raw_values)
    if raw is None:
        return []
    if isinstance(raw, list | tuple):
        return list(raw)
    return [raw]


def attr_strings(entry: Any, name: str) -> list[str]:
    return [str(item) for item in attr_values(entry, name) if item is not None]


def distinguished_name(entry: Any) -> str:
    value = attr_value(entry, "distinguishedName")
    if value:
        return str(value)
    dn = getattr(entry, "entry_dn", None)
    return str(dn) if dn else ""


def lookup_sam(
    conn: Any,
    base_dn: str,
    sam: str,
    attributes: list[str] | None = None,
) -> tuple[str, Any] | None:
    fields = attributes or [
        "sAMAccountName",
        "distinguishedName",
        "objectSid",
        "objectClass",
        "userAccountControl",
        "servicePrincipalName",
        "member",
        "msDS-AllowedToDelegateTo",
        "msDS-ManagedPassword",
        "msDS-ManagedAccountPrecededByLink",
    ]
    for candidate in sam_variants(sam):
        conn.search(
            base_dn,
            f"(sAMAccountName={ldap_filter_value(candidate)})",
            search_scope=SUBTREE,
            attributes=fields,
        )
        if conn.entries:
            entry = conn.entries[0]
            dn = distinguished_name(entry)
            if dn:
                return dn, entry
    return None


def encode_unicode_pwd(password: str) -> bytes:
    return f'"{password}"'.encode("utf-16-le")


def try_ntlm_bind(target: Target, username: str, password: str) -> tuple[bool, str]:
    server = Server(target.dc_ip, use_ssl=target.ldaps, get_info=None)
    user_dn = f"{target.domain}\\{username}"
    try:
        conn = Connection(
            server, user=user_dn, password=password, authentication="NTLM", auto_bind=True
        )
        conn.unbind()
        return True, "ok"
    except Exception as exc:
        return False, str(exc)[:200]


def write_evidence(session: Session, capability_id: str, result: dict[str, Any]) -> None:
    session.path(f"{capability_id}.json").write_text(
        json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8"
    )


def finish(
    session: Session,
    graph: AttackGraph,
    capability_id: str,
    result: dict[str, Any],
    **log: Any,
) -> dict[str, Any]:
    write_evidence(session, capability_id, result)
    graph.save(session.path("graph.json"))
    session.log(f"{capability_id}.complete", **log)
    return result


def register_attr_rollback(
    session: Session,
    *,
    target_dn: str,
    attribute: str,
    previous: list[Any],
    rollback: str,
) -> None:
    encoded: list[Any] = []
    encoding = "plain"
    for item in previous:
        if isinstance(item, bytes | bytearray):
            encoded.append(bytes(item).hex())
            encoding = "hex"
        else:
            encoded.append(item)
    session.register_cleanup(
        {
            "kind": "ldap-attribute",
            "target": target_dn,
            "attribute": attribute,
            "previous": encoded,
            "encoding": encoding,
            "rollback": rollback,
        }
    )


def register_add_value_rollback(
    session: Session,
    *,
    target_dn: str,
    attribute: str,
    values: list[Any],
    rollback: str,
) -> None:
    session.register_cleanup(
        {
            "kind": "ldap-add-value",
            "target": target_dn,
            "attribute": attribute,
            "values": [
                str(item) if not isinstance(item, bytes | bytearray) else item.hex()
                for item in values
            ],
            "encoding": "hex" if values and isinstance(values[0], bytes | bytearray) else "plain",
            "rollback": rollback,
        }
    )


def register_object_rollback(session: Session, *, target_dn: str, rollback: str) -> None:
    session.register_cleanup(
        {
            "kind": "ldap-object",
            "target": target_dn,
            "rollback": rollback,
        }
    )


def register_advisory_rollback(
    session: Session,
    *,
    kind: str,
    target: str,
    rollback: str,
) -> None:
    session.register_cleanup(
        {
            "kind": kind,
            "target": target,
            "rollback": rollback,
        }
    )
