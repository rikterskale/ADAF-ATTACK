"""Plain-language safety and guidance used by the novice operator experience."""

from __future__ import annotations

from typing import Any

from adaf_attack.core.registry import Capability

_GLOSSARY = {
    "kerberoast": "A request for service-account tickets that can be checked offline for weak passwords.",
    "dcsync": "A replication request that can expose password material; use only with explicit approval.",
    "rbcd": "A delegation setting that can let one computer act on behalf of a user to another service.",
    "spn": "A service name in Active Directory that tells Kerberos where a service is running.",
    "tgt": "A Kerberos Ticket Granting Ticket, used to request service tickets.",
}


def safety_summary(cap: Capability) -> dict[str, str | bool]:
    """Return independent safety facts rather than a misleading single color."""
    network = cap.category not in {"analysis", "export"}
    if cap.destructive:
        level, plain = "RED", "Can change a target when its write options are used."
    elif network:
        level, plain = (
            "YELLOW",
            "Reads information from an authorized target and contacts the network.",
        )
    else:
        level, plain = "GREEN", "Works from saved evidence and does not contact a target."
    return {"level": level, "network": network, "plain": plain}


def plain_description(cap: Capability) -> str:
    safety = safety_summary(cap)
    return f"{cap.summary}. {safety['plain']}"


def beginner_next_actions(cap: Capability) -> list[dict[str, str]]:
    from adaf_attack.core.ux import suggested_next_actions

    actions: list[dict[str, str]] = []
    for capability_id in suggested_next_actions(cap, limit=3):
        actions.append(
            {
                "id": capability_id,
                "message": f"Next, review {capability_id} to build on the evidence you just collected.",
            }
        )
    return actions


def explain_finding(finding: dict[str, Any]) -> str:
    title = str(finding.get("title") or finding.get("id") or "This finding")
    severity = str(finding.get("severity") or "unknown").lower()
    return f"{title} is rated {severity}. Review its evidence and remediation before making any change."


def glossary_definition(term: str) -> str | None:
    return _GLOSSARY.get(term.strip().lower())
