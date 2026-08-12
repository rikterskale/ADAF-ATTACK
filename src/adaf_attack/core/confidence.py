"""Shared confidence scoring for exploit chains and next-actions.

Confidence levels are derived from observed graph evidence quality, not from
operational success.  They are intentionally conservative.
"""

from __future__ import annotations

from typing import Any

# Base confidence by terminal relation when only the edge itself is observed.
RELATION_BASE_CONFIDENCE: dict[str, str] = {
    # High — strong, well-understood signals
    "DCSync": "high",
    "GetChangesAll": "high",
    "GenericAll": "high",
    "WriteDacl": "high",
    "WriteOwner": "high",
    "ESC1Enrollable": "high",
    "ESC6": "high",
    "WriteKeyCredentialLink": "high",
    "WriteRBCD": "high",
    "AllowedToAct": "high",
    "ReadGMSAPassword": "high",
    "GMSAPasswordReadable": "high",
    "ReadLAPSPassword": "high",
    "LAPSReadable": "high",
    # Medium — useful but often needs corroboration
    "ESC1": "medium",
    "ESC2": "medium",
    "ESC3Agent": "medium",
    "ESC4": "medium",
    "ESC7": "medium",
    "ESC8WebEnrollment": "medium",
    "ESC9": "medium",
    "HasSPN": "medium",
    "CanASREP": "medium",
    "UnconstrainedDelegation": "medium",
    "AllowedToDelegate": "medium",
    "WriteGPO": "medium",
    "WriteSYSVOL": "medium",
    "HasKeyCredentialLink": "medium",
    "ForceChangePassword": "medium",
    "AddMember": "medium",
    "SpoolerOpen": "medium",
    "EfsrpcOpen": "medium",
    # Low — weak / candidate-only signals
    "ESC3RequiresRA": "low",
    "ESC10": "low",
    "ESC11": "low",
    "ESC13": "low",
    "TrustedBy": "low",
}

CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 0}


def confidence_for_relation(relation: str, *, profile: dict[str, Any] | None = None) -> str:
    """Return confidence label for a terminal relation."""
    if profile and profile.get("confidence"):
        return str(profile["confidence"])
    return RELATION_BASE_CONFIDENCE.get(relation, "unknown")


def boost_confidence(base: str, *, evidence_count: int = 0, has_enroll: bool = False) -> str:
    """Optionally raise confidence when corroborating evidence is present."""
    rank = CONFIDENCE_RANK.get(base, 0)
    if has_enroll and rank < 3:
        rank += 1
    if evidence_count >= 2 and rank < 3:
        rank += 1
    for label, value in CONFIDENCE_RANK.items():
        if value == rank:
            return label
    return base


def score_chain(
    *,
    terminal_relation: str,
    path_length: int,
    edge_kinds: list[str] | None = None,
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce a normalized confidence + ranking payload for one exploit chain."""
    base = confidence_for_relation(terminal_relation, profile=profile)
    kinds = edge_kinds or []
    has_enroll = any(k in {"Enroll", "AutoEnroll", "ESC1Enrollable"} for k in kinds)
    final = boost_confidence(base, evidence_count=len(kinds), has_enroll=has_enroll)

    # Lower numeric score = more interesting (matches existing graph ranking style)
    weight = {"high": 1.0, "medium": 2.0, "low": 3.5, "unknown": 5.0}.get(final, 5.0)
    numeric = weight + (0.15 * max(0, path_length - 1))

    return {
        "confidence": final,
        "confidence_rank": CONFIDENCE_RANK.get(final, 0),
        "numeric_score": round(numeric, 2),
        "terminal_relation": terminal_relation,
        "path_length": path_length,
    }
