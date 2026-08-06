"""Canonical, report-safe findings derived from persisted session evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Evidence:
    artifact: str
    pointer: str = "/"
    sha256: str = ""


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    confidence: str
    impact: str
    remediation: str
    evidence: tuple[Evidence, ...]
    attack_techniques: tuple[str, ...] = ()
    affected_assets: tuple[str, ...] = ()
    control_mappings: tuple[str, ...] = ()
    source_capability: str = ""

    def document(self) -> dict[str, Any]:
        return asdict(self)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _evidence(path: Path, pointer: str = "/") -> tuple[Evidence, ...]:
    return (Evidence(path.name, pointer, _digest(path)),)


def _load(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _finding(
    code: str, title: str, severity: str, impact: str, remediation: str, path: Path, *,
    pointer: str = "/", techniques: tuple[str, ...] = (), assets: tuple[str, ...] = (),
    capability: str = "",
) -> Finding:
    return Finding(
        id=code, title=title, severity=severity, confidence="observed", impact=impact,
        remediation=remediation, evidence=_evidence(path, pointer), attack_techniques=techniques,
        affected_assets=assets, source_capability=capability,
    )


def findings_from_session(session: Path) -> list[Finding]:
    """Create deterministic findings from known artifact shapes; never expose secrets."""
    findings: list[Finding] = []
    rules = [
        ("kerberoast.json", "ADAF-KERB-001", "Kerberoastable service accounts", "high", "Credential cracking could enable lateral movement.", "Use strong service-account passwords and managed service accounts.", ("T1558.003",), "kerberoast"),
        ("asrep-roast.json", "ADAF-ASREP-001", "AS-REP roastable accounts", "high", "Offline password cracking may expose account credentials.", "Require Kerberos pre-authentication and reset affected passwords.", ("T1558.004",), "asrep-roast"),
        ("rbcd.json", "ADAF-RBCD-001", "Resource-based constrained delegation exposure", "high", "Delegation control may enable service impersonation.", "Remove unneeded delegation entries and restrict write permissions.", ("T1134.001",), "rbcd"),
        ("shadow-creds.json", "ADAF-SHADOW-001", "Shadow credential write exposure", "high", "Writable KeyCredentialLink can enable persistent account access.", "Restrict write access and review registered key credentials.", ("T1098",), "shadow-creds"),
        ("gpo-abuse.json", "ADAF-GPO-001", "Group Policy modification exposure", "high", "GPO control can distribute attacker-controlled configuration.", "Limit GPO edit rights and review linked policy ACLs.", ("T1484.001",), "gpo-abuse"),
    ]
    for name, code, title, severity, impact, remediation, techniques, capability in rules:
        path = session / name
        data = _load(path)
        if data:
            findings.append(_finding(code, title, severity, impact, remediation, path, techniques=techniques, capability=capability))

    adcs = session / "adcs-enum.json"
    data = _load(adcs) or {}
    for key, technique in (("esc1_candidates", "T1649"), ("esc2_candidates", "T1649"), ("esc4_acl_templates", "T1222.001")):
        candidates = data.get(key) or []
        if candidates:
            findings.append(_finding(f"ADAF-ADCS-{key.upper().replace('_', '-')}", f"AD CS {key.replace('_', ' ')}", "critical", "Certificate services misconfiguration may enable domain privilege escalation.", "Restrict enrollment and template modification permissions; validate certificate template settings.", adcs, pointer=f"/{key}", techniques=(technique,), assets=tuple(str(x) for x in candidates[:20]), capability="adcs-enum"))
    for key in ("esc9_candidates", "esc10_candidates", "esc11_candidates", "esc13_candidates"):
        candidates = data.get(key) or []
        if candidates:
            findings.append(_finding(f"ADAF-ADCS-{key.upper().replace('_', '-')}", f"AD CS {key.replace('_', ' ')}", "high", "Certificate mapping or enrollment policy may permit unintended authentication.", "Validate the affected CA and template configuration against the current AD CS hardening baseline.", adcs, pointer=f"/{key}", techniques=("T1649",), assets=tuple(str(x) for x in candidates[:20]), capability="adcs-enum"))

    acl = session / "acl-enum.json"
    data = _load(acl) or {}
    principals = data.get("dcsync_principals") or []
    if principals:
        findings.append(_finding("ADAF-ACL-DCSYNC-001", "Directory replication rights assigned", "critical", "Directory replication rights can expose directory credential material.", "Remove unnecessary replication rights and investigate the assigned principals.", acl, pointer="/dcsync_principals", techniques=("T1003.006",), assets=tuple(str(x) for x in principals[:20]), capability="acl-enum"))
    return sorted(findings, key=lambda item: (item.severity, item.id))


def write_findings(session: Path, findings: list[Finding]) -> Path:
    path = session / "findings.json"
    path.write_text(json.dumps([item.document() for item in findings], indent=2) + "\n", encoding="utf-8")
    return path
