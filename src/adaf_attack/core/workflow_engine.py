"""Finding-driven workflow state machine for guided assessments.

The engine is deliberately transport-agnostic: the TUI, CLI, and automated
operators can all submit the same finding and decision events. State is stored
as redacted JSON so a workflow can be resumed, audited, queried, or handed off
without carrying credential material.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

FindingStatus = Literal["open", "validated", "exploited", "mitigated", "closed"]
WorkflowMode = Literal["interactive", "automated", "agent"]

PHASES: tuple[str, ...] = (
    "scoping",
    "discovery",
    "validation",
    "prioritization",
    "response",
    "verification",
    "reporting",
    "closure",
)

SEVERITY_WEIGHT = {"critical": 100, "high": 75, "medium": 45, "low": 20, "info": 5}
CONFIDENCE_WEIGHT = {"confirmed": 1.0, "observed": 0.85, "suspected": 0.6, "unknown": 0.4}
STATUS_ORDER: dict[FindingStatus, int] = {
    "open": 0,
    "validated": 1,
    "exploited": 2,
    "mitigated": 3,
    "closed": 4,
}


class WorkflowError(ValueError):
    """Raised for invalid workflow transitions or malformed persisted state."""


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


@dataclass
class FindingRecord:
    """First-class finding that can drive workflow state and recommendations."""

    id: str
    title: str
    severity: str = "info"
    confidence: str = "unknown"
    status: FindingStatus = "open"
    impact: str = ""
    remediation: str = ""
    source: str = "operator"
    evidence: list[dict[str, Any]] = field(default_factory=list)
    affected_assets: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)
    priority: float = 0.0
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def normalize(self) -> None:
        self.severity = self.severity.lower().strip() or "info"
        self.confidence = self.confidence.lower().strip() or "unknown"
        if self.severity not in SEVERITY_WEIGHT:
            self.severity = "info"
        if self.confidence not in CONFIDENCE_WEIGHT:
            self.confidence = "unknown"
        self.priority = round(
            SEVERITY_WEIGHT[self.severity] * CONFIDENCE_WEIGHT[self.confidence]
            + min(len(self.affected_assets), 20) * 2,
            2,
        )
        self.updated_at = _now()


@dataclass
class WorkflowAction:
    """Recommended or mandatory operator action derived from state/findings."""

    id: str
    title: str
    description: str
    phase: str
    kind: Literal["required", "recommended", "decision"] = "recommended"
    finding_ids: list[str] = field(default_factory=list)
    capability_id: str | None = None
    consequence: str = ""
    completed: bool = False
    blocked: bool = False
    created_at: str = field(default_factory=_now)
    completed_at: str | None = None


@dataclass
class AuditEvent:
    event_id: str
    event_type: str
    timestamp: str
    actor: str
    summary: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowState:
    """Complete persisted state for one guided workflow."""

    workflow_id: str
    title: str
    mode: WorkflowMode = "interactive"
    phase: str = "scoping"
    status: Literal["active", "blocked", "complete", "archived"] = "active"
    completed_steps: list[str] = field(default_factory=list)
    findings: dict[str, FindingRecord] = field(default_factory=dict)
    pending_actions: dict[str, WorkflowAction] = field(default_factory=dict)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    audit_log: list[AuditEvent] = field(default_factory=list)
    progress: float = 0.0
    risk_score: float = 0.0
    revision: int = 0
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    @property
    def open_findings(self) -> list[FindingRecord]:
        return [finding for finding in self.findings.values() if finding.status != "closed"]

    def document(self) -> dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "title": self.title,
            "mode": self.mode,
            "phase": self.phase,
            "status": self.status,
            "completed_steps": self.completed_steps,
            "findings": {key: asdict(value) for key, value in self.findings.items()},
            "pending_actions": {key: asdict(value) for key, value in self.pending_actions.items()},
            "decisions": self.decisions,
            "audit_log": [asdict(event) for event in self.audit_log],
            "progress": self.progress,
            "risk_score": self.risk_score,
            "revision": self.revision,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class WorkflowGuidance:
    """Small, transport-neutral view for a guided client."""

    phase: str
    status: str
    progress: float
    risk_score: float
    open_finding_ids: tuple[str, ...]
    blockers: tuple[str, ...]
    next_action_id: str | None
    explanation: str

    def document(self) -> dict[str, Any]:
        return asdict(self)


class WorkflowEngine:
    """Durable finding-driven state machine.

    ``ingest_finding`` is the main integration point for scanners, sessions,
    humans, and agents. Every mutation recalculates priorities, branches, and
    progress, then appends an audit event and atomically persists state.
    """

    STATE_FILE = "workflow-state.json"

    def __init__(
        self,
        workspace: Path,
        *,
        title: str = "ADAF-ATTACK guided assessment",
        workflow_id: str | None = None,
        mode: WorkflowMode = "interactive",
    ) -> None:
        self.workspace = Path(workspace)
        self.path = self.workspace / self.STATE_FILE
        self.state = self._load_or_new(title=title, workflow_id=workflow_id, mode=mode)

    @classmethod
    def from_state(cls, workspace: Path, payload: dict[str, Any]) -> WorkflowEngine:
        engine = cls(workspace, title=str(payload.get("title", "guided assessment")))
        engine.state = cls._decode_state(payload)
        engine._recalculate(persist=False)
        return engine

    def _load_or_new(
        self, *, title: str, workflow_id: str | None, mode: WorkflowMode
    ) -> WorkflowState:
        if self.path.exists():
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeError) as exc:
                raise WorkflowError(f"Invalid persisted workflow state: {exc}") from exc
            if not isinstance(payload, dict):
                raise WorkflowError("Invalid persisted workflow state: expected an object")
            return self._decode_state(payload)
        return WorkflowState(workflow_id or _id("WF"), title, mode=mode)

    @staticmethod
    def _decode_state(payload: dict[str, Any]) -> WorkflowState:
        try:
            findings = {
                key: FindingRecord(**value)
                for key, value in (payload.get("findings") or {}).items()
            }
            actions = {
                key: WorkflowAction(**value)
                for key, value in (payload.get("pending_actions") or {}).items()
            }
            audit = [AuditEvent(**value) for value in (payload.get("audit_log") or [])]
            mode = payload.get("mode", "interactive")
            status = payload.get("status", "active")
            if mode not in {"interactive", "automated", "agent"}:
                raise WorkflowError(f"Unknown workflow mode: {mode}")
            if status not in {"active", "blocked", "complete", "archived"}:
                raise WorkflowError(f"Unknown workflow status: {status}")
            state = WorkflowState(
                workflow_id=str(payload["workflow_id"]),
                title=str(payload.get("title", "guided assessment")),
                mode=mode,
                phase=str(payload.get("phase", "scoping")),
                status=status,
                completed_steps=list(payload.get("completed_steps") or []),
                findings=findings,
                pending_actions=actions,
                decisions=list(payload.get("decisions") or []),
                audit_log=audit,
                progress=float(payload.get("progress", 0.0)),
                risk_score=float(payload.get("risk_score", 0.0)),
                revision=int(payload.get("revision", 0)),
                created_at=str(payload.get("created_at", _now())),
                updated_at=str(payload.get("updated_at", _now())),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkflowError(f"Invalid workflow state: {exc}") from exc
        if state.phase not in PHASES:
            raise WorkflowError(f"Unknown workflow phase: {state.phase}")
        for finding in state.findings.values():
            if finding.status not in STATUS_ORDER:
                raise WorkflowError(f"Unknown finding status: {finding.status}")
        for action in state.pending_actions.values():
            if action.phase not in PHASES:
                raise WorkflowError(f"Unknown action phase: {action.phase}")
            if action.kind not in {"required", "recommended", "decision"}:
                raise WorkflowError(f"Unknown action kind: {action.kind}")
        return state

    def persist(self) -> Path:
        self.workspace.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.state.document(), indent=2, sort_keys=True) + "\n"
        fd, temporary = tempfile.mkstemp(prefix="workflow-", suffix=".tmp", dir=self.workspace)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except OSError:
            with suppress(OSError):
                Path(temporary).unlink(missing_ok=True)
            raise
        return self.path

    def _event(self, event_type: str, summary: str, *, actor: str, **payload: Any) -> None:
        self.state.audit_log.append(
            AuditEvent(_id("EV"), event_type, _now(), actor, summary, payload)
        )
        self.state.revision += 1
        self.state.updated_at = _now()

    def _ensure_mutable(self) -> None:
        if self.state.status in {"complete", "archived"}:
            raise WorkflowError("Workflow is already closed")

    def _recalculate(self, *, persist: bool = True) -> None:
        for finding in self.state.findings.values():
            finding.normalize()
        self.state.risk_score = round(
            min(100.0, sum(finding.priority for finding in self.state.open_findings)), 2
        )
        self._rebuild_actions()
        completed = len(self.state.completed_steps)
        finding_count = len(self.state.findings)
        closed = sum(finding.status == "closed" for finding in self.state.findings.values())
        phase_progress = PHASES.index(self.state.phase) / len(PHASES) * 100
        finding_progress = 0 if not finding_count else (closed / finding_count) * 10
        self.state.progress = round(
            min(100.0, phase_progress + finding_progress + min(completed, 8) * 2.5), 2
        )
        if self.state.status == "active" and self._required_actions():
            self.state.status = "blocked"
        elif self.state.status == "blocked" and not self._required_actions():
            self.state.status = "active"
        if persist:
            self.persist()

    def _required_actions(self) -> list[WorkflowAction]:
        return [
            action
            for action in self.state.pending_actions.values()
            if action.kind == "required" and not action.completed and not action.blocked
        ]

    def _rebuild_actions(self) -> None:
        existing = self.state.pending_actions
        actions: dict[str, WorkflowAction] = {
            key: action for key, action in existing.items() if action.completed
        }
        if "scope-authorized" not in self.state.completed_steps:
            actions["authorize-scope"] = WorkflowAction(
                "authorize-scope",
                "Confirm scope and authorization",
                "Record the approved target scope before collection.",
                "scoping",
                "required",
                consequence="Without authorization, all network actions remain locked.",
            )
        elif not self.state.findings and "discovery-complete" not in self.state.completed_steps:
            actions["run-discovery"] = WorkflowAction(
                "run-discovery",
                "Run baseline discovery",
                "Collect enough read-only evidence to establish the attack surface.",
                "discovery",
                "required",
                capability_id="ldap-enum",
                consequence="No finding-driven branches are available until discovery completes.",
            )
        for finding in self.state.findings.values():
            if finding.status == "open":
                key = f"validate:{finding.id}"
                actions[key] = WorkflowAction(
                    key,
                    f"Validate: {finding.title}",
                    "Confirm evidence, scope, and confidence before selecting a response.",
                    "validation",
                    "required",
                    [finding.id],
                    consequence="Response and closure remain locked until this finding is validated.",
                )
            elif finding.status == "validated":
                key = f"decision:{finding.id}"
                decision_recorded = any(
                    item.get("action_id") == key for item in self.state.decisions
                )
                if not decision_recorded:
                    actions[key] = WorkflowAction(
                        key,
                        f"Choose response for: {finding.title}",
                        "Choose whether to confirm impact, mitigate, or formally accept the risk.",
                        "prioritization",
                        "decision",
                        [finding.id],
                        consequence="The workflow cannot move to reporting until a response decision is recorded.",
                    )
                else:
                    response_key = f"response:{finding.id}"
                    actions[response_key] = WorkflowAction(
                        response_key,
                        f"Record response: {finding.title}",
                        "Apply remediation or record a documented risk acceptance before verification.",
                        "response",
                        "required",
                        [finding.id],
                        consequence="The finding must be mitigated before verification and closure.",
                    )
            elif finding.status == "exploited":
                key = f"mitigate:{finding.id}"
                actions[key] = WorkflowAction(
                    key,
                    f"Mitigate: {finding.title}",
                    "Apply or document remediation for the validated impact.",
                    "response",
                    "required",
                    [finding.id],
                    consequence="Verification cannot begin until the finding is mitigated.",
                )
            elif finding.status == "mitigated":
                key = f"verify:{finding.id}"
                actions[key] = WorkflowAction(
                    key,
                    f"Verify mitigation: {finding.title}",
                    "Collect or attach evidence that the remediation is effective.",
                    "verification",
                    "required",
                    [finding.id],
                    consequence="The finding cannot be closed without verification evidence.",
                )
        if (
            (
                not self.state.findings
                or all(item.status == "closed" for item in self.state.findings.values())
            )
            and not self._required_actions()
            and self.state.phase in {"validation", "prioritization", "response", "verification"}
        ):
            actions["generate-report"] = WorkflowAction(
                "generate-report",
                "Generate final reports",
                "Create executive, technical, and remediation outputs from the closed evidence set.",
                "reporting",
                "required",
                capability_id="report",
            )
        for key, prior in existing.items():
            if prior.completed and key in actions:
                actions[key] = prior
        self.state.pending_actions = actions

    def start(self, *, actor: str = "operator") -> WorkflowState:
        self._ensure_mutable()
        self._event("workflow.started", "Guided workflow started", actor=actor)
        self._recalculate()
        return self.state

    def complete_step(
        self, step: str, *, actor: str = "operator", phase: str | None = None
    ) -> WorkflowState:
        self._ensure_mutable()
        if not step.strip():
            raise WorkflowError("Step name cannot be empty")
        if step not in self.state.completed_steps:
            self.state.completed_steps.append(step)
        if phase:
            if phase not in PHASES:
                raise WorkflowError(f"Unknown workflow phase: {phase}")
            self.state.phase = phase
        self._event(
            "step.completed",
            f"Completed workflow step: {step}",
            actor=actor,
            step=step,
            phase=self.state.phase,
        )
        self._recalculate()
        return self.state

    def ingest_finding(
        self,
        finding: FindingRecord | dict[str, Any],
        *,
        actor: str = "system",
        override: bool = False,
    ) -> FindingRecord:
        self._ensure_mutable()
        record = finding if isinstance(finding, FindingRecord) else FindingRecord(**finding)
        if not record.id.strip() or not record.title.strip():
            raise WorkflowError("Finding id and title are required")
        if record.status not in STATUS_ORDER:
            raise WorkflowError(f"Unknown finding status: {record.status}")
        record.normalize()
        prior = self.state.findings.get(record.id)
        if prior and not override:
            record.created_at = prior.created_at
            record.related_findings = sorted(set(prior.related_findings + record.related_findings))
        self.state.findings[record.id] = record
        self._event(
            "finding.ingested",
            f"Finding ingested: {record.title}",
            actor=actor,
            finding_id=record.id,
            override=override,
        )
        self._recalculate()
        return record

    def inject_finding(
        self, title: str, *, actor: str = "operator", **fields: Any
    ) -> FindingRecord:
        record = FindingRecord(
            id=fields.pop("id", _id("FND")), title=title, source="operator", **fields
        )
        return self.ingest_finding(record, actor=actor, override=True)

    def enrich_finding(
        self, finding_id: str, *, actor: str = "system", **updates: Any
    ) -> FindingRecord:
        self._ensure_mutable()
        record = self._finding(finding_id)
        for key, value in updates.items():
            if not hasattr(record, key) or key in {"id", "created_at", "updated_at"}:
                raise WorkflowError(f"Finding field cannot be enriched: {key}")
            setattr(record, key, value)
        record.normalize()
        self._event(
            "finding.enriched",
            f"Finding enriched: {record.title}",
            actor=actor,
            finding_id=finding_id,
            fields=list(updates),
        )
        self._recalculate()
        return record

    def correlate(
        self, finding_ids: Iterable[str], *, actor: str = "system", relation: str = "related"
    ) -> None:
        self._ensure_mutable()
        ids = list(dict.fromkeys(finding_ids))
        for finding_id in ids:
            self._finding(finding_id)
        for finding_id in ids:
            record = self.state.findings[finding_id]
            record.related_findings = sorted(
                set(record.related_findings + [item for item in ids if item != finding_id])
            )
            record.tags = sorted(set(record.tags + [relation]))
            record.updated_at = _now()
        self._event(
            "findings.correlated",
            f"Correlated {len(ids)} findings",
            actor=actor,
            finding_ids=ids,
            relation=relation,
        )
        self._recalculate()

    def transition_finding(
        self,
        finding_id: str,
        status: FindingStatus,
        *,
        actor: str = "operator",
        evidence: dict[str, Any] | None = None,
    ) -> FindingRecord:
        self._ensure_mutable()
        record = self._finding(finding_id)
        if status not in STATUS_ORDER:
            raise WorkflowError(f"Unknown finding status: {status}")
        current = STATUS_ORDER[record.status]
        target = STATUS_ORDER[status]
        if target < current or target > current + 1:
            raise WorkflowError(f"Invalid finding transition: {record.status} -> {status}")
        if status != "open" and "scope-authorized" not in self.state.completed_steps:
            raise WorkflowError("Finding validation requires authorized scope")
        if status == "closed" and not evidence and not record.evidence:
            raise WorkflowError("Closing a finding requires verification evidence")
        record.status = status
        if evidence:
            record.evidence.append(evidence)
        record.updated_at = _now()
        phase_for_status = {
            "validated": "validation",
            "exploited": "prioritization",
            "mitigated": "response",
            "closed": "verification",
        }
        if status in phase_for_status:
            self.state.phase = phase_for_status[status]
        self._event(
            "finding.status_changed",
            f"{record.id}: {status}",
            actor=actor,
            finding_id=finding_id,
            status=status,
        )
        self._recalculate()
        return record

    def decide(
        self, action_id: str, decision: str, *, actor: str = "operator", rationale: str = ""
    ) -> WorkflowState:
        self._ensure_mutable()
        action = self.state.pending_actions.get(action_id)
        if not action:
            raise WorkflowError(f"Unknown workflow action: {action_id}")
        if action.kind != "decision":
            raise WorkflowError(f"Action is not a decision point: {action_id}")
        if not decision.strip():
            raise WorkflowError("Decision cannot be empty")
        self.state.decisions.append(
            {
                "action_id": action_id,
                "decision": decision,
                "rationale": rationale,
                "actor": actor,
                "timestamp": _now(),
            }
        )
        action.completed = True
        action.completed_at = _now()
        self._event(
            "decision.recorded",
            f"Decision recorded: {decision}",
            actor=actor,
            action_id=action_id,
            decision=decision,
            rationale=rationale,
        )
        self._recalculate()
        return self.state

    def complete_action(self, action_id: str, *, actor: str = "operator") -> WorkflowState:
        self._ensure_mutable()
        action = self.state.pending_actions.get(action_id)
        if not action:
            raise WorkflowError(f"Unknown workflow action: {action_id}")
        if action.blocked:
            raise WorkflowError(f"Action is blocked: {action_id}")
        if action.kind == "decision":
            raise WorkflowError(f"Decision action requires decide(): {action_id}")
        action.completed = True
        action.completed_at = _now()
        if action_id == "authorize-scope":
            self.complete_step("scope-authorized", actor=actor, phase="discovery")
            return self.state
        if action_id == "run-discovery":
            self.complete_step("discovery-complete", actor=actor, phase="validation")
            return self.state
        if action_id.startswith("validate:"):
            finding_id = action_id.split(":", 1)[1]
            self.transition_finding(finding_id, "validated", actor=actor)
            return self.state
        if action_id.startswith("mitigate:"):
            finding_id = action_id.split(":", 1)[1]
            self.transition_finding(
                finding_id,
                "mitigated",
                actor=actor,
                evidence={"action_id": action_id, "type": "operator-remediation"},
            )
            return self.state
        if action_id.startswith("response:"):
            finding_id = action_id.split(":", 1)[1]
            # Preserve the explicit lifecycle even when the operator chose a
            # direct mitigation response instead of a separate impact test.
            self.transition_finding(finding_id, "exploited", actor=actor)
            self.transition_finding(
                finding_id,
                "mitigated",
                actor=actor,
                evidence={"action_id": action_id, "type": "operator-response"},
            )
            return self.state
        if action_id.startswith("verify:"):
            finding_id = action_id.split(":", 1)[1]
            record = self._finding(finding_id)
            record.evidence.append({"action_id": action_id, "type": "verification"})
            record.updated_at = _now()
            self.state.phase = "verification"
            self._event(
                "finding.verification_recorded",
                f"Verification recorded: {record.title}",
                actor=actor,
                finding_id=finding_id,
                action_id=action_id,
            )
            self._recalculate()
            return self.state
        if action_id == "generate-report":
            self._event(
                "action.completed",
                f"Action completed: {action.title}",
                actor=actor,
                action_id=action_id,
            )
            self.complete_step("report-generated", actor=actor, phase="reporting")
            return self.state
        self._event(
            "action.completed",
            f"Action completed: {action.title}",
            actor=actor,
            action_id=action_id,
        )
        self._recalculate()
        return self.state

    def recommendations(self, *, limit: int = 5) -> list[WorkflowAction]:
        actions = [
            action
            for action in self.state.pending_actions.values()
            if not action.completed and not action.blocked
        ]
        actions.sort(
            key=lambda item: (
                item.kind != "required",
                PHASES.index(item.phase) if item.phase in PHASES else len(PHASES),
                item.id,
            )
        )
        return actions[: max(0, limit)]

    def query_actions(
        self,
        *,
        phase: str | None = None,
        kind: str | None = None,
        include_completed: bool = False,
    ) -> list[WorkflowAction]:
        """Return a deterministic, queryable action view for UI and agents."""
        actions = list(self.state.pending_actions.values())
        if phase:
            actions = [item for item in actions if item.phase == phase]
        if kind:
            actions = [item for item in actions if item.kind == kind]
        if not include_completed:
            actions = [item for item in actions if not item.completed and not item.blocked]
        return sorted(actions, key=lambda item: (PHASES.index(item.phase), item.id))

    def audit_history(self, *, event_type: str | None = None) -> list[AuditEvent]:
        """Return the append-only audit history, optionally filtered by type."""
        if event_type is None:
            return list(self.state.audit_log)
        return [event for event in self.state.audit_log if event.event_type == event_type]

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-safe state plus current guidance for transport adapters."""
        document = self.state.document()
        document["guidance"] = self.guidance().document()
        document["recommendations"] = [asdict(action) for action in self.recommendations(limit=20)]
        return document

    def guidance(self) -> WorkflowGuidance:
        """Return the complete next-step view used by guided clients."""
        recommendations = self.recommendations(limit=1)
        required = self._required_actions()
        blockers = tuple(action.id for action in required)
        if recommendations:
            action = recommendations[0]
            explanation = action.consequence or action.description
        elif self.state.status in {"complete", "archived"}:
            explanation = "This workflow is finished and ready for retention or review."
        else:
            explanation = (
                "No action is currently available; inspect the audit log or resume safely."
            )
        return WorkflowGuidance(
            phase=self.state.phase,
            status=self.state.status,
            progress=self.state.progress,
            risk_score=self.state.risk_score,
            open_finding_ids=tuple(item.id for item in self.state.open_findings),
            blockers=blockers,
            next_action_id=recommendations[0].id if recommendations else None,
            explanation=explanation,
        )

    def query_findings(
        self, *, status: FindingStatus | None = None, severity: str | None = None
    ) -> list[FindingRecord]:
        records = list(self.state.findings.values())
        if status:
            records = [item for item in records if item.status == status]
        if severity:
            records = [item for item in records if item.severity == severity.lower()]
        return sorted(records, key=lambda item: (-item.priority, item.id))

    def close(self, *, actor: str = "operator", archive: bool = False) -> WorkflowState:
        self._ensure_mutable()
        # An empty, authorized assessment still gets a final-report audit step;
        # keep the no-finding path one-call closeable for automation clients.
        if not self.state.findings and "generate-report" in self.state.pending_actions:
            self.complete_action("generate-report", actor=actor)
        if self._required_actions():
            raise WorkflowError("Cannot close workflow while required actions remain")
        if "scope-authorized" not in self.state.completed_steps:
            raise WorkflowError("Cannot close workflow before scope authorization")
        if "discovery-complete" not in self.state.completed_steps:
            raise WorkflowError("Cannot close workflow before discovery completes")
        if self.state.findings and any(
            item.status != "closed" for item in self.state.findings.values()
        ):
            raise WorkflowError("Cannot close workflow while findings remain open")
        self.state.phase = "closure"
        self.complete_step("final-report", actor=actor, phase="closure")
        self.state.status = "archived" if archive else "complete"
        self._event("workflow.closed", "Workflow closed", actor=actor, archived=archive)
        self._recalculate()
        return self.state

    def _finding(self, finding_id: str) -> FindingRecord:
        try:
            return self.state.findings[finding_id]
        except KeyError as exc:
            raise WorkflowError(f"Unknown finding: {finding_id}") from exc


def finding_from_document(document: dict[str, Any]) -> FindingRecord:
    """Adapt a canonical ``core.findings.Finding`` document into engine state."""
    evidence = document.get("evidence") or []
    record = FindingRecord(
        id=str(document.get("id", "")),
        title=str(document.get("title", "")),
        severity=str(document.get("severity", "info")),
        confidence=str(document.get("confidence", "unknown")),
        impact=str(document.get("impact", "")),
        remediation=str(document.get("remediation", "")),
        source=str(document.get("source_capability", "session")),
        evidence=[item if isinstance(item, dict) else {"value": str(item)} for item in evidence],
        affected_assets=[str(item) for item in document.get("affected_assets", [])],
        tags=[str(item) for item in document.get("attack_techniques", [])],
        metadata={"control_mappings": document.get("control_mappings", [])},
    )
    record.normalize()
    return record


__all__ = [
    "AuditEvent",
    "FindingRecord",
    "PHASES",
    "WorkflowAction",
    "WorkflowEngine",
    "WorkflowError",
    "WorkflowGuidance",
    "WorkflowState",
    "finding_from_document",
]
