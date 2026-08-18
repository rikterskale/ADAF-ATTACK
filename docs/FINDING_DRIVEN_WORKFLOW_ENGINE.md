# Finding-driven workflow engine

The guided workflow is a durable state machine whose transitions are derived
from evidence, findings, operator decisions, and system state. The TUI is one
client of the engine; CLI commands and automated agents can use the same
interface without duplicating workflow rules.

## Architecture

```text
capability/session/agent/operator input
                |
                v
      Finding adapter + validator
                |
                v
  WorkflowEngine: state -> rules -> actions -> audit
        |             |             |
        v             v             v
 workflow-state.json  recommendations  TUI / CLI / agent
```

The engine lives in `adaf_attack.core.workflow_engine`. It owns state
transitions and persistence; scanners only submit findings and evidence. The
existing canonical `core.findings.Finding` model is adapted with
`finding_from_document` so existing session artifacts remain compatible.

## Data model

`FindingRecord` is the workflow-native finding object. It contains:

- stable ID, title, severity, confidence, impact, and remediation;
- lifecycle status: `open`, `validated`, `exploited`, `mitigated`, `closed`;
- evidence references, affected assets, tags, related findings, source, and
  extensible metadata;
- calculated priority and timestamps.

`WorkflowState` contains:

- workflow identity, mode (`interactive`, `automated`, or `agent`), phase, and
  status;
- completed steps and progress percentage;
- all findings, pending actions, decisions, and append-only audit events;
- aggregate risk score and monotonic revision number.

`WorkflowAction` is a derived or completed action. Its `kind` is `required`,
`recommended`, or `decision`; it can point to findings and a capability and
includes the consequence of ignoring it. `AuditEvent` records who changed
what, when, and why.

## State machine and branching

The default phases are:

`scoping → discovery → validation → prioritization → response → verification → reporting → closure`

Every mutation recalculates priorities, risk, pending actions, status, and
progress. Examples:

- no authorization produces the required `authorize-scope` action;
- authorized state with no evidence produces required `run-discovery`;
- an open finding produces a required validation action;
- every validated finding produces a decision point, including low/info findings;
- a completed decision produces a response action, while an exploited finding
  produces a required mitigation action;
- a mitigated finding produces required verification;
- reporting unlocks only after every finding is closed (or the assessment has
  no findings);
- closure is rejected while required actions or non-closed findings remain.

Operators may inject findings, enrich them, correlate them, or override an
existing record. Overrides are explicitly audited. Automated and agent clients
can call the same methods and choose whether to execute recommended actions or
pause at decision points.

## Prioritization

Priority is deterministic and explainable:

```text
priority = severity_weight × confidence_weight + min(affected_assets, 20) × 2
```

Severity weights are critical 100, high 75, medium 45, low 20, and info 5.
Confidence weights are confirmed 1.0, observed 0.85, suspected 0.6, and
unknown 0.4. Workflow risk is the capped sum of priorities for non-closed
findings. Recommendations sort required actions before decision and optional
actions, then by phase and stable ID.

## Guided user experience

The TUI exposes the engine through the existing wizard:

1. Scope and authorization are confirmed before target activity.
2. Access material and target details are collected.
3. A capability is selected or a safe reconnaissance template is chosen.
4. The review gate records the scope decision and unlocks execution.
5. Completed session findings are adapted into `FindingRecord` objects.
6. The workflow panel continuously shows phase, status, progress, risk, open
   finding count, and the next required/recommended action.
7. Finding decisions drive validation, response, verification, reporting, and
   closure. The user can resume from `workflow-state.json` after interruption.

The pre-existing safety gate remains authoritative: workflow recommendations
can explain or unlock a next step, but they cannot bypass force, checklist, or
runner authorization controls.

## Completeness and edge cases

- State writes are atomic through a temporary file and `os.replace`.
- Malformed state fails closed with `WorkflowError` rather than silently
  inventing progress.
- Unknown phases, statuses, actions, and findings are rejected.
- Finding lifecycle transitions are monotonic and closing requires verification
  evidence.
- Duplicate findings preserve original creation time and merge relationships;
  explicit overrides are available for operator correction.
- Locked configuration directories do not prevent the interactive TUI from
  running; workflow persistence reports the failure through normal error
  handling while execution remains safe.
- Empty findings are valid: discovery can complete and reporting/closure can
  proceed without inventing risk.
- Required actions block closure; recommended actions never create a dead end.
- `guidance()` returns a stable phase/status/progress/risk/blocker/next-action
  snapshot for interactive, CLI, and agent clients.
- The engine is transport-independent and can be resumed, queried, or driven
  by an automated client using the same public methods.

## Integration surface

```python
from pathlib import Path

from adaf_attack.core.workflow_engine import WorkflowEngine, finding_from_document

engine = WorkflowEngine(Path("workspace"), mode="interactive")
engine.start(actor="operator")
engine.complete_action("authorize-scope")
engine.complete_action("run-discovery")
engine.ingest_finding(finding_from_document(session_finding), actor="session")

for action in engine.recommendations():
    print(action.id, action.kind, action.consequence)

engine.complete_action("validate:ADAF-1")
engine.decide("decision:ADAF-1", "mitigate", rationale="Owner approved")
```

The persisted document is queryable JSON, making it suitable for CLI output,
agent context, audit review, and later report packaging without exposing
credentials or vault contents. Transport adapters can use `snapshot()` for a
single state/guidance/recommendations payload, `query_findings()` for filtered
finding views, `query_actions()` for phase or action-kind views, and
`audit_history()` for append-only audit inspection. Completing a finding-linked
action advances the lifecycle and phase where the engine can do so safely;
explicit status transitions remain available for evidence that must be supplied
by a scanner, operator, or external remediation system.
