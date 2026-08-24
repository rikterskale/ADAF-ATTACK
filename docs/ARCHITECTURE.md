# Architecture

This document describes the component boundaries, data flow, trust model, and
session lifecycle of ADAF-ATTACK.

## Component map

```
┌─────────────────────────────────────────────────────────┐
│                        CLI / TUI                        │
│  (Typer commands, Rich output, --format json contract)  │
└──────────────────────────┬──────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
   ┌──────────────────┐      ┌───────────────────┐
   │  Execution Policy │      │  Engagement Plan  │
   │  (force/ack/token │      │  (YAML scope,     │
   │   gates)          │      │   approval tokens) │
   └────────┬─────────┘      └────────┬──────────┘
            │                         │
            └────────────┬────────────┘
                         ▼
              ┌──────────────────────┐
              │  Capability Registry │
              │  (SafetyProfile,     │
              │   CapabilityRunner)  │
              └──────────┬───────────┘
                         │
           ┌─────────────┼─────────────┐
           ▼             ▼             ▼
  ┌──────────────┐ ┌──────────┐ ┌──────────────┐
  │   Session    │ │  Target  │ │ AttackGraph  │
  │ (events.jsonl│ │ (5 auth  │ │ (weighted    │
  │  vault,      │ │  modes)  │ │  edges,      │
  │  cleanup)    │ │          │ │  paths)      │
  └──────────────┘ └──────────┘ └──────────────┘
```

## Core modules

### `core.registry` — Capability registry

Every offensive capability is a `CapabilityRunner` registered with a
`SafetyProfile`. The profile declares three dimensions:

| Dimension | Values |
|-----------|--------|
| **RiskLevel** | `OBSERVE` · `SENSITIVE` · `SIDE_EFFECT` · `DESTRUCTIVE` |
| **ApprovalPolicy** | `NONE` · `CONFIRM` · `FORCE_AND_ACK` · `SCOPED_TOKEN` |
| **RollbackClass** | `NONE` · `MANUAL` · `AUTOMATIC` |

Computed properties on `SafetyProfile`:

- `requires_force` — true when `ApprovalPolicy >= FORCE_AND_ACK`
- `requires_ack` — true when `ApprovalPolicy == FORCE_AND_ACK`
- `is_mutating` — true when `RiskLevel >= SIDE_EFFECT`

### `core.execution_policy` — Gate enforcement

`enforce_execution_policy()` accepts an `ExecutionRequest` and raises
`PolicyError` if the caller has not satisfied the safety profile. Gates
checked in order:

1. `--force` required when `requires_force` is true.
2. `--i-understand` (first-use acknowledgement) when `requires_ack` is true.
3. `--approval-token` when `ApprovalPolicy == SCOPED_TOKEN`.

`safety_for_operation()` handles mixed read/write capabilities, promoting the
safety profile to the most restrictive participant.

### `core.session` — Session lifecycle

A session is created by `Session.__init__()`:

1. Generate a timestamped session ID: `YYYYMMDDTHHMMSSZ-<8-hex>`.
2. Generate a correlation ID (full UUID4 hex).
3. Create the session directory under the workspace.
4. Write `session.json` (schema version 2) with session metadata.

Every subsequent event is appended to `events.jsonl` with a SHA-256 hash
chain. See [SESSION_DATA_MODEL.md](SESSION_DATA_MODEL.md) for the full
schema.

### `core.vault` — Credential material store

`SessionVault` stores credential material with Fernet encryption at rest.
The public index (`vault/index.json`) contains only redacted metadata. Secret
blobs are written as `<name>.vault` files. See
[VAULT_OPERATIONS.md](VAULT_OPERATIONS.md) for operational guidance.

### `core.rollback` — Destructive-change tracking

Capabilities that modify the directory record pre-change state via
`record_pre_state()`. Each entry is classified as `revertable` (automated
undo available) or `advisory` (requires operator judgment). See
[ROLLBACK_MATRIX.md](ROLLBACK_MATRIX.md) for the full matrix.

### `core.engineering` — Shared primitives

- **Pydantic contracts**: `SessionContract`, `FindingContract`,
  `RunResultContract`, `CapabilityResultContract` validate boundary data.
- **SessionStore**: SQLite index at `<workspace>/sessions.sqlite` for fast
  session lookup by capability, finding, or time range.
- **`execute_with_controls()`**: bounded timeout and retry for capability work.
  Timeout and retries are disabled for mutating operations to prevent partial
  state.
- **`discover_plugins()`**: loads optional capability extensions from the
  `adaf_attack.capabilities` entry-point group. See
  [PLUGIN_AUTHORING.md](PLUGIN_AUTHORING.md).
- **`configure_logging()`**: structured JSON logging routed to stderr; never
  contaminates the `--format json` stdout contract.
- **`diagnostics_snapshot()`**: captures a redaction-safe diagnostic bundle.

### `core.engagement` — Engagement plans and approval

`EngagementPlan` is loaded from a YAML file via `load_plan()`. The plan
binds an engagement ID, target scope, allowed capabilities, phases with
options, OPSEC profile, and an allowed-targets allowlist. See
[ENGAGEMENT_SCHEMA.md](ENGAGEMENT_SCHEMA.md) for the YAML schema.

### `core.target` — Authentication

`Target` supports five authentication modes: Kerberos/ccache, AES key,
NTLM hashes, password, and anonymous. Credential rotation probes LDAP bind
in order and uses the first successful credential.

### `core.graph` — Attack graph

`AttackGraph` maintains weighted edges between principals. Edge weights
(35+ types) encode attack-path cost. `HIGH_VALUE_GROUPS` defines the set of
high-value targets for path analysis.

### `core.redaction` — Secret redaction

Three redaction profiles (`operator`, `purple`, `client`) control what
appears in output. Value-pattern regexes catch Kerberos blobs, PEM keys,
LM:NT hashes, GPP cpassword, and cloud tokens even in unstructured fields.

### `core.control_plane` — OPSEC and evidence packaging

Three OPSEC profiles (`stealth`, `balanced`, `loud`) control network
aggressiveness. `package_evidence()` creates a redacted archive for client
delivery.

## Data flow

```
Operator ──► CLI ──► ExecutionPolicy ──► CapabilityRunner.run()
                                              │
                            ┌─────────────────┼──────────────────┐
                            ▼                 ▼                  ▼
                        Session           AttackGraph          Target
                     (events.jsonl)       (graph.json)       (LDAP/Krb)
                     (vault/)             (interesting.json)
                     (cleanup.json)
                     (findings.json)
                     (outcome.json)
                            │
                            ▼
                       SessionStore
                    (sessions.sqlite)
```

1. The CLI parses arguments and builds a `Target` and `ExecutionRequest`.
2. `enforce_execution_policy()` gates the run based on the capability's
   `SafetyProfile`.
3. For engagement-scoped runs, `verify_scoped_approval()` validates the
   HMAC-signed token against engagement ID, target, capability, and parameter
   digest.
4. Credential rotation probes LDAP bind candidates in order.
5. `execute_with_controls()` invokes the runner with timeout/retry bounds.
6. The runner writes to the session (events, graph, vault, cleanup).
7. Post-execution: findings are generated, the outcome is written, and the
   session is indexed in `SessionStore`.

## Trust boundaries

| Boundary | Enforcement |
|----------|-------------|
| Operator → CLI | Authentication is out of scope (OS-level) |
| CLI → Target | Scoped approval tokens bind engagement + target + capability + parameters |
| CLI → Filesystem | Session paths are sandboxed via `Session.path()` resolve check |
| Vault → Disk | Fernet encryption; key never written to disk |
| Vault index → Reader | Redacted via `redact()` before writing public metadata |
| Event log → Auditor | SHA-256 hash chain with `os.fsync` durability |
| Phase options → Target | Every target-bearing option validated against `allowed_targets` |
| Approval token → Environment | HMAC verifier blocked in `ADAF_ATTACK_ENV=prod` without explicit acknowledgement |

## Plugin boundary

Third-party capabilities register via the `adaf_attack.capabilities`
entry-point group. They receive the same `Session`, `AttackGraph`, and
`Target` objects as built-in capabilities. The registry validates their
`SafetyProfile` at discovery time. See
[PLUGIN_AUTHORING.md](PLUGIN_AUTHORING.md).
