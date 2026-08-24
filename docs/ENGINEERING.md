# Engineering foundations

ADAF-ATTACK exposes shared engineering primitives in
`adaf_attack.core.engineering` that enforce data contracts, execution
boundaries, and observability across all capability runs.

## Pydantic contracts

Boundary data is validated by strict Pydantic models:

| Contract | Validates |
|----------|-----------|
| `SessionContract` | `session.json` metadata (schema version, session ID, timestamps) |
| `FindingContract` | Individual findings (severity, evidence hashes, MITRE mapping) |
| `RunResultContract` | Capability return dicts (ok, capability, session_path, result) |
| `CapabilityResultContract` | Inner result payloads from capability runners |

These contracts enforce the schema at write time. A capability that returns
malformed data fails at the contract boundary, not downstream in reporting.

## SessionStore

`SessionStore` maintains a local SQLite index at
`<workspace>/sessions.sqlite`. It indexes session metadata, capability IDs,
and findings for fast lookup without scanning session directories.

```python
store = SessionStore(workspace / "sessions.sqlite")
store.index_session(metadata, capability="ldap-enum", findings=[...])
```

The index is a cache over the authoritative `session.json` and
`findings.json` files. It can be rebuilt from the session directories.

## execute_with_controls

`execute_with_controls()` wraps capability execution with bounded timeout
and retry:

```python
result = execute_with_controls(
    runner_callable,
    timeout=300,       # seconds; None = no timeout
    retries=2,         # retry count; 0 = no retries
    mutating=True,     # when True, timeout and retries are disabled
)
```

The `mutating` flag is critical: destructive operations must not be
interrupted mid-write or retried, as this could leave the directory in a
partial state. When `mutating=True`, both `timeout` and `retries` are
silently ignored.

## Plugin discovery

`discover_plugins()` loads capabilities from the
`adaf_attack.capabilities` entry-point group at startup. Each entry point
must resolve to a callable that registers capabilities with the global
registry. Invalid profiles are logged and skipped. See
[PLUGIN_AUTHORING.md](PLUGIN_AUTHORING.md) for the full extension contract.

## Structured logging

`configure_logging()` sets up JSON-formatted logging routed to stderr.
The `--debug` CLI flag activates diagnostic-level output. Log records never
appear on stdout, preserving the `--format json` machine-readable contract.

`JsonLogFormatter` produces one JSON object per line with `ts`, `level`,
`logger`, and `message` fields. Sensitive values are redacted before
formatting.

## Diagnostics

`diagnostics_snapshot()` captures a point-in-time diagnostic bundle:
interpreter version, platform, installed packages, writable paths, and
environment variable presence (values are never captured). The bundle is
safe to share and powers `adaf-attack support-bundle`.

## Schema migration

Session and finding documents carry an explicit `schema_version` field
(currently `2`). When the schema evolves, migration logic in the
engineering module promotes older documents forward. The version is
checked at read time by the Pydantic contracts.
