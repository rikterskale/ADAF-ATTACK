# Engineering foundations

ADAF-ATTACK exposes shared engineering primitives in
`adaf_attack.core.engineering`:

- Pydantic contracts validate session, finding, and run-result boundaries.
- `SessionStore` maintains a local SQLite index at `<workspace>/sessions.sqlite`.
- Session and finding documents are migrated forward with explicit schema versions.
- `execute_with_controls` provides bounded retry and timeout behavior for capability work.
- `discover_plugins` uses the `adaf_attack.capabilities` entry-point group for optional extensions.
- Structured JSON logging and redaction-safe diagnostics support reproducible troubleshooting.

Capability runners may accept `timeout` and `retries` through the shared execution path. These controls do not change authorization requirements: destructive operations still require the existing explicit force and engagement safeguards.
