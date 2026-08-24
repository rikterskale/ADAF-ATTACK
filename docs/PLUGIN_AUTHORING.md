# Plugin authoring guide

ADAF-ATTACK discovers optional capability extensions at startup via Python
entry points. This guide covers the extension contract, safety profile
requirements, and packaging.

## Entry-point group

Plugins register capabilities under the `adaf_attack.capabilities`
entry-point group. The `discover_plugins()` function in
`core.engineering` loads every entry point in this group at startup.

### pyproject.toml example

```toml
[project.entry-points."adaf_attack.capabilities"]
my-custom-enum = "my_plugin.capabilities:register"
```

### setup.cfg example

```ini
[options.entry_points]
adaf_attack.capabilities =
    my-custom-enum = my_plugin.capabilities:register
```

## Registration function

Each entry point must resolve to a callable that registers capabilities
with the global `capability_registry`. The callable receives no arguments
and is invoked once during plugin discovery.

```python
from adaf_attack.core.registry import (
    ApprovalPolicy,
    RiskLevel,
    RollbackClass,
    SafetyProfile,
    capability_registry,
)


class MyEnumRunner:
    """A read-only enumeration capability."""

    def run(self, target, session, graph, *, include_secrets=False, force=False, **kwargs):
        # target: Target — authenticated connection parameters
        # session: Session — write events and artifacts here
        # graph: AttackGraph — add discovered edges
        session.log("my-enum.start", domain=target.domain)
        # ... perform enumeration ...
        result = {"users_found": 42}
        session.log("my-enum.complete", **result)
        return result


def register():
    capability_registry.register(
        "my-custom-enum",
        runner=MyEnumRunner(),
        safety=SafetyProfile(
            risk=RiskLevel.OBSERVE,
            approval=ApprovalPolicy.NONE,
            rollback=RollbackClass.NONE,
        ),
        category="enumeration",
        summary="Example custom enumeration capability",
    )
```

## CapabilityRunner protocol

The runner must implement the `run` method with this signature:

```python
def run(
    self,
    target: Target,
    session: Session,
    graph: AttackGraph,
    *,
    include_secrets: bool = False,
    force: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    ...
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `target` | `Target` dataclass with domain, dc_ip, and auth credentials |
| `session` | Active `Session` for logging events and writing artifacts |
| `graph` | `AttackGraph` for adding discovered edges and nodes |
| `include_secrets` | When true, include secret material in the result (redacted by default) |
| `force` | True when the operator passed `--force` (already policy-checked) |
| `**kwargs` | Capability-specific options passed via `-P key=value` |

### Return value

Return a dict. The dict is passed through `normalize_capability_result()`
and written to the session as part of the outcome. Include structured data
that downstream capabilities (`attack-paths`, `next-actions`, `report`) can
consume.

## Safety profiles

Every capability must declare a `SafetyProfile`. The registry validates the
profile at discovery time.

### Risk levels

| Level | Meaning | Example |
|-------|---------|---------|
| `OBSERVE` | Read-only; no target modification | `ldap-enum` |
| `SENSITIVE` | Reads sensitive data | `dcsync` (reads NT hashes) |
| `SIDE_EFFECT` | Network side effects (coercion, spray) | `password-spray` |
| `DESTRUCTIVE` | Modifies the target directory | `acl-write` |

### Approval policies

| Policy | Gate | When to use |
|--------|------|-------------|
| `NONE` | No gate | Read-only capabilities |
| `CONFIRM` | Interactive confirmation | Sensitive reads |
| `FORCE_AND_ACK` | `--force` + first-use `--i-understand` | Destructive writes |
| `SCOPED_TOKEN` | `--approval-token` | Network side effects against a scoped target |

### Rollback classes

| Class | Meaning |
|-------|---------|
| `NONE` | No rollback needed or possible |
| `MANUAL` | Operator must verify and revert manually |
| `AUTOMATIC` | `record_pre_state()` captures enough to auto-revert |

## Recording rollback state

Destructive capabilities must record pre-change state so the `rollback`
capability can reverse the change. Use `record_pre_state()` from
`core.rollback`:

```python
from adaf_attack.core.rollback import record_pre_state

# Before modifying an LDAP attribute:
record_pre_state(
    session,
    kind="ldap-attribute",
    target="CN=victim,DC=corp,DC=local",
    attribute="msDS-AllowedToActOnBehalfOfOtherIdentity",
    previous=original_value,
)
```

See [ROLLBACK_MATRIX.md](ROLLBACK_MATRIX.md) for the full list of supported
rollback kinds.

## Testing

Plugin capabilities are exercised through the same CI pipeline as built-in
capabilities. The recommended pattern:

1. Register the capability in a test fixture.
2. Run it against a mock `Target` with a temporary `Session`.
3. Assert the session event log contains the expected events.
4. Assert the return dict contains the expected keys.

For destructive capabilities, also verify that `cleanup.json` contains a
valid rollback entry.

## Packaging

Distribute plugins as standard Python packages with the entry-point
declaration above. They can be installed alongside ADAF-ATTACK or into the
same virtual environment:

```bash
pip install my-adaf-plugin
adaf-attack list-capabilities  # should show my-custom-enum
```

The plugin's `SafetyProfile` is validated at discovery time. If the profile
is invalid, the capability is skipped with a warning logged to stderr.
