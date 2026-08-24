# Engagement and campaign YAML schema

This document defines the YAML schemas for engagement plans and campaign
manifests used by `adaf-attack engagement` and `adaf-attack campaign-run`.

## Engagement plan

An engagement plan scopes an authorized operation to specific targets,
capabilities, and phases. Create a template with
`adaf-attack engagement init --output engagement.yaml`.

### Required fields

```yaml
engagement_id: ENG-2026-001
target:
  domain: corp.local
  dc_ip: 10.0.0.10
allowed_capabilities:
  - ldap-enum
  - acl-enum
  - shadow-creds
phases:
  - name: reconnaissance
    capabilities:
      - ldap-enum
      - acl-enum
  - name: credential-access
    capabilities:
      - shadow-creds
    options:
      host: 10.0.0.10
```

### Full schema reference

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `engagement_id` | string | yes | Unique engagement identifier matching your authorization paperwork |
| `target` | mapping | yes | Contains `domain` (string) and `dc_ip` (string) |
| `target.domain` | string | yes | Target Active Directory domain |
| `target.dc_ip` | string | yes | Domain controller IP address |
| `allowed_capabilities` | list[string] | yes | Capability IDs permitted for this engagement; must be registered in the catalog |
| `phases` | list[mapping] | yes | Ordered list of execution phases |
| `allowed_targets` | list[string] | no | Hostnames/IPs that phase options may reference; defaults to `[target.dc_ip]` |
| `opsec_profile` | string | no | One of `stealth`, `balanced` (default), `loud` |

### Phase schema

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | string | no | Human-readable phase name; defaults to `"unnamed"` |
| `capabilities` | list[string] | yes | Capability IDs to run in this phase; must be in `allowed_capabilities` |
| `options` | mapping | no | Capability-specific options passed as `-P key=value` to the runner |

### Reserved option keys

The following keys in `options` are reserved and rejected by the validator:
`force`, `acknowledged`, `approval_token`, `session`, `graph`, `workspace`,
`include_secrets`. These are managed by the execution pipeline.

### Target option keys

Options with these keys are validated against `allowed_targets`:
`host`, `target`, `target_host`, `target_ip`, `remote_host`, `remote_ip`,
`dc_ip`, `set_on`, `set_from`, `listener`, `relay_target`, `relay_targets`,
`write_target`. A phase that references a target not in the allowlist is
rejected before any network action.

### OPSEC profiles

| Profile | Behavior |
|---------|----------|
| `stealth` | Minimal network footprint, longer delays, reduced parallelism |
| `balanced` | Default; standard timing and parallelism |
| `loud` | Aggressive timing; acceptable when detection is not a concern |

## Campaign manifest

A campaign runs multiple engagement plans in order, with optional
credential hand-off between phases.

```yaml
campaign_id: CAMPAIGN-2026-Q2
engagements:
  - plan: domain-a.yaml
  - plan: domain-b.yaml
    credential_handoff:
      allow: true
      from_session: ./workspaces/domain-a-session
      item: tgt
```

### Campaign fields

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `campaign_id` | string | yes | Unique campaign identifier |
| `engagements` | list[mapping] | yes | Ordered list of engagement references |
| `engagements[].plan` | string | yes | Path to an engagement YAML file |
| `engagements[].credential_handoff` | mapping | no | Credential hand-off configuration |
| `engagements[].credential_handoff.allow` | bool | no | Must be `true` to enable hand-off |
| `engagements[].credential_handoff.from_session` | string | no | Path to the source session directory |
| `engagements[].credential_handoff.item` | string | no | Vault item name (e.g., `tgt`) |

### Credential hand-off

A Kerberos cache may be handed to a subsequent engagement plan only when
`credential_handoff.allow: true` is explicitly declared. The credential is
loaded from the encrypted source-session vault and is never copied into the
campaign manifest or output. The destination session receives a vault
reference, not the raw credential.

### Approval token mapping

For engagements with side-effect or destructive phases, supply a separate
approval-token mapping:

```bash
adaf-attack campaign-run campaign.yaml \
  --approval-tokens tokens.json \
  --workspace ./workspaces -u operator
```

The `tokens.json` file maps engagement IDs to tokens:

```json
{
  "ENG-2026-001": "<token-for-domain-a>",
  "ENG-2026-002": "<token-for-domain-b>"
}
```

Each token must cover the engagement's normalized phase parameters as well
as the engagement ID, capability, and target. See
[APPROVAL_TOKENS.md](APPROVAL_TOKENS.md) for the token format.
