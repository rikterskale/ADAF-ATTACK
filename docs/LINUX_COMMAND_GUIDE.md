# ADAF-ATTACK command guide: Linux

This Bash command reference applies to Kali and other supported Linux
distributions for authorized internal assessments. Replace angle-bracket values
with engagement-approved data.

## Install and verify

On Kali:

```bash
bash scripts/install-kali.sh
source .venv/bin/activate
adaf-attack --version
adaf-attack doctor --explain
adaf-attack paths
```

On another Linux distribution with Python 3.11-3.14:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install '.[full]'
adaf-attack doctor --explain
```

The default workspace is `~/.local/share/adaf-attack/workspaces`. Override it
for one shell or command:

```bash
export ADAF_ATTACK_WORKSPACE="$HOME/assessment/adaf-workspaces"
ADAF_ATTACK_WORKSPACE=/evidence/adaf adaf-attack paths
```

## Global options and target command shape

Global options apply to every command, but must appear before the command:
`--format human|json`, `--no-color`, and `--non-interactive`.

```bash
adaf-attack --format json doctor --explain
adaf-attack capability-help
adaf-attack capability-help ldap-enum

adaf-attack run <capability> -d <domain> --dc-ip <dc-or-host> \
  [-u <user> -p '<password>' | --hashes <lm:nt-or-nt> | -k --ccache <path>] \
  [--aes-key <hex>] [--ldaps] [--workspace <directory>]

adaf-attack --format json run <capability> -d <domain> --dc-ip <dc-or-host>
adaf-attack plan <capability> -d <domain> --dc-ip <dc-or-host>
```

`-k`/`--kerberos` selects ticket authentication, and `--ccache` sets
`KRB5CCNAME`. `--creds-file <path>` supports authorized credential rotation.
Avoid `--include-secrets` unless specifically required; normal output redacts
sensitive values.

## Capability reference

| Capability | Purpose | Capability-specific options |
|---|---|---|
| `ldap-enum` | LDAP identities, groups, SPNs, trusts, delegation, and links | common options |
| `trusts-enum` | Trust direction, type, and SID-filtering evidence | common options |
| `acl-enum` | ACL edges and replication-right evidence | `--scope high-value|domain|full`, `--max-objects <n>` |
| `adcs-enum` | CA, template, and ESC signal discovery | common options |
| `gmsa-laps-enum` | gMSA/LAPS presence and access signals | common options |
| `kerberoast` / `asrep-roast` | Kerberos credential-access evidence | common options; Kerberos extra required |
| `coercion-map` | Spooler/EFSRPC surface mapping | common options |
| `rbcd`, `shadow-creds`, `gpo-sysvol` | Delegation, key-credential, or SYSVOL surfaces | see `capability-help`; mutation requires `--force` |
| `gpo-abuse` | Writable-GPO and link evidence | common options |
| `cert-request`, `pkinit-auth` | Certificate-related operations | see `capability-help`; require `--force` |
| `attack-paths` | Rank saved/current graph paths | `--graph`, `--start`, `--max-depth`, `--limit` |
| `bloodhound-export`, `report` | Graph and report exports | common options |

Use `adaf-attack capability-help <capability>` for the current generated
reference. Destructive capabilities require `--force`; record the output of
`plan` first. This guide intentionally omits mutation procedures.

## Offline analysis and evidence workflows

```bash
adaf-attack rank-paths --graph /evidence/graph.json --start <principal> --max-depth 6 --limit 25 --output /evidence/ranked.json
adaf-attack credential-exposure --session /evidence/session-a --session /evidence/session-b
adaf-attack bloodhound-reconcile --session /evidence/session-a --bloodhound /evidence/bloodhound.json
adaf-attack trust-correlation --session /evidence/session-a --session /evidence/session-b
adaf-attack delegation-validation --session /evidence/session-a
adaf-attack adcs-validation --session /evidence/session-a
adaf-attack campaign-compose --session /evidence/session-a --session /evidence/session-b
adaf-attack purple-handoff --session /evidence/session-a
adaf-attack gpo-impact-plan --session /evidence/session-a
adaf-attack coercion-fixtures --fixtures /evidence/fixtures --authorized-fixtures
adaf-attack workflow-profiles
adaf-attack workflow-profiles purple-team
```

## Sessions, artifacts, and interactive mode

```bash
adaf-attack sessions
adaf-attack sessions --workspace /evidence/adaf-workspaces
adaf-attack sessions --session <session-id>
adaf-attack start
```

Each run writes `session.json`, `events.jsonl`, result JSON, and usually
`graph.json`. Ranked output includes conventional paths plus evidence-backed
`exploit_chains` with impact, tactic, technique references, and confidence.

## Troubleshooting

| Symptom | Action |
|---|---|
| `ModuleNotFoundError` | Activate `.venv` and install `.[full]`; see the new-user guide. |
| Kerberos capability unavailable | Install `adaf-attack[kerberos]`. |
| TUI unavailable | Install `adaf-attack[tui]`. |
| `GRAPH_NOT_FOUND` | Pass an existing `graph.json` to `rank-paths`. |
| Session path rejected | Use `adaf-attack sessions` and supply the session directory. |
| Automation parsing fails | Use `--format json --no-color`; do not parse Rich tables. |

For installation lifecycle, air-gapped setup, and host restoration, use the
[Linux new-user guide](LINUX_NOVICE_USABILITY_GUIDE.md) and
[troubleshooting guide](TROUBLESHOOTING.md).
