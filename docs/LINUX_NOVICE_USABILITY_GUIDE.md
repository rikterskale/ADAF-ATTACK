---
guide_id: linux-novice-usability
guide_schema_version: 1
platform: linux
canonical_path: docs/LINUX_NOVICE_USABILITY_GUIDE.md
project_name: ADAF-ATTACK
target_release: 0.10.1
support_status: hosted_ci_artifact_smoke
primary_shells: ["Bash"]
maintainer_source_of_truth: pyproject.toml
---

# ADAF-ATTACK Linux new-user guide

Use the tool only under written authorization. The first-success commands below
are offline and do not contact Active Directory.

## Prerequisites

- Python 3.11-3.14
- `python3-venv` (Debian/Ubuntu) or the equivalent distribution package
- Git only for a source checkout
- Access to the private GitHub release wheel or an authorized checkout

```bash
python3 --version
python3 -m venv --help >/dev/null
```

## Download or clone

Download the approved wheel from the private GitHub release, or clone the source:

```bash
git clone <approved-repository-url> ADAF-ATTACK
cd ADAF-ATTACK
```

Run source commands from this directory, where `pyproject.toml` is visible.

## Install

Recommended wheel path:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "./dist/adaf_attack-0.10.1-py3-none-any.whl[full]"
```

Authorized source path:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install ".[full]"
```

On Kali, use [KALI.md](KALI.md) and `scripts/install-kali.sh`, which also tests
the distro guard and system prerequisite path.

## Verify

```bash
python -m pip check
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace ./quickstart
adaf-attack guide --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack list-capabilities
adaf-attack paths
```

When lost, run `adaf-attack guide`. It always returns one copy-ready next step.

## First safe offline run

```bash
adaf-attack --format json doctor --explain
adaf-attack --format json list-capabilities
adaf-attack --format json paths
```

Exit code `0` and `"ok": true` confirm success. `paths` reports the workspace
where later session evidence and reports are stored; the commands above do not
create target-side artifacts.

## Stop or cancel

Press `Ctrl+C` once and wait for the process to exit. Preserve any workspace
created by a target-interacting command until evidence and cleanup status have
been reviewed.

## Upgrade and downgrade

Install the exact approved wheel in the existing venv:

```bash
python -m pip install --upgrade "./dist/adaf_attack-0.10.1-py3-none-any.whl[full]"
python -m pip check
adaf-attack --version
```

An older wheel path performs an explicit downgrade.

## Uninstall and data preservation

Deactivate and delete only the venv. Workspaces are outside it by default:

```bash
deactivate
rm -rf .venv
test -d "${XDG_DATA_HOME:-$HOME/.local/share}/adaf-attack/workspaces" && echo "workspace preserved"
```

Delete workspace data only after retention approval:

```bash
rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/adaf-attack/workspaces"
```

Kali installer users should use `bash scripts/install-kali.sh --uninstall`;
add `--remove-workspace` only when evidence deletion is intended.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No module named venv` | Install `python3-venv` with the distribution package manager. |
| `externally-managed-environment` | Create a venv; do not use `--break-system-packages`. |
| Wrong Python | Run `which python3` and create the venv with the required interpreter. |
| Command not found | Activate `.venv`, or call `.venv/bin/adaf-attack`. |
| Proxy/custom CA failure | Configure pip's approved proxy and CA bundle before retrying. |
| Optional dependency conflict | Use separate venvs for incompatible third-party operator tools. |

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for air-gapped wheelhouses and
sanitized diagnostics.

## Support boundaries

Hosted CI installs wheels and sdists on Ubuntu and performs a real wheel
installation in a Kali rolling container. Other distributions follow the same
Python contract but are not individually hosted. Live AD behavior and local
security policy depend on your target environment.

---

## Command reference (Linux)

This Bash command reference applies to Kali and other supported Linux
distributions for authorized internal assessments. Replace angle-bracket values
with engagement-approved data.

### Install and verify

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

### Global options and target command shape

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

### Capability reference

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

### Offline analysis and evidence workflows

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

### Sessions, artifacts, and interactive mode

```bash
adaf-attack sessions
adaf-attack sessions --workspace /evidence/adaf-workspaces
adaf-attack sessions --session <session-id>
adaf-attack start
```

Each run writes `session.json`, `events.jsonl`, result JSON, and usually
`graph.json`. Ranked output includes conventional paths plus evidence-backed
`exploit_chains` with impact, tactic, technique references, and confidence.

### Troubleshooting

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
