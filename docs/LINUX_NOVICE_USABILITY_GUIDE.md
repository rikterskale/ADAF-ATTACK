---
guide_id: linux-novice-usability
guide_schema_version: 1
platform: linux
canonical_path: docs/LINUX_NOVICE_USABILITY_GUIDE.md
project_name: ADAF-ATTACK
target_release: 0.10.0
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
python -m pip install "./dist/adaf_attack-0.10.0-py3-none-any.whl[full]"
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
adaf-attack doctor --explain
adaf-attack list-capabilities
adaf-attack paths
```

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
python -m pip install --upgrade "./dist/adaf_attack-0.10.0-py3-none-any.whl[full]"
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
security policy remain release-sign-off tasks.
