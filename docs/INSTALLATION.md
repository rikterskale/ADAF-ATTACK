# ADAF-ATTACK installation guide

This guide is the operator-facing installation path for ADAF-ATTACK. Follow it
in order. It is written for authorized internal red-team work and deliberately
starts with an offline verification flow before any target information or
credentials are supplied.

## 1. Before you install

ADAF-ATTACK is proprietary and is not published on PyPI. Obtain one of these
approved sources through your organization:

- a private release wheel (`adaf_attack-<version>-py3-none-any.whl`),
- an approved wheelhouse containing that wheel and its dependencies, or
- an authorized source checkout.

Do not substitute a public package, an unapproved mirror, or a random Git
checkout. Keep the wheel, release manifest, and `SHA256SUMS` together when
they are supplied.

Supported Python versions are 3.11, 3.12, 3.13, and 3.14. Use a dedicated
virtual environment. Do not install into the operating-system Python and do
not use `sudo pip`.

The normal operator installation is the `full` extra. It includes the TUI,
Kerberos/Impacket support, and report generation. The `certipy` extra remains
separate because its cryptography constraints can conflict with the pinned
runtime.

## 2. Choose the installation path

| Operator environment | Recommended path |
|---|---|
| Windows | PowerShell installer or approved wheel in a venv |
| Kali Linux | `scripts/install-kali.sh` |
| Other Linux | Approved wheel in a venv or source checkout |
| macOS | Approved wheel in a venv; offline CLI/reporting is the primary path |
| Air-gapped host | Transfer and verify a complete wheelhouse, then use the portable bootstrap |
| Contributor | Authorized checkout with `.[dev,operator]` |

If you are unsure, use the generic wheel instructions first. Platform-specific
guides are available for [Windows](WINDOWS_NOVICE_USABILITY_GUIDE.md),
[Kali](KALI.md), and [Linux](LINUX_NOVICE_USABILITY_GUIDE.md).

## 3. Linux or macOS: install an approved wheel

From the directory containing the approved wheel:

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install './adaf_attack-<version>-py3-none-any.whl[full]'
```

Verify that the shell is using the new environment:

```bash
command -v python
command -v adaf-attack
python -m pip --version
adaf-attack --version
python -m pip check
```

If the wheel filename contains shell metacharacters or spaces, use an
absolute, quoted path. If the shell command is not found after activation,
run the venv executable directly:

```bash
.venv/bin/adaf-attack --version
.venv/bin/python -m adaf_attack.cli --format json doctor --explain
```

### Minimal and specialized installations

Install the base wheel without extras when only offline CLI functionality is
needed:

```bash
python -m pip install './adaf_attack-<version>-py3-none-any.whl'
```

Add only the boundary you need:

```bash
python -m pip install './adaf_attack-<version>-py3-none-any.whl[tui]'
python -m pip install './adaf_attack-<version>-py3-none-any.whl[kerberos]'
python -m pip install './adaf_attack-<version>-py3-none-any.whl[reports]'
python -m pip install './adaf_attack-<version>-py3-none-any.whl[certipy]'
```

For the production operator surface, prefer `[full]`. Use a separate virtual
environment for Certipy if pip reports a cryptography conflict.

## 4. Windows: PowerShell installer

Open PowerShell in the authorized checkout or release bundle. The installer
creates an isolated environment, installs a user-level command shim, and
preserves workspaces during uninstall.

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
Unblock-File .\scripts\Install-AdafAttack.ps1
.\scripts\Install-AdafAttack.ps1 -Package .\adaf_attack-<version>-py3-none-any.whl -Extras full
```

For a source checkout:

```powershell
.\scripts\Install-AdafAttack.ps1 -RepoRoot (Get-Location).Path -Editable -Extras full
```

For a specific Python installation:

```powershell
.\scripts\Install-AdafAttack.ps1 -Python py -PythonVersion 3.13 -Extras full
```

The installer can emit machine-readable failures:

```powershell
.\scripts\Install-AdafAttack.ps1 -Json -Package .\adaf_attack-<version>-py3-none-any.whl
```

Close and reopen PowerShell after installation so the updated user PATH is
loaded. Then verify:

```powershell
Get-Command adaf-attack -All
adaf-attack --version
python -m pip check
adaf-attack --format json doctor --explain
```

If the shim is not yet visible, use the installer environment directly:

```powershell
& "$env:LOCALAPPDATA\adaf-attack\venv\Scripts\python.exe" -m adaf_attack.cli --version
```

## 5. Kali Linux: installer-assisted setup

The Kali installer can provision system prerequisites, create the project
virtual environment, install shell completion, and emit actionable errors.
Run it from the authorized checkout:

```bash
bash scripts/install-kali.sh --extras full
source .venv/bin/activate
adaf-attack --format json doctor --explain
```

If system packages are already approved and installed:

```bash
bash scripts/install-kali.sh --skip-system-deps --extras full
```

To install a release wheel instead of the checkout:

```bash
bash scripts/install-kali.sh \
  --package ./adaf_attack-<version>-py3-none-any.whl \
  --extras full
```

Use structured installer errors when integrating with a provisioning system:

```bash
bash scripts/install-kali.sh --json --skip-system-deps
```

The installer refuses to modify an unowned virtual environment. Choose a new
`--venv` path or uninstall the matching ADAF-ATTACK environment first.

## 6. Air-gapped or offline installation

Build the complete wheelhouse on a connected machine using the same target OS
family and Python compatibility range:

```bash
python scripts/build-release-wheelhouse.py \
  --wheel ./adaf_attack-<version>-py3-none-any.whl \
  --output ./wheelhouse \
  --extras full
python scripts/generate_release_manifest.py \
  --dist . \
  --wheelhouse ./wheelhouse \
  --output ./wheelhouse/release-manifest.json \
  --validate
```

Transfer the wheel, the complete `wheelhouse/`, the manifest, and any supplied
checksums through the approved media process. On the isolated host, install
without network access:

```bash
python3 scripts/install-approved-wheel.py \
  --wheel ./adaf_attack-<version>-py3-none-any.whl \
  --venv .venv \
  --extras full \
  --find-links ./wheelhouse \
  --manifest ./wheelhouse/release-manifest.json
```

The bootstrap verifies the release wheel and every manifest-listed wheelhouse
file before pip runs, refuses to reuse an existing environment, runs
`pip check`, and executes an offline quickstart smoke test. A missing
distribution means the wheelhouse is incomplete; rebuild it for the target
platform instead of enabling internet access on the isolated host.

## 7. First verification: safe and offline

After any installation path, run this sequence. These commands do not contact
Active Directory and do not modify a target:

```bash
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack --format json paths
adaf-attack quickstart --workspace ./quickstart
adaf-attack session show --session ./quickstart/demo-session
adaf-attack --format json list-capabilities
```

A successful readiness check reports `ok: true` and a ready installation.
Optional warnings for TUI, Kerberos, reporting, or Certipy are expected when
those extras were not installed. `quickstart` creates disposable local demo
evidence and never contacts a domain controller.

If the default application directories are blocked:

```bash
adaf-attack paths --repair
adaf-attack --format json doctor --profile user-readiness --explain
```

Or select approved writable per-user directories:

```bash
export ADAF_ATTACK_DATA_DIR="$PWD/.adaf-data"
export ADAF_ATTACK_CONFIG_DIR="$PWD/.adaf-config"
export ADAF_ATTACK_WORKSPACE="$PWD/.adaf-workspaces"
adaf-attack paths --repair
```

PowerShell equivalent:

```powershell
$env:ADAF_ATTACK_DATA_DIR = "$PWD\.adaf-data"
$env:ADAF_ATTACK_CONFIG_DIR = "$PWD\.adaf-config"
$env:ADAF_ATTACK_WORKSPACE = "$PWD\.adaf-workspaces"
adaf-attack paths --repair
```

## 8. Optional shell completion and TUI

Generate completion scripts without changing shell startup files:

```bash
adaf-attack completions bash --output-dir ./completions
adaf-attack completions zsh --output-dir ./completions
```

The Kali installer can install completion for the active Bash or Zsh shell.
On Windows, reopen the terminal after the installer updates PATH.

Launch the TUI only after the CLI quickstart succeeds:

```bash
adaf-attack start
```

Use `?` inside the TUI for keyboard help. The interface remains review-first;
selecting a capability never executes it, and destructive operations still
require the normal review and authorization gates.

## 9. Live AD readiness

Do not begin a live run as an installation test. First obtain written scope,
approved credentials, target DNS and routing, synchronized clocks for
Kerberos, and an engagement workspace. Run the explicit target preflight:

```bash
adaf-attack --format json doctor --profile live-ad \
  --domain corp.example \
  --dc-ip 10.0.0.10
```

Then inspect the generated plan before running anything:

```bash
adaf-attack plan ldap-enum \
  --domain corp.example \
  --dc-ip 10.0.0.10 \
  --export ./ldap-enum-plan.md
```

Never place passwords, hashes, tickets, private keys, or approval tokens in
shell history, documentation, support bundles, or profile files. Use the
session vault and approved credential sources described in the operator guide.

## 10. Upgrade, uninstall, and preserve evidence

Keep each release in its own clean virtual environment when comparing
versions. For a portable install, remove the old `.venv` only after exporting
or preserving any required session evidence, then rerun the installation and
quickstart verification.

Windows:

```powershell
.\scripts\Install-AdafAttack.ps1 -Uninstall
```

Kali:

```bash
bash scripts/install-kali.sh --uninstall
```

Both installers preserve workspaces by default. Removing workspaces is an
explicit, destructive action:

```powershell
.\scripts\Install-AdafAttack.ps1 -Uninstall -RemoveWorkspace
bash scripts/install-kali.sh --uninstall --remove-workspace
```

Confirm the exact workspace path before using the removal option.

## 11. If installation fails

Run the following and keep the output after sanitizing organization-specific
identifiers:

```bash
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack --format json paths
python --version
python -m pip --version
python -m pip check
adaf-attack --version
```

Then follow [Troubleshooting](TROUBLESHOOTING.md). It covers PATH issues,
Python selection, virtual-environment failures, PowerShell policy, proxies
and custom CAs, offline wheelhouses, optional dependency conflicts, writable
directories, and safe support evidence collection.
