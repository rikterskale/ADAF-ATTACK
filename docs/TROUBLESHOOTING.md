# Installation troubleshooting

For a complete clean-install walkthrough, start with the
[Installation guide](INSTALLATION.md). Use this page when a step fails or
when an installed command behaves differently from the documented path.

## Fastest triage path

Work through these checks in order. Stop at the first failing command; later
checks are not useful until that boundary is healthy.

```text
Python selected → virtual environment active → package installed
→ PATH points at that environment → pip dependencies consistent
→ local paths writable → offline quickstart passes → live preflight passes
```

Run the following from the same shell in which the failure occurred:

```bash
python --version
python -c 'import sys; print(sys.executable)'
python -m pip --version
python -m pip check
command -v adaf-attack || true
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack --format json paths
```

On PowerShell, use:

```powershell
py -0p
python --version
python -c "import sys; print(sys.executable)"
python -m pip --version
python -m pip check
Get-Command adaf-attack -All
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack --format json paths
```

If the failure is not local setup, reproduce it with the smallest safe
offline command before attempting a live target:

```bash
adaf-attack quickstart --workspace ./quickstart-retry
```

Run this first and retain the output after sanitizing paths and usernames:

```bash
adaf-attack --format json doctor --explain
adaf-attack --format json paths
python --version
python -m pip --version
python -m pip check
```

The default doctor profile is offline and performs no network probes. For an
authorized target, run the explicit live preflight instead:

```bash
adaf-attack --format json doctor --profile live-ad \
  --domain corp.example --dc-ip 10.0.0.10
```

To attach diagnostics to a support request, export a redacted bundle and
review it for organization-specific identifiers before sharing:

```bash
adaf-attack --format json support-bundle --output adaf-support-bundle.json
```

## Command not found or old version

For scripted installer diagnostics, use `-Json` with the Windows installer or
`--json` with the Kali installer. Both include a stable error code, message,
and remediation field. The Windows installer classifies common failures as
`PYTHON_UNSUPPORTED`, `PATH_NOT_FOUND`, `EXECUTION_POLICY_BLOCKED`,
`PROXY_TLS_FAILED`, `INSTALLER_OWNERSHIP`, or `INSTALLER_FAILURE` (aligned with
`adaf-attack errors` where applicable).

- Open a new terminal after a Windows installer changes user PATH.
- Windows: run `Get-Command adaf-attack -All` and `py -0p`.
- Linux/macOS: run `command -v adaf-attack` and `command -v python`.
- Use the venv executable directly to distinguish PATH from installation issues.
- Confirm `python -m pip --version` points into the intended venv.

If `adaf-attack --version` reports an unexpected release, compare these three
paths. They must refer to the same environment:

```bash
command -v python
command -v adaf-attack
python -m pip show adaf-attack
```

On Windows:

```powershell
(Get-Command python).Source
(Get-Command adaf-attack).Source
python -m pip show adaf-attack
```

Activate the intended venv again, or call its executable by absolute path.
Do not solve a mixed-environment problem by installing with `sudo`.

## Python and virtual environments

ADAF-ATTACK requires Python 3.11-3.14. The Windows installer accepts
`-Python <full-path>` or `-Python py -PythonVersion 3.13`. On Debian-family
systems, install `python3-venv` if venv creation fails. A PEP 668
`externally-managed-environment` error means pip is protecting the system Python:
create a venv instead of using `sudo pip` or `--break-system-packages`.

If `python3 -m venv .venv` fails on Debian/Kali, install the matching venv
package through the approved system package process, then retry:

```bash
sudo apt-get update
sudo apt-get install --yes python3-venv python3-pip
```

If multiple Python versions are installed, select one explicitly and verify
the resulting interpreter before installing:

```bash
python3.13 -m venv .venv
.venv/bin/python --version
```

Do not reuse an environment created by another Python minor version.

## PowerShell execution policy and SmartScreen

Use the narrowest policy approved by your organization:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
Unblock-File .\scripts\Install-AdafAttack.ps1
```

Verify the repository/release source before unblocking. Group Policy can
override local policy; contact the endpoint owner rather than bypassing it.

## Proxy, private index, and custom CA

Configure pip through approved environment variables or `pip.ini`/`pip.conf`:

```bash
python -m pip config debug
python -m pip install --cert /path/to/company-ca.pem <approved-wheel>
```

Use `HTTPS_PROXY` only with the approved proxy. Avoid permanent
`--trusted-host` settings because they disable certificate verification for the
named host. Private GitHub release downloads also need an authenticated client
that trusts the organization's CA.

If pip reports a TLS or certificate error, first inspect the effective
configuration rather than disabling verification:

```bash
python -m pip config debug
env | grep -E '^(HTTP|HTTPS|NO)_PROXY=|^PIP_' || true
```

On PowerShell:

```powershell
python -m pip config debug
Get-ChildItem Env: | Where-Object Name -match '^(HTTP|HTTPS|NO)_PROXY$|^PIP_'
```

Use the organization's CA bundle with `--cert` or its approved pip
configuration. If the release is air-gapped, use `--find-links` and
`--no-index` rather than fighting a blocked proxy.

## Offline or air-gapped install

Build a wheelhouse on a connected host matching the offline OS and Python
family. The repository helper creates the wheelhouse and its manifest
together:

```bash
python scripts/build-release-wheelhouse.py \
  --wheel ./adaf_attack-0.10.1-py3-none-any.whl \
  --output ./wheelhouse --extras full
python scripts/generate_release_manifest.py \
  --dist . --wheelhouse ./wheelhouse \
  --output ./wheelhouse/release-manifest.json --validate
```

Install through the portable bootstrap to verify the approved artifact and
every manifest-listed wheelhouse file before pip runs:

```bash
python scripts/install-approved-wheel.py \
  --wheel ./adaf_attack-0.10.1-py3-none-any.whl \
  --venv .venv --extras full \
  --find-links ./wheelhouse \
  --manifest ./wheelhouse/release-manifest.json
```

Transfer every file and, when supplied, verify `SHA256SUMS`. If pip reports a
missing distribution, rebuild the wheelhouse for that platform rather than
allowing network access on the isolated host.

## Optional tooling conflicts

`full` contains production TUI, Kerberos, and report dependencies. Contributor
tools are only in `dev`. Certipy remains separate because its cryptography
constraints can conflict with the core runtime:

```bash
python -m pip install "adaf-attack[certipy]"
```

Prefer a dedicated Certipy venv if pip cannot resolve the combined environment.
AD CS capabilities invoke the `certipy` binary from `PATH`, so activate the
dedicated venv (or prepend its `bin`/`Scripts` directory to `PATH`) in the same
shell before running them; otherwise the capability reports the tool as
missing. `doctor --explain` distinguishes required failures from optional
warnings.
Use `--profile operator` to make TUI, reporting, and Kerberos tooling blocking,
or `--profile certipy` to validate the separate AD CS dependency boundary.

Typical symptoms and fixes:

| Symptom | Likely cause | Fix |
|---|---|---|
| `No module named textual` | TUI extra not installed | Install `[tui]` or `[full]` in the active venv. |
| `No module named impacket` | Kerberos/operator extra missing | Install `[kerberos]` or `[full]`; rerun `doctor --profile operator`. |
| `reportlab` or `pypdf` missing | Reporting extra missing | Install `[reports]` or `[full]`. |
| `certipy` missing from PATH | Separate Certipy environment is inactive | Activate that venv or add its `bin`/`Scripts` directory to PATH. |
| Dependency resolution conflict | Certipy mixed into the pinned runtime | Keep Certipy in a separate venv. |

Do not install an arbitrary newer dependency to silence a warning. Runtime
versions are intentionally pinned for reproducible release behavior.

## Target and input failures

JSON failures include a stable error code, remediation, and often a suggested
command. Use the code to choose the recovery path:

| Error code | First recovery action |
|---|---|
| `AUTHENTICATION_FAILED` | Recheck the account, secret source, DNS, and clock; never add a password to shell history. |
| `TARGET_UNREACHABLE` | Run the explicit live-AD doctor profile and verify routing and firewall rules for the authorized network. |
| `REQUIRED_INPUT_MISSING` | Run `adaf-attack capability-help <capability>` and provide the named option or `-P` parameter. |
| `INPUT_FILE_INVALID` | Confirm the path exists, is readable, and matches the documented artifact format. |
| `PERMISSION_DENIED` | Select writable per-user data/config/workspace directories with `adaf-attack paths`. |
| `SESSION_NOT_FOUND` | Pass an existing session directory from `adaf-attack sessions --limit 10`, or recreate with `quickstart`. |
| `APPROVAL_TOKEN_EXPIRED` | Request a fresh scoped token for the same `--engagement-id`, then re-run with `--approval-token`. |
| `APPROVAL_TOKEN_INVALID` | Confirm `--engagement-id` matches the token claims, then re-run with a valid `--approval-token`. |
| `SECRET_IN_OUTPUT` | Do not share the output; rotate the exposed secret if it was real; regenerate a redacted `support-bundle`. |
| `PROXY_TLS_FAILED` / air-gap | Configure the approved CA (`pip --cert`) or install from a complete wheelhouse with `--no-index --find-links`. |

For a complete catalog, run `adaf-attack --format json errors`. The generic
`RUN_FAILED` code is reserved for provider failures that do not match a safer
specific recovery class; retain the exact message and sanitized support bundle
when requesting help.

## Quickstart and workspace failures

| Symptom | Fix |
|---|---|
| `QUICKSTART_WORKSPACE_EXISTS` | Choose a new empty `--workspace` path; the command will not overwrite an existing demo session. |
| `QUICKSTART_WRITE_FAILED` | Run `paths`, choose writable data/config/workspace directories, then retry. |
| `PERMISSION_DENIED` under a managed home directory | Set `ADAF_ATTACK_DATA_DIR`, `ADAF_ATTACK_CONFIG_DIR`, and `ADAF_ATTACK_WORKSPACE` to approved per-user paths. |
| A session is present but findings are empty | Confirm the session contains `findings.json`; malformed JSON is treated as unavailable evidence rather than repaired automatically. |
| A report or package fails on a huge workspace | Use a dedicated session directory and preview exclusions before creating the archive. |

Never point `--workspace` at a broad home, repository root, or shared evidence
directory for a disposable quickstart.

## Read-only profile or managed workstation

If `doctor` reports that the data or configuration directory is not writable,
choose writable per-user locations and rerun the check:

```powershell
$env:ADAF_ATTACK_DATA_DIR = "D:\adaf-data"
$env:ADAF_ATTACK_CONFIG_DIR = "D:\adaf-config"
$env:ADAF_ATTACK_WORKSPACE = "D:\adaf-workspaces"
adaf-attack --format json doctor --explain
```

If the directories are missing, the non-destructive repair command can create
them for you:

```bash
adaf-attack paths --repair
adaf-attack doctor --profile user-readiness
```

`paths --repair` only creates the data, configuration, and workspace directories;
it does not delete, move, or overwrite existing session data. If repair itself
is denied, set the three `ADAF_ATTACK_*` variables to approved writable paths.

On Linux/macOS use the same variable names with shell syntax. Help and planning
commands remain usable when recent-command preferences cannot be saved, but
explicit `adaf-attack config set` changes require a writable config directory.

## Sanitized support evidence

Provide:

- OS edition/version and shell version
- `python --version`, `python -m pip --version`, and `python -m pip check`
- `adaf-attack --version` and sanitized JSON from `doctor --explain`
- install method (wheel filename/source commit), selected extras, and exit code
- the exact error text with credentials, domain names, IPs, usernames, home
  paths, tokens, and proxy URLs removed

Do not send workspaces, vaults, credential files, ticket material, private keys,
raw AD data, or unredacted environment dumps.
