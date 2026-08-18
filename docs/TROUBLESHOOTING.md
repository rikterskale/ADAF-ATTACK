# Installation troubleshooting

Run this first and retain the output after sanitizing paths and usernames:

```bash
adaf-attack --format json doctor --explain
adaf-attack --format json paths
python --version
python -m pip --version
python -m pip check
```

## Command not found or old version

- Open a new terminal after a Windows installer changes user PATH.
- Windows: run `Get-Command adaf-attack -All` and `py -0p`.
- Linux/macOS: run `command -v adaf-attack` and `command -v python`.
- Use the venv executable directly to distinguish PATH from installation issues.
- Confirm `python -m pip --version` points into the intended venv.

## Python and virtual environments

ADAF-ATTACK requires Python 3.11-3.13. The Windows installer accepts
`-Python <full-path>` or `-Python py -PythonVersion 3.13`. On Debian-family
systems, install `python3-venv` if venv creation fails. A PEP 668
`externally-managed-environment` error means pip is protecting the system Python:
create a venv instead of using `sudo pip` or `--break-system-packages`.

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

## Offline or air-gapped install

Build a wheelhouse on a connected host matching the offline OS and Python
family:

```bash
python -m pip download --dest wheelhouse "./adaf_attack-0.10.0-py3-none-any.whl[full]"
python -m pip install --no-index --find-links wheelhouse "adaf-attack[full]==0.10.0"
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
`doctor --explain` distinguishes required failures from optional warnings.

## Read-only profile or managed workstation

If `doctor` reports that the data or configuration directory is not writable,
choose writable per-user locations and rerun the check:

```powershell
$env:ADAF_ATTACK_DATA_DIR = "D:\adaf-data"
$env:ADAF_ATTACK_CONFIG_DIR = "D:\adaf-config"
$env:ADAF_ATTACK_WORKSPACE = "D:\adaf-workspaces"
adaf-attack --format json doctor --explain
```

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
