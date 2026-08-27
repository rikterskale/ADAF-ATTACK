---
guide_id: windows-novice-usability
guide_schema_version: 1
platform: windows
canonical_path: docs/WINDOWS_NOVICE_USABILITY_GUIDE.md
project_name: ADAF-ATTACK
target_release: 0.10.1
support_status: hosted_ci_artifact_and_installer_smoke
primary_shells: ["Windows PowerShell 5.1", "PowerShell 7"]
maintainer_source_of_truth: pyproject.toml
---

# ADAF-ATTACK Windows new-user guide

Use ADAF-ATTACK only under written authorization. The safe first run below is
offline and does not contact Active Directory.

## Prerequisites

- 64-bit Windows 10/11 or Windows Server
- Python 3.11-3.14 from python.org, including the `py` launcher
- Windows PowerShell 5.1 or PowerShell 7
- Git when using a source checkout
- Access to this private repository or an approved release wheel

Check the launcher before installing:

```powershell
py -0p
py -3.11 --version
```

## Download or clone

For the release path, download the approved `.whl` from the private GitHub
release. To use the installer, clone or extract the matching source release:

```powershell
git clone <approved-repository-url> ADAF-ATTACK
Set-Location .\ADAF-ATTACK
```

The working directory must contain `pyproject.toml` and `scripts`.

## Install

Place the wheel in `dist`, then run the PowerShell 5.1-compatible installer:

```powershell
.\scripts\Install-AdafAttack.ps1 `
  -Package .\dist\adaf_attack-0.10.1-py3-none-any.whl `
  -Extras full `
  -Python py `
  -PythonVersion 3.11
```

For an authorized source checkout before a release asset exists:

```powershell
.\scripts\Install-AdafAttack.ps1 -Extras full -Python py -PythonVersion 3.11
```

The installer creates `.venv`, `%LOCALAPPDATA%\adaf-attack\bin\adaf-attack.cmd`,
an ownership record, and `%LOCALAPPDATA%\adaf-attack\workspaces`. It adds only
its shim directory to the user PATH. Open a new terminal after installation.

## Verify

```powershell
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace .\quickstart
adaf-attack guide --workspace .\quickstart --session .\quickstart\demo-session
adaf-attack list-capabilities
adaf-attack paths
```

If the command is not found in the current window, either open a new terminal or
run `.\.venv\Scripts\adaf-attack.exe` for the immediate verification.

When lost, run `adaf-attack guide`. It always returns one copy-ready next step.

## First safe offline run

```powershell
adaf-attack --format json doctor --explain
adaf-attack --format json list-capabilities
adaf-attack --format json paths
```

Each result should contain `"ok": true`. `paths` identifies the workspace where
future `session.json`, `events.jsonl`, findings, and reports are written. These
commands create no target artifacts.

## Stop or cancel

Press `Ctrl+C` once. Wait for the command to stop and preserve its session
directory; do not delete evidence while a process is still writing. Onboarding
commands above finish on their own.

## Upgrade and downgrade

Download the exact approved wheel, then rerun the installer. It upgrades or
downgrades the existing venv and runs `pip check`:

```powershell
.\scripts\Install-AdafAttack.ps1 `
  -Package .\dist\adaf_attack-0.10.1-py3-none-any.whl `
  -Extras full `
  -Python py `
  -PythonVersion 3.11
adaf-attack --version
```

## Uninstall and data preservation

The default uninstall removes only installer-owned components: `.venv`, the
shim, its exact user PATH entry, and its owned environment variable. It
preserves workspaces:

```powershell
.\scripts\Install-AdafAttack.ps1 -Uninstall
```

Delete workspace evidence only after retention approval:

```powershell
.\scripts\Install-AdafAttack.ps1 -Uninstall -RemoveWorkspace
```

Verify with `Get-Command adaf-attack -ErrorAction SilentlyContinue` in a new
terminal and inspect `%LOCALAPPDATA%\adaf-attack\workspaces`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Script execution is disabled | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or use an approved process-scope policy. |
| SmartScreen marks downloaded scripts | Verify source/signature, then `Unblock-File .\scripts\Install-AdafAttack.ps1`. |
| Wrong Python is selected | Use `py -0p`, then pass `-Python <full-python.exe-path>`. |
| `adaf-attack` is not found | Open a new terminal; verify the exact shim directory in user PATH. |
| pip reports proxy/certificate errors | Configure the approved proxy and CA; do not use `--trusted-host` as a blanket bypass. |
| Optional tooling conflicts | Keep Certipy or other conflicting tools in a separate venv and rerun `doctor --explain`. |

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for full diagnostics and offline
installation guidance.

## Support boundaries

Hosted CI exercises wheel installation on Windows and the installer under
Windows PowerShell 5.1/Python 3.11 and PowerShell 7/Python 3.14. It does not
prove live AD connectivity, endpoint security policy compatibility, scheduled
task credentials, or destructive capability rollback in your environment.

---

## Command reference (Windows)

This is the PowerShell command reference for authorized internal assessments.
Run commands from the repository root or activate the project virtual
environment first. Replace every value in angle brackets with engagement-
approved data.

### Install and verify

```powershell
.\scripts\Install-AdafAttack.ps1 `
  -Package .\dist\adaf_attack-0.10.1-py3-none-any.whl `
  -Extras full
.\.venv\Scripts\Activate.ps1
adaf-attack --version
adaf-attack doctor --explain
adaf-attack paths
```

If script execution is blocked, set the policy only for the current user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

The installer creates `.venv`, a user PATH shim, and the default workspace at
`%LOCALAPPDATA%\adaf-attack\workspaces`. Override it per shell when needed:

```powershell
$env:ADAF_ATTACK_WORKSPACE = 'D:\assessment\adaf-workspaces'
```

### Global options and output

Global options apply to every command, but must appear before the command:
`--format human|json`, `--no-color`, and `--non-interactive`. Use JSON for
automation and save it outside the session workspace when it is a pipeline
input.

```powershell
adaf-attack --format json doctor --explain
adaf-attack --no-color list-capabilities
adaf-attack capability-help
adaf-attack capability-help ldap-enum
```

### Target command shape

All target-interacting capabilities use the following common shape:

```powershell
adaf-attack run <capability> -d <domain> --dc-ip <dc-or-host> `
  [-u <user> -p <password> | --hashes <lm:nt-or-nt> | -k --ccache <path>] `
  [--aes-key <hex>] [--ldaps] [--workspace <directory>]
```

For JSON output, put the global option before `run`, for example:

```powershell
adaf-attack --format json run <capability> -d <domain> --dc-ip <dc-or-host>
```

`-k`/`--kerberos` selects ticket authentication. `--ccache` sets `KRB5CCNAME`.
`--creds-file <path>` permits authorized credential rotation. `--include-secrets`
disables output redaction; keep it off unless the engagement requires it.

Before any target-interacting run, preview the expected effects:

```powershell
adaf-attack plan <capability> -d <domain> --dc-ip <dc-or-host>
```

### Capability reference

| Capability | Purpose | Capability-specific options |
|---|---|---|
| `ldap-enum` | LDAP users, computers, groups, SPNs, trusts, delegation, and links | common options |
| `trusts-enum` | Trust direction, type, and SID-filtering evidence | common options |
| `acl-enum` | ACL edges and replication rights | `--scope high-value|domain|full`, `--max-objects <n>` |
| `adcs-enum` | CA, template, and ESC signal discovery | common options |
| `gmsa-laps-enum` | gMSA/LAPS presence and access signals | common options; redaction remains default |
| `kerberoast` | Service-ticket collection evidence | common options; requires Kerberos extra |
| `asrep-roast` | Pre-authentication-disabled account evidence | common options; requires Kerberos extra |
| `coercion-map` | Spooler/EFSRPC surface mapping | common options |
| `rbcd` | RBCD evidence | common options; mutation path requires `--force` |
| `shadow-creds` | Key-credential-link evidence | `--sam <account>`; mutation path requires `--force` |
| `gpo-abuse` | Writable GPO, link, and ACL evidence | common options |
| `gpo-sysvol` | SYSVOL write-surface evidence | `--gpo <name>`; stage path requires `--force` |
| `cert-request` | Certificate request operation | `--template`, `--ca`, `--alt-name`; requires `--force` |
| `pkinit-auth` | Certificate-based Kerberos authentication | `--sam`, `--key`, `--cert`, or `--pfx`; requires `--force` |
| `attack-paths` | Rank graph paths from a saved or prior graph | `--graph`, `--start`, `--max-depth`, `--limit` |
| `bloodhound-export` | BloodHound CE graph JSON and ZIP export | common options |
| `report` | Session Markdown/HTML report | common options |

Capabilities marked destructive are guarded by `--force`; use the command
reference and `plan` output as the pre-execution record. This guide does not
provide mutation procedures.

### Offline analysis commands

These commands do not contact a domain controller. Use PowerShell paths and
repeat `--session` where shown.

```powershell
adaf-attack rank-paths --graph 'D:\evidence\graph.json' --start <principal> --max-depth 6 --limit 25 --output 'D:\evidence\ranked.json'
adaf-attack credential-exposure --session 'D:\evidence\session-a' --session 'D:\evidence\session-b'
adaf-attack bloodhound-reconcile --session 'D:\evidence\session-a' --bloodhound 'D:\evidence\bloodhound.json'
adaf-attack trust-correlation --session 'D:\evidence\session-a' --session 'D:\evidence\session-b'
adaf-attack delegation-validation --session 'D:\evidence\session-a'
adaf-attack adcs-validation --session 'D:\evidence\session-a'
adaf-attack campaign-compose --session 'D:\evidence\session-a' --session 'D:\evidence\session-b'
adaf-attack purple-handoff --session 'D:\evidence\session-a'
adaf-attack gpo-impact-plan --session 'D:\evidence\session-a'
adaf-attack workflow-profiles
adaf-attack workflow-profiles purple-team
```

`coercion-fixtures` reads only fixture files but requires explicit confirmation:

```powershell
adaf-attack coercion-fixtures --fixtures 'D:\fixtures' --authorized-fixtures
```

### Sessions, artifacts, and TUI

```powershell
adaf-attack sessions
adaf-attack sessions --workspace 'D:\assessment\adaf-workspaces'
adaf-attack sessions --session <session-id>
adaf-attack start
```

Each run creates `session.json`, `events.jsonl`, result JSON files, and usually
`graph.json`. `rank-paths` returns both conventional paths and
`exploit_chains`, with observed relation, impact, tactic, ATT&CK references,
and confidence.

### Troubleshooting

| Symptom | Action |
|---|---|
| `ldap3` missing | Re-run `.\scripts\Install-AdafAttack.ps1 -Extras full`. |
| Kerberos feature unavailable | Install the `kerberos` or `full` extra. |
| TUI dependency missing | Install the `tui` or `full` extra. |
| `GRAPH_NOT_FOUND` | Pass an existing `graph.json` to `rank-paths`. |
| Session not found | Use `adaf-attack sessions` to identify the exact directory. |
| JSON needs parsing | Use `--format json --no-color`; do not scrape the table output. |

For installer upgrade/uninstall, PATH cleanup, data preservation, and offline
setup, use the [Windows new-user guide](WINDOWS_NOVICE_USABILITY_GUIDE.md) and
[troubleshooting guide](TROUBLESHOOTING.md).
