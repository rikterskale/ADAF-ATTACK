# ADAF-ATTACK

**Aggressive Active Directory offensive toolkit for senior internal red teamers.**

> Authorized internal red team use only.

## Platforms

| OS | Support |
|----|---------|
| **Linux** | Primary |
| **Windows** | First-class (PowerShell install, paths, scheduled tasks) |
| **macOS** | Supported (same Python stack) |

Windows guide: [docs/WINDOWS.md](docs/WINDOWS.md)

## Philosophy

- No plan-only / lab-cert / containment gates
- Lightweight controls: `--force`, redaction by default, session logging

## Capabilities (v0.6.0)

| ID | Category | Description |
|----|----------|-------------|
| `ldap-enum` | enumeration | Users, computers, groups, trusts, SPNs |
| `trusts-enum` | enumeration | Trust direction, SID filtering, forest vs external |
| `adcs-enum` | enumeration | CAs, templates, ESC1 + enrollment ACEs |
| `acl-enum` | enumeration | GenericAll, WriteDacl, WriteOwner, DCSync, … |
| `gmsa-laps-enum` | enumeration | gMSA / LAPS presence + read ACL signals |
| `kerberoast` | credential-access | hashcat `$krb5tgs$23$` |
| `asrep-roast` | credential-access | hashcat `$krb5asrep$23$` |
| `bloodhound-export` | export | JSON + zip for BloodHound CE |

## Install

**Linux / macOS**

```bash
pip install -e ".[full]"
adaf-attack doctor
```

**Windows (PowerShell)**

```powershell
.\scripts\Install-AdafAttack.ps1 -Extras full
# new terminal
adaf-attack doctor
Import-Module .\scripts\AdafAttack.psm1
```

## Examples

```bash
adaf-attack run ldap-enum -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'
adaf-attack run acl-enum -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'
adaf-attack run bloodhound-export -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'
adaf-attack paths
adaf-attack start
```

## CLI output and safety UX

Every non-interactive command supports a stable JSON document with
`--format json`; use `--no-color` for plain human-readable output and
`--non-interactive` to prevent interactive-only commands from launching.

```bash
# Diagnose prerequisites and receive specific remediation steps
adaf-attack --format json doctor --explain

# Inspect every capability or one complete generated reference
adaf-attack capability-help
adaf-attack capability-help shadow-creds

# Preview network effects and destructive-risk requirements before execution
adaf-attack --no-color plan shadow-creds -d corp.local --dc-ip 10.0.0.10

# Inspect session artifacts and read-only cleanup status
adaf-attack --format json sessions
```

Default workspaces:

- Linux: `~/.local/share/adaf-attack/workspaces`
- Windows: `%LOCALAPPDATA%\adaf-attack\workspaces`
- Override: `ADAF_ATTACK_WORKSPACE` or `--workspace`

## License

Private. Internal use only.
