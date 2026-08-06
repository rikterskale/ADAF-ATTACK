# ADAF-ATTACK

**Aggressive Active Directory offensive toolkit for senior internal red teamers.**

> Authorized internal red team use only.

## Philosophy

- No plan-only mode
- No lab certification gates
- No containment checks
- Lightweight professional controls only:
  - `--force` required for destructive actions
  - Clear visual warnings
  - Secrets redacted by default (`--include-secrets` to keep them)
  - Full session / workspace logging

## Current Capabilities

| ID | Category | Description |
|----|----------|-------------|
| `ldap-enum` | enumeration | Users, computers, groups, trusts, SPNs via LDAP |
| `kerberoast` | credential-access | Request TGS tickets for SPN accounts |
| `asrep-roast` | credential-access | Roast accounts with DONT_REQ_PREAUTH |

Attack-path graph is built automatically during collection (MemberOf, HasSPN, CanASREP, TrustedBy edges).

## Install

```bash
# Core (LDAP enum works out of the box)
pip install -e ".[dev]"

# + Kerberos attacks
pip install -e ".[dev,kerberos]"

# + TUI
pip install -e ".[dev,tui]"

# Everything
pip install -e ".[full]"
```

## Usage

```bash
adaf-attack doctor
adaf-attack list-capabilities

# LDAP enumeration
adaf-attack run ldap-enum -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'

# Kerberoasting (tickets redacted by default)
adaf-attack run kerberoast -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'

# Keep tickets in output
adaf-attack run kerberoast -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1' --include-secrets

# AS-REP roasting
adaf-attack run asrep-roast -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'

# Interactive TUI
adaf-attack start
```

Results and the attack graph are written under `workspaces/<session-id>/`.

## Interface

| Mode | Command | Notes |
|------|---------|-------|
| Pure CLI | `adaf-attack run ...` | Always available |
| Interactive TUI | `adaf-attack start` | Requires `textual` |

## License

Private. Internal use only.
