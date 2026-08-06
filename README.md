# ADAF-ATTACK

**Aggressive Active Directory offensive toolkit for senior internal red teamers.**

> Authorized internal red team use only.

## Philosophy

- No plan-only mode
- No lab certification gates
- No containment checks
- Lightweight professional controls only:
  - `--force` required for destructive actions
  - Secrets redacted by default (`--include-secrets` to keep them)
  - Full session / workspace logging

## Capabilities (v0.3.0)

| ID | Category | Description |
|----|----------|-------------|
| `ldap-enum` | enumeration | Users, computers, groups, trusts, SPNs |
| `kerberoast` | credential-access | TGS requests → hashcat `$krb5tgs$23$` |
| `asrep-roast` | credential-access | AS-REP → hashcat `$krb5asrep$23$` |

Attack-path graph is built during collection (MemberOf, HasSPN, CanASREP, TrustedBy) with basic path ranking.

## Install

```bash
pip install -e ".[dev]"                  # LDAP
pip install -e ".[dev,kerberos]"         # + roasting
pip install -e ".[dev,tui]"              # + interactive shell
pip install -e ".[full]"                 # everything
```

## CLI

```bash
adaf-attack doctor
adaf-attack list-capabilities

adaf-attack run ldap-enum -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'
adaf-attack run kerberoast -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1' --include-secrets
adaf-attack run asrep-roast -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1' --include-secrets
```

## Interactive TUI

```bash
adaf-attack start
```

- Fill Domain / DC / credentials
- Select a capability
- Toggle **Include secrets** / **Force**
- Press **Run** (or `r`)

Live output and ranked paths appear in the log panel.

## Output

Every run writes under `workspaces/<session-id>/`:

- `ldap-enum.json` / `kerberoast.json` / `asrep-roast.json`
- `*.hashes.txt` (when `--include-secrets`)
- `graph.json` (full graph + interesting summary)
- `interesting.json` (AS-REP / Kerberoastable / top paths)
- `events.jsonl` + `session.json`

## License

Private. Internal use only.
