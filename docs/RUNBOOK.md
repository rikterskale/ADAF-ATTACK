# ADAF-ATTACK operator runbook

This is the shortest safe operating loop for one authorized operator. The
tool is proprietary and is for written, approved internal red-team work only.

## 1. Install and verify

Use an approved private wheel or source checkout; this project is not on
PyPI. From the installed environment:

```bash
adaf-attack doctor --profile user-readiness
adaf-attack --format json doctor --explain > doctor.json
adaf-attack quickstart --workspace ./quickstart
adaf-attack guide --workspace ./quickstart --session ./quickstart/demo-session
```

The quickstart is offline. Before a live command, verify the target, account,
scope, and approval token in the engagement paperwork. When lost, run
`adaf-attack guide` — it returns one copy-ready next step for the current
journey stage (install → authorize → operate → report → closeout).

## 2. Discover, plan, then run

The normal solo workflow is:

```bash
adaf-attack guide
adaf-attack list-capabilities --by-phase
adaf-attack capability-help ldap-enum
adaf-attack plan ldap-enum -d corp.example --dc-ip 10.0.0.10
adaf-attack run ldap-enum -d corp.example --dc-ip 10.0.0.10 -u operator
adaf-attack workflow import-session --session <session>
adaf-attack guide
adaf-attack run attack-paths -d corp.example --dc-ip 10.0.0.10
adaf-attack run next-actions -d corp.example --dc-ip 10.0.0.10
```

Use `-P key=value` for capability-specific options. Review the plan and the
session artifacts before any operation requiring `--force`; destructive and
network-side-effect operations also require the acknowledgement or scoped
approval required by the capability safety profile. Direct target-interacting
execution also requires `--approval-token` and its matching `--engagement-id`;
the engagement workflow supplies these automatically after scope validation.

Useful daily commands are `doctor`, `paths`, `capability-help`, `plan`,
`run ldap-enum`, `run acl-enum`, `run adcs-enum`, `run attack-paths`, `run
next-actions`, `session show`, and `rollback`.

## 3. JSON scripting

Every non-interactive command supports a stable JSON document with `"ok":
true` on success. Keep stdout for the document and send diagnostics to
stderr:

```bash
adaf-attack --format json run ldap-enum -d corp.example --dc-ip 10.0.0.10 \
  -u operator > result.json
python -c 'import json,sys; print(json.load(open("result.json"))["session_path"])'
```

Generated example commands are review-only. They are shell-quoted for names,
domains, hosts, filters, and service principals containing spaces or shell
metacharacters. Treat `<attacker-ip>`, `<sam>`, and other angle-bracket values
as required operator substitutions; do not paste them unchanged.

For a single-operator review, use `list-capabilities --full` when the compact
catalog is not enough. `list-capabilities --copy` and `rank-paths --copy` copy
tab-separated tables without invoking a shell. Clipboard support uses `clip`,
`pbcopy`, `wl-copy`, `xclip`, or `xsel`, whichever is available. `rank-paths
--full` keeps every path segment.

Evidence-backed command examples may include `follow_on_commands`: offline
Hashcat modes for Kerberoast/AS-REP files and review-only ticket-vault import
steps for generated ccache artifacts. These snippets never execute
automatically; validate the artifact path and authorization first.

## 4. Preserve context and undo changes

Keep the session directory for the engagement. It contains the event log,
graph, findings, outcome, and cleanup state. `next-actions` records the
observed evidence and rationale used to recommend each action. If a mutation
was performed, inspect the cleanup status before closing the engagement:

```bash
adaf-attack cleanup-status --session ./adaf-workspace/<session>
adaf-attack run rollback -d corp.example --dc-ip 10.0.0.10 \
  -P session=./adaf-workspace/<session> --force
adaf-attack session show --session ./adaf-workspace/<session>
```

Rollback is best-effort and capability-specific. Confirm the target state
afterward and document any manual cleanup, especially issued certificates,
captured tickets, external relay processes, or credentials already exposed.

For a complete command surface, see [CLI_REFERENCE.md](CLI_REFERENCE.md).
