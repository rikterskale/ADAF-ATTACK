# ADAF-ATTACK CLI reference

This is the maintained command inventory for the registered CLI surface. The
command names are checked against the Typer application by
`python scripts/check_cli_documentation.py`. Use `adaf-attack <command> --help`
for current options, defaults, validation, and examples.

| Command | Surface |
|---|---|
| `adaf-attack ad-recon` | Read-only AD reconnaissance group |
| `adaf-attack ad-recon init` | Write a read-only reconnaissance template |
| `adaf-attack ad-recon profile` | Show the reconnaissance collection baseline |
| `adaf-attack adcs-validation` | Validate AD CS evidence offline |
| `adaf-attack bloodhound-reconcile` | Reconcile BloodHound evidence |
| `adaf-attack campaign-compose` | Compose a read-only campaign |
| `adaf-attack campaign-run` | Run an ordered campaign |
| `adaf-attack capability` | Capability command group |
| `adaf-attack capability list` | List capabilities through the command group |
| `adaf-attack capability show` | Show capability details |
| `adaf-attack capability dependencies` | Show capability prerequisite relationships |
| `adaf-attack capability-help` | Show generated capability help |
| `adaf-attack check` | Check beginner setup or preflight an authorized target |
| `adaf-attack cleanup` | Execute recorded cleanup with explicit force |
| `adaf-attack cleanup-status` | Show rollback readiness and restored-state status |
| `adaf-attack detection-status` | Record defensive detection validation |
| `adaf-attack coercion-fixtures` | Validate authorized coercion fixtures |
| `adaf-attack command` | Build a copy-ready command with option explanations |
| `adaf-attack completions` | Print shell completions |
| `adaf-attack config` | Persistent configuration command group |
| `adaf-attack config keys` | List supported configuration keys |
| `adaf-attack config set` | Set a configuration value |
| `adaf-attack config show` | Show configuration |
| `adaf-attack config unset` | Remove a configuration value |
| `adaf-attack credential-exposure` | Prioritize credential exposure evidence |
| `adaf-attack delegation-validation` | Validate delegation evidence |
| `adaf-attack demo` | Run the offline demo |
| `adaf-attack doctor` | Check local prerequisites or explicit target preflight |
| `adaf-attack engagement` | Engagement command group |
| `adaf-attack engagement init` | Create an engagement template |
| `adaf-attack engagement package` | Create a redacted evidence archive |
| `adaf-attack engagement dashboard` | Show the unified engagement dashboard |
| `adaf-attack engagement missions` | List goal-first guided missions |
| `adaf-attack engagement mission` | Show a deterministic mission workflow |
| `adaf-attack engagement report` | Generate engagement reports |
| `adaf-attack engagement run` | Run an authorized engagement plan |
| `adaf-attack engagement validate` | Validate an engagement plan |
| `adaf-attack errors` | List error codes and remediation |
| `adaf-attack favorites` | Pinned capability command group |
| `adaf-attack favorites add` | Pin a capability for quick recall |
| `adaf-attack favorites list` | List pinned capabilities |
| `adaf-attack favorites remove` | Unpin a capability |
| `adaf-attack finding` | Finding explanation and remediation command group |
| `adaf-attack finding explain` | Explain a saved finding in plain language |
| `adaf-attack finding workspace` | Open an actionable finding workspace |
| `adaf-attack finding remediate` | Build a remediation checklist for a finding |
| `adaf-attack forest-campaign` | Compose a forest-aware campaign |
| `adaf-attack glossary` | Explain Active Directory and operator terms |
| `adaf-attack gpo-impact-plan` | Plan GPO impact validation |
| `adaf-attack help-me` | Show the guided novice tour |
| `adaf-attack home` | Show goal-based starting points |
| `adaf-attack init` | First-run onboarding: check environment and save defaults |
| `adaf-attack list-capabilities` | List registered capabilities |
| `adaf-attack path` | Attack-path command group |
| `adaf-attack path rank` | Rank attack paths |
| `adaf-attack path inspect` | Inspect graph-edge evidence and risk |
| `adaf-attack paths` | Show or repair local paths |
| `adaf-attack plan` | Preview a capability run |
| `adaf-attack profile` | Target and opsec profile command group |
| `adaf-attack profile default` | Show or set the default profile |
| `adaf-attack profile delete` | Delete a profile |
| `adaf-attack profile list` | List profiles |
| `adaf-attack profile set` | Create or update a profile |
| `adaf-attack profile show` | Show a profile |
| `adaf-attack profile use` | Select a profile |
| `adaf-attack purple-handoff` | Build a detection-aware handoff |
| `adaf-attack quickstart` | Run the safe first-install flow |
| `adaf-attack query` | Query local graph and finding evidence |
| `adaf-attack start-here` | Beginner-friendly safe first-install alias |
| `adaf-attack explain` | Explain a capability in plain language |
| `adaf-attack what-next` | Recommend the next beginner-friendly action |
| `adaf-attack command-center` | Mission-control overview for an engagement |
| `adaf-attack impact-map` | Map evidence to findings, assets, and impact |
| `adaf-attack investigate` | Read-only zero-noise evidence investigation |
| `adaf-attack story` | Build an executive assessment narrative |
| `adaf-attack replay` | Replay a session timeline |
| `adaf-attack confidence` | Show evidence confidence quality |
| `adaf-attack product-templates` | List polished assessment templates |
| `adaf-attack deliverables` | Show client deliverables readiness |
| `adaf-attack rank-paths` | Rank paths from a saved graph |
| `adaf-attack recent` | Show recently viewed capabilities |
| `adaf-attack review` | Preview a capability before running it |
| `adaf-attack run` | Run a capability against a target |
| `adaf-attack search` | Search registered capabilities |
| `adaf-attack session` | Session command group |
| `adaf-attack session diff` | Compare sessions |
| `adaf-attack session access` | Show safe identity and credential context |
| `adaf-attack session resume` | Prepare a safe review/resume package |
| `adaf-attack finding triage` | View or update finding status, tags, and notes |
| `adaf-attack session list` | List workspace sessions |
| `adaf-attack session show` | Inspect a session |
| `adaf-attack sessions` | Navigate persisted sessions |
| `adaf-attack start` | Launch the Textual TUI |
| `adaf-attack start-demo` | Start the safe offline demo |
| `adaf-attack support-bundle` | Write a redacted diagnostic bundle |
| `adaf-attack targets` | List recent non-secret target identifiers |
| `adaf-attack tool` | Offline graph, evidence, scope, detection, and lab tools |
| `adaf-attack tour` | Show the guided operator tour |
| `adaf-attack trust-correlation` | Correlate trust evidence |
| `adaf-attack credential-inventory` | Inventory credential-exposure artifacts without revealing secrets |
| `adaf-attack tool graph` | Explore a saved graph offline |
| `adaf-attack tool evidence-import` | Import JSON evidence into a session |
| `adaf-attack tool scope` | Inspect an engagement scope without executing it |
| `adaf-attack tool verify` | Verify remediation evidence for a finding |
| `adaf-attack tool detect` | Export evidence-backed detection hypotheses |
| `adaf-attack tool lab` | Inspect a disposable lab manifest offline |
| `adaf-attack cockpit` | Open an evidence-first session cockpit |
| `adaf-attack what-if` | Simulate graph changes offline |
| `adaf-attack timeline` | Replay a session audit timeline |
| `adaf-attack copilot` | Recommend evidence-backed next actions |
| `adaf-attack collaboration` | Show finding ownership and comments |
| `adaf-attack workflow` | Finding-driven guided workflow command group |
| `adaf-attack workflow actions` | List derived workflow actions |
| `adaf-attack workflow audit` | Show the append-only audit history |
| `adaf-attack workflow authorize` | Record the scope authorization decision |
| `adaf-attack workflow close` | Finish and close or archive the workflow |
| `adaf-attack workflow correlate` | Link related findings |
| `adaf-attack workflow decide` | Record a decision at a decision point |
| `adaf-attack workflow do` | Complete a required or recommended action |
| `adaf-attack workflow enrich` | Enrich a finding's fields |
| `adaf-attack workflow findings` | Query findings by status, severity, or asset |
| `adaf-attack workflow import-session` | Import canonical session findings |
| `adaf-attack workflow inject` | Inject an operator finding |
| `adaf-attack workflow next` | Show ranked next actions |
| `adaf-attack workflow snapshot` | Emit full state, guidance, and recommendations |
| `adaf-attack workflow status` | Show phase, progress, risk, and next step |
| `adaf-attack workflow transition` | Advance a finding's lifecycle status |
| `adaf-attack workflow-profiles` | Show repeatable workflow profiles |

The reference intentionally documents command names centrally; detailed option
contracts remain generated by Typer help and the capability help surface.
# Session continuation and finding triage

Completed sessions can be resumed safely for review without executing a capability:

```text
adaf-attack session resume --session ./session-dir
adaf-attack finding triage --session ./session-dir --id F-001 --status acknowledged --tag review
adaf-attack session diff ./older-session ./newer-session
```

`session diff` reports aggregate changes plus added/removed finding IDs and severity deltas. Triage state is stored in `findings.json` and is included in CLI JSON output and the TUI findings dashboard.
