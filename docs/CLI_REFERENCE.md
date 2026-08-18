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
| `adaf-attack capability-help` | Show generated capability help |
| `adaf-attack cleanup` | Execute recorded cleanup with explicit force |
| `adaf-attack coercion-fixtures` | Validate authorized coercion fixtures |
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
| `adaf-attack engagement report` | Generate engagement reports |
| `adaf-attack engagement run` | Run an authorized engagement plan |
| `adaf-attack engagement validate` | Validate an engagement plan |
| `adaf-attack errors` | List error codes and remediation |
| `adaf-attack forest-campaign` | Compose a forest-aware campaign |
| `adaf-attack gpo-impact-plan` | Plan GPO impact validation |
| `adaf-attack list-capabilities` | List registered capabilities |
| `adaf-attack path` | Attack-path command group |
| `adaf-attack path rank` | Rank attack paths |
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
| `adaf-attack rank-paths` | Rank paths from a saved graph |
| `adaf-attack recent` | Show recently viewed capabilities |
| `adaf-attack run` | Run a capability against a target |
| `adaf-attack search` | Search registered capabilities |
| `adaf-attack session` | Session command group |
| `adaf-attack session diff` | Compare sessions |
| `adaf-attack session list` | List workspace sessions |
| `adaf-attack session show` | Inspect a session |
| `adaf-attack sessions` | Navigate persisted sessions |
| `adaf-attack start` | Launch the Textual TUI |
| `adaf-attack support-bundle` | Write a redacted diagnostic bundle |
| `adaf-attack tour` | Show the guided operator tour |
| `adaf-attack trust-correlation` | Correlate trust evidence |
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
