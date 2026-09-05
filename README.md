# ADAF-ATTACK

[![CI](https://github.com/rikterskale/ADAF-ATTACK/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rikterskale/ADAF-ATTACK/actions/workflows/ci.yml)
[![CodeQL](https://github.com/rikterskale/ADAF-ATTACK/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/rikterskale/ADAF-ATTACK/actions/workflows/codeql.yml)
[![Python](https://img.shields.io/badge/python-3.11%20|%203.12%20|%203.13%20|%203.14-blue)](pyproject.toml)
[![License: Proprietary](https://img.shields.io/badge/license-Proprietary-lightgrey)](#license)

**Authorized Active Directory offensive toolkit. Start with `adaf-attack guide`.**

> Authorized internal red team use only. Proprietary. Not on PyPI.

### Who this is for / what it will not do

| For | Not for |
|---|---|
| Authorized internal red / purple teams with written scope | Public or unauthorized AD testing |
| Operators with an approved private wheel or checkout | Invented public install URLs, pipx/uv/Poetry release paths |
| Offline-first install, guidance, evidence, reporting, rollback | “Plan-only” containment theater or auto-running destructive work |
| Guided next steps via `adaf-attack guide` | Reading source to guess the next command |

Setup and `guide` never contact a domain controller. Recommendations never
auto-execute destructive work. Destructive runs still require `--force` and/or
approval tokens; mutating capabilities record rollback pre-state.

## Quick start (first ten minutes)

From an approved wheel to a guided offline first success (no domain controller).
Create a venv first. Windows and Kali operators should use their platform
installer instead of this block.

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install "./adaf_attack-0.10.1-py3-none-any.whl[full]"
python -m pip check
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace ./quickstart
adaf-attack --format json guide --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack --format json paths
```

Expect every command to exit `0`, doctor `"ready": true`, and one copy-ready
`suggested_command` from `guide`.

**When lost:** run `adaf-attack guide` (with the same `--workspace` /
`--session`). It is the single authoritative next step from install through
closeout. CLI and TUI share the same journey snapshot.
For parity checks, `what-next`, `workflow next`, `tour`, and `home` accept the
same workspace/session hints and should emit the same `suggested_command`.

Journey stage labels (character-for-character with `guide` / TUI Home):

| Stage id | Label |
|---|---|
| `install-blocked` | Install readiness |
| `session-blocked` | Session context |
| `first-success` | Safe offline first success |
| `orient` | Authorize scope |
| `discover` | Baseline discovery |
| `operate` | Finding-driven operations |
| `deliver` | Reporting and packaging |
| `closeout` | Engagement closeout |
| `complete` | Complete |

Surfaces use Ready / Blocked / Failed / Done. Empty findings dashboards name the
same next command `guide` would print.

If any step fails: `adaf-attack --format json doctor --profile user-readiness --explain`,
then `adaf-attack --format json support-bundle --output adaf-support-bundle.json`.
See [Troubleshooting](docs/TROUBLESHOOTING.md). Windows and Kali operators should
start from their platform guide below rather than pip directly.

## Platform guides

| OS | Support |
|----|---------|
| **Kali Linux** | First-class (installer, platform detection, XDG paths) |
| **Linux** | Primary (generic distributions) |
| **Windows** | First-class (PowerShell install, paths, scheduled tasks) |
| **macOS** | Supported (wheel install and POSIX paths) |

- New-user guides: [Windows](docs/WINDOWS_NOVICE_USABILITY_GUIDE.md) ·
  [Linux](docs/LINUX_NOVICE_USABILITY_GUIDE.md) · [macOS](docs/MACOS.md)
- Platform/operator references: [Windows](docs/WINDOWS.md) ·
  [Kali](docs/KALI.md). Command references live in the new-user guides above.
- [Troubleshooting](docs/TROUBLESHOOTING.md) ·
  [Installation guide](docs/INSTALLATION.md) ·
  [Single-operator runbook](docs/RUNBOOK.md) ·
  [Known limitations](docs/KNOWN_LIMITATIONS.md) · [Changelog](CHANGELOG.md)
- [New-user readiness guide](docs/USER_READINESS.md) ·
  [Feature and support matrix](docs/FEATURE_MATRIX.md) ·
  [Supported platforms and architectures](docs/SUPPORTED_PLATFORMS.md)
- Architecture and internals:
  [Architecture](docs/ARCHITECTURE.md) ·
  [Environment variables](docs/ENVIRONMENT_VARIABLES.md) ·
  [Session data model](docs/SESSION_DATA_MODEL.md) ·
  [Engagement schema](docs/ENGAGEMENT_SCHEMA.md) ·
  [Approval tokens](docs/APPROVAL_TOKENS.md) ·
  [Vault operations](docs/VAULT_OPERATIONS.md) ·
  [Rollback matrix](docs/ROLLBACK_MATRIX.md) ·
  [Plugin authoring](docs/PLUGIN_AUTHORING.md) ·
  [Engineering](docs/ENGINEERING.md) ·
  [Verified completion roadmap](docs/ROADMAP_ENHANCEMENTS.md)

## Philosophy

- No plan-only or containment gates
- Lightweight controls: `--force`, approval tokens, redaction by default, session logging
- `guide` is the only authoritative “what next” surface

## Operator orientation

| Need | Command |
|---|---|
| What do I do next? | `adaf-attack guide` |
| Where are logs/sessions? | `adaf-attack paths` (repair with `paths --repair`) |
| Is the install healthy? | `adaf-attack doctor --profile user-readiness --explain` |
| Redacted support pack | `adaf-attack support-bundle --output adaf-support-bundle.json` |
| Undo directory mutations | `adaf-attack rollback` / `cleanup-status` |
| Leave safely | Uninstall preserves data by default (see [Uninstall](#uninstall)) |

Canonical decision guide: [docs/USER_READINESS.md](docs/USER_READINESS.md).
Release-manager MANUAL pack: [docs/RELEASE_EVIDENCE.md](docs/RELEASE_EVIDENCE.md).
Vendor scorecard: [docs/VENDOR_SCORECARD.md](docs/VENDOR_SCORECARD.md).
Security reports: [SECURITY.md](SECURITY.md).

## Capabilities

> The tables below highlight commonly used capabilities. For the complete
> catalog of 90+ registered capabilities with maturity, risk, and approval
> metadata, see [docs/CAPABILITY_CATALOG.md](docs/CAPABILITY_CATALOG.md).

Discovery / enumeration:

| ID | Description |
|----|-------------|
| `ldap-enum` | Users, computers, groups, trusts, SPNs |
| `trusts-enum` | Trust direction, SID filtering, forest vs external |
| `adcs-enum` | CAs, templates, ESC1 + enrollment ACEs |
| `adcs-policy-probe` | ESC10 / ESC11 / ESC13 policy evaluation |
| `acl-enum` | GenericAll, WriteDacl, WriteOwner, DCSync, … |
| `gmsa-laps-enum` | gMSA / LAPS presence + read ACL signals |
| `sysvol-hunt` | Search SYSVOL for credentials and drop paths |
| `coercion-map` | Enumerate coercion-relevant RPC endpoints |
| `gpo-abuse`, `gpo-link`, `gpo-sysvol` | Writable GPOs, links, SYSVOL paths |
| `asreq-userhunt` | Validate usernames via AS-REQ without lockout impact |
| `ad-cve-scan` | Non-exploiting Zerologon/noPAC/Certifried/signing posture |
| `rodc-delegation` | RODC KRBTGT and delegation exposure |
| `bloodhound-import` | Import BloodHound identity evidence for offline analysis |
| `hybrid-signals` | Correlate hybrid identity signals |

Credential access:

| ID | Description |
|----|-------------|
| `kerberoast`, `asrep-roast` | hashcat `$krb5tgs$` / `$krb5asrep$` |
| `dcsync` | MS-DRSR replication-based NT/LM/AES extraction |
| `secretsdump-local` | SAM/LSA/DPAPI dump from a compromised host |
| `password-spray` | Lockout-aware LDAP spray (scoped approval required; fails closed without verified lockout policy) |
| `laps-read` | LAPS v1 + v2 password retrieval |
| `gpp-cpassword-hunt` | Locate + decrypt legacy GPP cpassword (MS14-025); plaintext is redacted by default |
| `shadow-creds` | Enumerate + write `msDS-KeyCredentialLink` |
| `unpac-the-hash` | Recover NT hash from PAC_CREDENTIAL_INFO after PKINIT (Certipy UnPAC or U2U + AS-REP key) |

Kerberos operations:

| ID | Description |
|----|-------------|
| `pkinit-auth` | Auth via PFX / PEM cert to a TGT |
| `ticket-forge` | Golden / silver / sapphire ticket forgery |
| `s4u-abuse` | Full S4U2Self + S4U2Proxy chain (constrained delegation / RBCD) |
| `ticket-lifecycle` | CCache/PFX import, export, PEM<->PFX conversion |
| `shadow-pkinit-workflow`, `rbcd-ticket-workflow` | Guided Kerberos workflow wrappers |

Privilege escalation / lateral movement:

| ID | Description |
|----|-------------|
| `acl-write` | Apply approved raw ACL descriptor with rollback |
| `cert-request` | Enroll certificate (ESC1-style with alt-name) |
| `rbcd` | Read / write RBCD `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| `template-mod` | Flip AD CS template to ESC1-vulnerable with rollback |
| `esc-chain` | Guided ESC1-ESC8 chain; ends in generated playbooks/handoff (external provider required) |
| `computer-takeover` | Full computer-object takeover recipe |
| `impacket-exec` | Scoped remote execution via wmiexec / smbexec / dcomexec / atexec; reports actual execution status |
| `coerce` | PetitPotam / PrinterBug / DFSCoerce / ShadowCoerce triggers |
| `ntlm-relay` | Managed ntlmrelayx run with fixed target allowlist |
| `rollback` | Apply an approved recorded rollback operation |

Analysis / reporting:

| ID | Description |
|----|-------------|
| `bloodhound-export` | JSON + zip for BloodHound CE |
| `attack-paths`, `blast-radius` | Ranking and reachable-impact analysis |
| `next-actions` | Ranked, review-first plans with risk tags |
| `report` | Canonical findings + evidence bundle |
| `credential-inventory` | Inventory credential-exposure evidence without revealing secrets |
| `campaign-run` | Execute an ordered authorized campaign |
| `purple-feedback` | Capture purple-team validation feedback |

## Prerequisites

### Choose your installation path

| Situation | Start here |
|---|---|
| Windows operator | [Windows new-user guide](docs/WINDOWS_NOVICE_USABILITY_GUIDE.md) |
| Kali operator | [Kali guide](docs/KALI.md) |
| Linux or macOS operator | [New-user readiness guide](docs/USER_READINESS.md) |
| Contributor | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Air-gapped operator | [Offline installation](docs/USER_READINESS.md#reproducible-installs) |
| No approved wheel or checkout access | Contact the repository owner; this project is not on PyPI |

Distribution access is required before installation: this project is delivered
through private release assets or an authorized source checkout. The commands
below assume that you already have an approved wheel or repository access.

For the shortest route, use the [new-user readiness guide](docs/USER_READINESS.md)
to choose the correct platform path. There is no public PyPI, pipx, uv, or
Poetry release install at this time. Docker is intentionally limited to
offline development/reporting; live AD/Kerberos workflows require host
network, DNS, clock, and authentication integration.

- Python 3.11, 3.12, 3.13, or 3.14
- A virtual environment (`python -m venv`) and pip
- Git only when installing from a source checkout
- Written authorization before any target-interacting command

The package is proprietary and is **not currently published on PyPI**. Release
installs use wheel assets attached to this repository's private GitHub releases.
If you cannot access those assets, ask the repository owner for an approved
wheel or use an authorized source checkout.

The license terms are in [LICENSE](LICENSE). Security reports belong in the
[private GitHub security channel](https://github.com/rikterskale/ADAF-ATTACK/security/advisories/new),
not in public issues.

The runtime dependency versions used by the release are pinned in both
`pyproject.toml` and [requirements-runtime.txt](requirements-runtime.txt).
The complete transitive dependency set is reproducible from the approved
wheelhouse described below.

## Recommended release install

Download the `.whl` asset for the required GitHub release, then install it into
an isolated environment. The `full` extra contains production operator features
(TUI, Kerberos, and reports), not contributor tools.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "./adaf_attack-0.10.1-py3-none-any.whl[full]"
```

On Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install ".\adaf_attack-0.10.1-py3-none-any.whl[full]"
```

For an internal release bundle, the portable bootstrap performs the same clean
environment setup on every OS:

```bash
python scripts/install-approved-wheel.py \
  --wheel ./adaf_attack-0.10.1-py3-none-any.whl \
  --venv .venv --extras full \
  --manifest ./wheelhouse/release-manifest.json
```

If your organization provides an approved package index, add
`--index-url <approved-index-url>`. For an air-gapped wheelhouse, use
`--find-links ./wheelhouse`; the script refuses to reuse an existing virtual
environment and verifies every manifest-listed artifact before installation.

The platform guides show the installer-assisted Windows and Kali paths.

## Source checkout and development install

Operators installing from an authorized checkout:

```bash
git clone <approved-repository-url> ADAF-ATTACK
cd ADAF-ATTACK
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install ".[full]"
```

Contributors use an editable install with the separate development extra:

```bash
python -m pip install --editable ".[dev,operator]"
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the pinned CI toolchain.

## Verify the installation

Use the [Quick start (first ten minutes)](#quick-start-first-ten-minutes) spine.
The shortest wheel-only acceptance path is:

```bash
python -m pip check
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace ./quickstart
adaf-attack --format json guide --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack --format json paths
```

`doctor --profile user-readiness --explain` verifies the interpreter, runtime
packages, writable paths, and packaged demo fixtures. Missing optional tooling
is reported with remediation; it does not invalidate the base installation when
`"ready": true`. Broader profiles:

```bash
adaf-attack --format json doctor --profile operator
adaf-attack --format json doctor --profile certipy
adaf-attack --format json doctor --profile live-ad \
  --domain corp.example --dc-ip 10.0.0.10
```

The default `offline` / `user-readiness` profiles never perform network probes.
The `live-ad` profile performs only explicit DNS and TCP preflight checks; it
does not authenticate or execute a capability.

If quickstart reports a permissions problem:

```bash
adaf-attack paths --repair
adaf-attack quickstart --workspace ./quickstart
```

Optional offline deliverable smoke **after** `guide` (still no DC contact):

```bash
adaf-attack engagement report --session ./quickstart/demo-session --engagement-id QUICKSTART-2026-001
adaf-attack engagement package --session ./quickstart/demo-session --output demo.zip --profile client
```

For support, export a redacted diagnostic bundle and review it before sharing:

```bash
adaf-attack --format json support-bundle --output adaf-support-bundle.json
```

## First safe offline success

Use the same spine as [Quick start](#quick-start). These commands do not contact
a domain controller and do not modify a target:

```bash
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace ./quickstart
adaf-attack --format json guide --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack --format json paths
```

Exit code `0`, doctor `"ready": true`, and a copy-ready `suggested_command` from
`guide` confirm the install. `paths` shows where session evidence will be stored.
When lost later, re-run `guide` — do not invent a parallel ladder.

Without an authorized target, the supported offline functionality includes diagnostics,
capability discovery, planning, evidence correlation, engagement reporting,
and package generation. LDAP reconnaissance, Kerberos, AD CS, relay/coercion,
and destructive capabilities additionally require an authorized target and the
relevant optional tooling; mutating capabilities record in-session rollback
state that `adaf-attack rollback` can reverse.

### Recommended first 30 minutes (always via `guide`)

1. Finish the [Quick start](#quick-start) (`doctor` → `quickstart` → `guide`).
2. Whenever unsure, re-run `adaf-attack guide --workspace ./quickstart --session ./quickstart/demo-session`
   and paste the suggested command — do not invent a parallel path.
3. Optional offline extras after guide says you are past first-success:
   `session show`, `engagement report`, `list-capabilities --novice --safe-only`.
4. Optional defaults: `adaf-attack init` (blank skips). This does not replace `guide`.
5. Before any live target work, follow your organization's engagement runbook,
   then let `guide` name the authorize / plan / run step.

### What works offline?

| Surface | Works offline? | Additional setup |
|---|---:|---|
| Installation checks, paths, capability help | Yes | None |
| Planning and workflow profiles | Yes | None |
| Demo sessions, findings, reports, packaging | Yes | Base install; reports extra for PDF output |
| LDAP and AD reconnaissance | No | Authorized account, DNS, DC reachability |
| Kerberos and Impacket adapters | No | `[kerberos]`, DNS, synchronized clocks |
| AD CS workflows | No | Separate `[certipy]` environment and approved CA |
| Relay, coercion, and destructive operations | No | Authorized target and rollback state |

## Offline and air-gapped installation

On a connected machine with the same OS/Python family, place the approved wheel
in an empty directory and download all dependencies:

```bash
python scripts/build-release-wheelhouse.py \
  --wheel ./adaf_attack-0.10.1-py3-none-any.whl \
  --output ./wheelhouse --extras full
```

Transfer the complete `wheelhouse` through your approved media process. On the
offline host:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --no-index --find-links wheelhouse "adaf-attack[full]==0.10.1"
python -m pip check
adaf-attack doctor --explain
```

The generated `wheelhouse/release-manifest.json` records the exact artifact,
dependency files, hashes, Python contract, and optional extras. Validate it
before transfer with:

```bash
python scripts/generate_release_manifest.py \
  --dist . --wheelhouse ./wheelhouse \
  --output ./wheelhouse/release-manifest.json --validate
```

Custom package indexes, proxies, and private certificate authorities must be
configured before building the wheelhouse; see
[troubleshooting](docs/TROUBLESHOOTING.md).

## Upgrade and downgrade

Install the explicitly approved artifact version into the existing environment:

```bash
python -m pip install --upgrade "./adaf_attack-0.10.1-py3-none-any.whl[full]"
python -m pip check
adaf-attack --version
```

The same command downgrades when the path names an older approved wheel. Keep
workspaces outside disposable virtual environments.

## Uninstall

Uninstall **preserves** session/workspace data by default. Confirm paths with
`adaf-attack paths` before any explicit wipe.

| Install path | Uninstall (preserves data) | Explicit data wipe |
|---|---|---|
| Windows installer | `.\scripts\Install-AdafAttack.ps1 -Uninstall` | add `-RemoveWorkspace` |
| Kali installer | `bash scripts/install-kali.sh --uninstall` | add `--remove-workspace` |
| Linux/macOS venv | `deactivate`; `rm -rf .venv` (or `$HOME/.venvs/adaf-attack`) | delete only the workspace path from `paths` |

Typical workspace roots (confirm with `paths` — do not guess):

- Linux/Kali: `~/.local/share/adaf-attack/workspaces`
- macOS: `~/Library/Application Support/adaf-attack/workspaces`
- Windows: `%LOCALAPPDATA%\adaf-attack\workspaces`

## Troubleshooting

Start with `adaf-attack --format json doctor --profile user-readiness --explain`
(or `live-ad` with `--domain` / `--dc-ip` before an authorized target preflight).
When lost after install, run `adaf-attack guide`. Attach a redacted
`support-bundle` when escalating. Then use the
[first-install troubleshooting guide](docs/TROUBLESHOOTING.md) for PATH refresh,
Python launcher selection, missing `venv`, PEP 668, PowerShell policy and
SmartScreen, proxies/custom CAs, offline installs, optional dependency conflicts,
and sanitized support evidence.

**Optional add-on: AD CS enrollment.** `cert-request` and `esc-chain` drive the
`certipy` binary. It is intentionally *not* part of `[full]` because
`certipy-ad` pins an older `cryptography`; install it in its own step (or a
dedicated venv) when you need live enrollment:

```bash
pip install "adaf-attack[certipy]"
```

If the primary operator environment already contains the pinned runtime, use a
separate venv for Certipy and expose only its executable to the operator shell:

```bash
python -m venv .venv-certipy
.venv-certipy/bin/python -m pip install "adaf-attack[certipy]"
export PATH="$PWD/.venv-certipy/bin:$PATH"
```

On Windows, prepend `.venv-certipy\\Scripts` to `PATH` instead.

The AD CS capabilities shell out to the `certipy` binary, so it must be on
`PATH` when they run. If you install Certipy into a dedicated venv, activate
that venv (or prepend its `bin`/`Scripts` directory to `PATH`) in the same
shell before running `cert-request`, `esc-chain`, or `pkinit-auth`. Verify with
`adaf-attack doctor --profile certipy`.

Without it, those capabilities still run and emit a ready-to-paste playbook.

## Examples

```bash
adaf-attack run ldap-enum -d <authorized-domain> --dc-ip <authorized-dc> -u <authorized-user>
adaf-attack run acl-enum -d <authorized-domain> --dc-ip <authorized-dc> -u <authorized-user>
adaf-attack run bloodhound-export -d <authorized-domain> --dc-ip <authorized-dc> -u <authorized-user>
adaf-attack paths
adaf-attack start
```

## First-class AD reconnaissance

Use the dedicated baseline to generate a reviewed, target-scoped plan for a
single shared evidence session. It inventories identity and trusts, ACL/AD CS/
GPO/RODC control paths, gMSA/LAPS exposure (without reading secrets), and AD
hardening posture. The baseline is read-only; review the generated allowlist
before running it.

```bash
adaf-attack ad-recon profile
adaf-attack ad-recon init --output ad-recon.yaml
adaf-attack engagement validate ad-recon.yaml
adaf-attack engagement run ad-recon.yaml --workspace ./workspaces -u <authorized-user>
```

For curated grouped execution, review a capability profile before running it:

```bash
adaf-attack capability-profile list
adaf-attack capability-profile show recon
adaf-attack capability-profile plan adcs --include-mutating
adaf-attack capability-profile run recon --domain corp.example --dc-ip 10.0.0.10 --yes
```

Profiles are deterministic groups for `recon`, `adcs`, `lateral-movement`, and
`persistence`. Approval-gated capabilities are skipped by default and only
become eligible with `--include-mutating`; grouped runs still use the scoped
engagement, approval-token, session, rollback, and findings controls.

For environments where no user credentials are available, review the
credential-free profile:

```bash
adaf-attack capability-profile show unauthenticated
adaf-attack capability-profile show unauthenticated --include-username-dependent
adaf-attack capability-profile show unauthenticated --include-noisy
```

It covers anonymous LDAP capability measurement, low-noise AD endpoint posture,
external exposure checks, and Timeroast. AS-REP/user-hunt checks are marked as
requiring a username list, while legacy Pre-Windows 2000 checks are marked as
high-noise active authentication. Use `offline-analysis` to plan saved
evidence correlation and reporting without contacting a target.

`rank-paths` also emits `exploit_chains`: evidence-backed chains for findings
that are otherwise represented as self-loops in the graph (such as AD CS,
credential exposure, delegation, GPO control, and directory replication).
Each chain includes its observed terminal relation, normalized impact, tactic,
ATT&CK technique references, and confidence level.

## CLI output and safety UX

Every non-interactive command supports a stable JSON document with
`--format json`; use `--no-color` for plain human-readable output and
`--non-interactive` to prevent interactive-only commands from launching. Add
`--debug` to emit diagnostic logging to stderr when troubleshooting a live run;
it never contaminates the `--format json` document on stdout.

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

## Offline versus live functionality

| Functionality | Required setup |
|---|---|
| `doctor`, `paths`, capability help, workflow profiles | Base install only |
| Reports, evidence correlation, engagement packaging | Saved session or demo fixture |
| LDAP/AD reconnaissance | Authorized account, DNS, network path to the DC |
| Kerberos/Impacket | `[kerberos]`, correct DNS and synchronized clocks |
| AD CS workflows | Separate `[certipy]` environment and approved CA |
| Relay/coercion/destructive operations | Explicit authorization, rollback state |

## Offline correlation workflows

The following commands operate only on saved session artifacts or authorized
fixture files: `credential-exposure`, `bloodhound-reconcile`,
`trust-correlation`, `delegation-validation`, `adcs-validation`,
`campaign-compose`, `purple-handoff`, `gpo-impact-plan`,
`coercion-fixtures`, and `workflow-profiles`.

```bash
adaf-attack credential-exposure --session /evidence/session-a --session /evidence/session-b
adaf-attack bloodhound-reconcile --session /evidence/session-a --bloodhound ./bloodhound.json
adaf-attack workflow-profiles purple-team
```

## Engagement automation and client reporting

ADAF-ATTACK can execute a reviewed, target-scoped engagement plan and preserve
an audit trail in the session evidence. Start with a template, review its
allowlist and phases, then validate it before any network action:

```bash
adaf-attack engagement init --output engagement.yaml
adaf-attack engagement validate engagement.yaml
adaf-attack engagement run engagement.yaml --workspace ./workspaces -u <authorized-user>
```

The plan permits only the listed targets and capabilities. Every target-bearing
phase option (including secondary hosts, listeners, and relay destinations) is
checked against `allowed_targets`; unknown or reserved execution options are
rejected. Any phase with network side effects, credential exposure, or target
mutation uses the capability's registered safety profile rather than a
plan-supplied risk flag.

Approved side-effect and destructive capabilities additionally require an
approval token issued by your internal authorization service. Tokens are
short-lived, target-, capability-, and phase-parameter-scoped, and logged as
`approval.accepted` events. The minimal verifier uses
`ADAF_APPROVAL_HMAC_KEY`; replace it with your internal service's asymmetric
JWKS verifier for production deployment.

Every completed engagement emits a canonical, redacted `findings.json` with
artifact hashes. Create executive, technical, and remediation deliverables
from the saved evidence without contacting the target again:

```bash
adaf-attack engagement report --session ./workspaces/<session-id> --engagement-id ENG-2026-001
```

The bundle contains print-ready HTML and, when installed with
`pip install "adaf-attack[reports]"`, PDF reports. Findings map to MITRE ATT&CK and
NIS2 Article 21 themes in `src/adaf_attack/mappings/`. The ATT&CK mapping currently
covers 8 technique IDs (T1003.006, T1098, T1134.001, T1222.001, T1484.001,
T1558.003, T1558.004, T1649); coverage will expand as capabilities mature. The NIS2
mapping covers 4 themes with 9 finding-ID mappings. These mappings support
assessment and remediation; they do not constitute a compliance certification.

For a deterministic, no-network demonstration of the reporting pipeline from a
source checkout:

```bash
python scripts/render_demo_engagement.py
```

Release-wheel users should use `adaf-attack demo`; its fixtures are included in
the wheel. For offline development and reporting, build the optional image:

```bash
docker build -t adaf-attack:local .
docker run --rm adaf-attack:local doctor --profile user-readiness
docker run --rm -v "${PWD}/output:/output" adaf-attack:local demo --workspace /output/quickstart
```

The image is an offline development/reporting quickstart, not a live-AD
deployment surface. Live Kerberos, DNS, SMB, and target-network behavior
requires host integration and is intentionally outside this Docker path.

## Session vault and workflow helpers

Set a per-engagement Fernet key to store secret vault entries encrypted at
rest. The public vault index remains redacted and records only typed material
references and safe metadata.

```bash
export ADAF_SESSION_VAULT_KEY='<Fernet key from your secret manager>'
adaf-attack run ticket-lifecycle -d corp.local --dc-ip 10.0.0.10 \
  --operation import-ccache --artifact ./operator.ccache
```

`next-actions` turns evidence-backed graph relations into ranked, reviewed
plans with risk and approval tags. It recommends commands but never executes
them automatically. `ticket-lifecycle` inventories or imports CCache material
and converts PEM key/certificate pairs to PFX for approved follow-on use.

The force-gated `shadow-pkinit-workflow` joins an approved Shadow Credentials
write with PKINIT TGT acquisition. `rbcd-ticket-workflow` joins an approved
RBCD write with a native S4U ticket request (`s4u-abuse` / Impacket `getST`)
when controlled-computer credentials are supplied
(`-P computer_password=` / `computer_hashes=` / `computer_ccache=`); without
those credentials it still writes a scoped playbook handoff. Both workflows
log their artifacts and decisions in the session.

After `adaf-attack guide` (not first-ten) and `--force` / approval, the
force-gated `unconst-tgtdump-workflow` (Kerberos section) hunts
unconstrained-delegation hosts and coerces a machine authentication. With
`-P capture=true` it also runs an in-process AP-REQ listener that harvests the
coerced machine's TGT into `<session>/captured/*.kirbi` (tune with
`capture_port`, `capture_timeout`, `capture_count`); captured tickets are
encrypted to the machine account, so decryption for S4U reuse still requires
the computer-account key offline (krbrelayx-style).

`campaign-run` executes an ordered set of independently scoped engagement plans. A Kerberos cache may be handed to a subsequent plan only by an explicit `credential_handoff.allow: true` declaration; it is loaded from the encrypted source-session vault and is never copied into the manifest or output.

```yaml
campaign_id: ENG-2026-001
engagements:
  - plan: domain-a.yaml
  - plan: domain-b.yaml
    credential_handoff:
      allow: true
      from_session: ./workspaces/domain-a-session
      item: tgt
```

Supply a separate approval-token mapping with `campaign-run --approval-tokens` for engagements that include approved side-effect or destructive phases. The token must cover the normalized phase parameters as well as the engagement, capability, and target. Ticket lifecycle operations include `import-ccache`, `export-ccache`, `import-pfx`, `export-pfx`, `pem-to-pfx`, and `pfx-to-pem`.

Default workspaces:

- Linux: `~/.local/share/adaf-attack/workspaces`
- Windows: `%LOCALAPPDATA%\adaf-attack\workspaces`
- Application data override: `ADAF_ATTACK_DATA_DIR`
- Configuration override: `ADAF_ATTACK_CONFIG_DIR`
- Workspace override: `ADAF_ATTACK_WORKSPACE` or `--workspace`

## License

Private. Internal use only.
