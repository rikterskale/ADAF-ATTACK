# ADAF-ATTACK

**Aggressive Active Directory offensive toolkit for senior internal red teamers.**

> Authorized internal red team use only.

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
  [Kali](docs/KALI.md) · [Windows commands](docs/WINDOWS_COMMAND_GUIDE.md) ·
  [Linux commands](docs/LINUX_COMMAND_GUIDE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md) ·
  [Known limitations](docs/KNOWN_LIMITATIONS.md) · [Changelog](CHANGELOG.md)
- [New-user readiness guide](docs/USER_READINESS.md) ·
  [Feature and support matrix](docs/FEATURE_MATRIX.md) ·
  [Disposable AD lab validation](docs/LIVE_AD_LAB_VALIDATION.md) ·
  [Live capability matrix](docs/LIVE_CAPABILITY_MATRIX.md) ·
  [Supported platforms and architectures](docs/SUPPORTED_PLATFORMS.md)

## Philosophy

- No plan-only / lab-cert / containment gates
- Lightweight controls: `--force`, redaction by default, session logging

## Capabilities

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

Credential access:

| ID | Description |
|----|-------------|
| `kerberoast`, `asrep-roast` | hashcat `$krb5tgs$` / `$krb5asrep$` |
| `dcsync` | MS-DRSR replication-based NT/LM/AES extraction |
| `secretsdump-local` | SAM/LSA/DPAPI dump from a compromised host |
| `password-spray` | Lockout-aware LDAP spray |
| `laps-read` | LAPS v1 + v2 password retrieval |
| `gpp-cpassword-hunt` | Locate + decrypt legacy GPP cpassword (MS14-025) |
| `shadow-creds` | Enumerate + write `msDS-KeyCredentialLink` |
| `unpac-the-hash` | Recover NT hash from a PKINIT-only cert |

Kerberos operations:

| ID | Description |
|----|-------------|
| `pkinit-auth` | Auth via PFX / PEM cert to a TGT |
| `ticket-forge` | Golden / silver / sapphire ticket forgery |
| `s4u-abuse` | Full S4U2Self + S4U2Proxy chain (constrained delegation / RBCD) |
| `ticket-lifecycle` | CCache/PFX import, export, PEM<->PFX conversion |

Privilege escalation / lateral movement:

| ID | Description |
|----|-------------|
| `acl-write` | Apply approved raw ACL descriptor with rollback |
| `cert-request` | Enroll certificate (ESC1-style with alt-name) |
| `rbcd` | Read / write RBCD `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| `template-mod` | Flip AD CS template to ESC1-vulnerable with rollback |
| `esc-chain` | Automated ESC1-ESC8 exploit chain |
| `computer-takeover` | Full computer-object takeover recipe |
| `impacket-exec` | wmiexec / smbexec / dcomexec / atexec |
| `coerce` | PetitPotam / PrinterBug / DFSCoerce / ShadowCoerce triggers |
| `ntlm-relay` | Managed ntlmrelayx run with fixed target allowlist |

Analysis / reporting:

| ID | Description |
|----|-------------|
| `bloodhound-export` | JSON + zip for BloodHound CE |
| `attack-paths`, `blast-radius` | Ranking and reachable-impact analysis |
| `next-actions` | Ranked, review-first plans with risk tags |
| `report` | Canonical findings + evidence bundle |

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
python -m pip install "./adaf_attack-0.10.0-py3-none-any.whl[full]"
```

On Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install ".\adaf_attack-0.10.0-py3-none-any.whl[full]"
```

For an internal release bundle, the portable bootstrap performs the same clean
environment setup on every OS:

```bash
python scripts/install-approved-wheel.py \
  --wheel ./adaf_attack-0.10.0-py3-none-any.whl \
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

```bash
python -m pip check
adaf-attack --version
adaf-attack doctor --explain
adaf-attack list-capabilities
adaf-attack paths
```

`doctor --explain` verifies the interpreter, architecture, runtime packages,
virtual environment, writable paths, and optional external tools such as
`ntlmrelayx` and `certipy`. Missing optional tooling is reported with
remediation; it does not invalidate the base installation. Use an explicit
profile when checking a broader workflow:

```bash
adaf-attack --format json doctor --profile operator
adaf-attack --format json doctor --profile certipy
adaf-attack --format json doctor --profile live-ad \
  --domain lab.example --dc-ip 10.0.0.10
```

The default `offline` profile never performs network probes. The `live-ad`
profile performs only explicit DNS and TCP preflight checks; it does not
authenticate or execute a capability.

For the complete wheel-only acceptance path, run:

```bash
adaf-attack doctor --profile user-readiness
adaf-attack demo --workspace ./demo-session
```

For the shortest safe first run, use the single-command quickstart. It checks
the installation and creates a disposable offline demo session without
contacting a domain controller:

```bash
adaf-attack quickstart --workspace ./quickstart
```

If the quickstart reports a permissions problem, run:

```bash
adaf-attack paths --repair
adaf-attack quickstart --workspace ./quickstart
```

For support, export a redacted diagnostic bundle and review it before sharing:

```bash
adaf-attack --format json support-bundle --output adaf-support-bundle.json
```

## First safe offline success

These commands do not contact a domain controller and do not modify a target:

```bash
adaf-attack --format json doctor --explain
adaf-attack --format json list-capabilities
adaf-attack --format json paths
```

Exit code `0` and JSON containing `"ok": true` confirm the install. `paths`
shows where future session evidence will be stored.

Without an AD lab, the supported offline functionality includes diagnostics,
capability discovery, planning, evidence correlation, engagement reporting,
and package generation. LDAP reconnaissance, Kerberos, AD CS, relay/coercion,
and destructive capabilities require the disposable authorized lab described
in [LIVE_AD_LAB_VALIDATION.md](docs/LIVE_AD_LAB_VALIDATION.md).

### Recommended first 30 minutes

1. Run `adaf-attack quickstart --workspace ./quickstart`.
2. Inspect the generated session with `adaf-attack sessions show --session ./quickstart/demo-session`.
3. Generate a report with `adaf-attack engagement report --session ./quickstart/demo-session --engagement-id QUICKSTART-2026-001`.
4. Read the capability prerequisites with `adaf-attack capability-help`.
5. Create and validate a scoped plan with `adaf-attack engagement init --output engagement.yaml` and `adaf-attack engagement validate engagement.yaml`.
6. Before any target interaction, read the authorized lab and engagement guidance.

### What works without an AD lab?

| Surface | Works offline? | Additional setup |
|---|---:|---|
| Installation checks, paths, capability help | Yes | None |
| Planning and workflow profiles | Yes | None |
| Demo sessions, findings, reports, packaging | Yes | Base install; reports extra for PDF output |
| LDAP and AD reconnaissance | No | Authorized account, DNS, DC reachability |
| Kerberos and Impacket adapters | No | `[kerberos]`, DNS, synchronized clocks |
| AD CS workflows | No | Separate `[certipy]` environment and test CA |
| Relay, coercion, and destructive operations | No | Authorized disposable lab and rollback evidence |

## Offline and air-gapped installation

On a connected machine with the same OS/Python family, place the approved wheel
in an empty directory and download all dependencies:

```bash
python scripts/build-release-wheelhouse.py \
  --wheel ./adaf_attack-0.10.0-py3-none-any.whl \
  --output ./wheelhouse --extras full
```

Transfer the complete `wheelhouse` through your approved media process. On the
offline host:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --no-index --find-links wheelhouse "adaf-attack[full]==0.10.0"
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
python -m pip install --upgrade "./adaf_attack-0.10.0-py3-none-any.whl[full]"
python -m pip check
adaf-attack --version
```

The same command downgrades when the path names an older approved wheel. Keep
workspaces outside disposable virtual environments.

## Uninstall

For a direct wheel/source install, remove the isolated environment. Workspace
data is separate and must be deleted explicitly:

```bash
deactivate 2>/dev/null || true
rm -rf .venv
# Optional and destructive: rm -rf ~/.local/share/adaf-attack/workspaces
```

Windows installer users must run
`.\scripts\Install-AdafAttack.ps1 -Uninstall`; Kali installer users run
`bash scripts/install-kali.sh --uninstall`. Both preserve workspace data by
default. Their explicit `-RemoveWorkspace` / `--remove-workspace` options delete
operator data.

## Troubleshooting

Start with `adaf-attack doctor --profile offline --explain`, or use
`adaf-attack doctor --profile live-ad --domain <authorized-domain> --dc-ip <authorized-dc>`
before a target-scoped preflight. Then use the
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

`rank-paths` also emits `exploit_chains`: evidence-backed chains for findings
that are otherwise represented as self-loops in the graph (such as AD CS,
credential exposure, delegation, GPO control, and directory replication).
Each chain includes its observed terminal relation, normalized impact, tactic,
ATT&CK technique references, and confidence level.

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

## Offline versus live functionality

| Functionality | Required setup |
|---|---|
| `doctor`, `paths`, capability help, workflow profiles | Base install only |
| Reports, evidence correlation, engagement packaging | Saved session or demo fixture |
| LDAP/AD reconnaissance | Authorized account, DNS, network path to the DC |
| Kerberos/Impacket | `[kerberos]`, correct DNS and synchronized clocks |
| AD CS workflows | Separate `[certipy]` environment and test CA |
| Relay/coercion/destructive operations | Disposable lab, explicit authorization, rollback evidence |

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

The plan permits only the listed targets and capabilities. Destructive
capabilities additionally require an approval token issued by your internal
authorization service. Tokens are short-lived, target- and capability-scoped,
and logged as `approval.accepted` events. The minimal verifier uses
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
NIS2 Article 21 themes in `src/adaf_attack/mappings/`. These mappings support
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
RBCD write with a scoped S4U ticket-request handoff; a configured provider and
controlled-computer credential are still required before a ticket request is
made. Both workflows log their artifacts and decisions in the session.

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

Supply a separate approval-token mapping with `campaign-run --approval-tokens` for engagements that include destructive phases. Ticket lifecycle operations include `import-ccache`, `export-ccache`, `import-pfx`, `export-pfx`, `pem-to-pfx`, and `pfx-to-pem`.

Default workspaces:

- Linux: `~/.local/share/adaf-attack/workspaces`
- Windows: `%LOCALAPPDATA%\adaf-attack\workspaces`
- Application data override: `ADAF_ATTACK_DATA_DIR`
- Configuration override: `ADAF_ATTACK_CONFIG_DIR`
- Workspace override: `ADAF_ATTACK_WORKSPACE` or `--workspace`

## License

Private. Internal use only.
