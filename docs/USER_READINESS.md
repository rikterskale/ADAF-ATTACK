# New-user readiness guide

This is the short decision guide for a technical user who does not know the
project yet. ADAF-ATTACK is proprietary, is not published on PyPI, and is for
authorized internal red-team work only.

## Choose one installation path

| Situation | Use | Result |
|---|---|---|
| Windows operator with a release wheel | `scripts/Install-AdafAttack.ps1` | Managed user install and PATH shim |
| Kali operator with a release wheel | `scripts/install-kali.sh` | Kali dependencies and managed venv |
| Linux or macOS operator | Private release wheel in a venv | Supported CLI install; macOS is offline-CLI focused |
| Contributor | Authorized checkout plus `.[dev,operator]` | Editable development install |
| Air-gapped operator | Approved wheelhouse | Reproducible offline install |
| No private release/checkout access | Ask the repository owner | There is no public PyPI install |

Docker, pipx, uv, and Poetry are not release installation surfaces today. Do
not invent a public package URL or use an unapproved mirror. Docker may be used
only for offline development/reporting; live AD/Kerberos behavior requires
host-integrated DNS, clock, authentication, and network access.

## First ten minutes

After installing an approved wheel, run this safe sequence. It does not contact
AD or modify a target. This block is the single first-ten canon shared with the
README Quick start, platform guides, and release evidence pack:

```bash
python -m pip check
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace ./quickstart
adaf-attack --format json guide --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack --format json paths
```

If every command exits with status 0 and the doctor JSON reports
`"ready": true` (also mirrored under `readiness.ready`), the base installation
is usable. The doctor checks the installed runtime modules, writable application
directories, and packaged demo fixtures. Optional warnings are expected when
TUI, Kerberos, reporting, Certipy, or Impacket command-line tools were not
selected.

When lost at any point, run `adaf-attack guide` with the current `--workspace`
and `--session`. It is the single authoritative next step from install through
closeout (CLI and TUI share the same journey). `tour` and `home` use the
default workspace only; for a custom workspace or session, call `guide` with
those flags.

Journey stage labels match CLI and TUI character-for-character:

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

Status language across surfaces: Ready / Blocked / Failed / Done.

If a managed workstation blocks the default application directories, repair
missing directories and retry:

```bash
adaf-attack paths --repair
adaf-attack quickstart --workspace ./quickstart
```

### After first success (optional)

Confirm that `workflow next` agrees with `guide` for the same snapshot, then
continue only by pasting `guide`'s `suggested_command`:

```bash
adaf-attack --format json workflow next --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack list-capabilities --novice --safe-only
```

For a second disposable offline demo from a release wheel (still no DC):

```bash
adaf-attack demo --workspace ./demo-session
adaf-attack engagement report --session ./demo-session/demo-session --engagement-id DEMO-2026-001
adaf-attack engagement package --session ./demo-session/demo-session --output demo-engagement.zip --profile client
```

The release wheel includes the demo fixtures. The source-only
`scripts/render_demo_engagement.py` helper remains available for checkout
development.

For live AD, stop here and follow your organization's approved engagement
runbook before supplying credentials. Mutating capabilities record rollback
pre-state in the session; `adaf-attack rollback` reverses pending changes.

## Feature availability

| Surface | Install | External setup | Network/target required | Release status |
|---|---|---|---|---|
| CLI, capability help, paths, doctor | Base | None | No | CI |
| LDAP/AD reconnaissance | Base | Authorized account and DNS | Yes | Operator-verified |
| TUI | `[tui]` or `[full]` | Terminal supporting Textual | No | CI smoke |
| Kerberos, Impacket adapters | `[kerberos]` or `[full]` | DNS/time/realm and tool PATH | Usually | Operator-verified |
| HTML reports | `[reports]` or `[full]` | None | No | CI |
| PDF reports | `[reports]` or `[full]` | None | No | CI |
| Certipy workflows | `[certipy]` | Certipy on PATH; separate dependency boundary | Yes | Operator-verified |
| Evidence correlation and packaging | Base/full | Saved session or fixture | No | CI |
| Destructive capabilities | Base/full | Written authorization and approval token | Yes | Authorized target |

`[full]` means operator features, not every external tool or a ready-to-use AD
environment. Experimental or target-dependent behavior is never implied by a
successful offline installation.

## Reproducible installs

The repository's `requirements-ci.txt` is the hashed CI lock. For a release,
the reliable user-facing reproducibility boundary is the complete wheelhouse:

```bash
python scripts/build-release-wheelhouse.py \
  --wheel ./adaf_attack-0.10.1-py3-none-any.whl \
  --output ./wheelhouse --extras full
```

Transfer the entire directory through the approved media process, then install
with `--no-index --find-links wheelhouse`. Never mix a partial wheelhouse with
the public internet and assume it is reproducible. Direct runtime constraints
are recorded in [requirements-runtime.txt](../requirements-runtime.txt); the
candidate wheelhouse and its `release-manifest.json` remain the release
artifacts of record.

For an internal release bundle, use the portable bootstrap from the repository
root:

```bash
python scripts/install-approved-wheel.py \
  --wheel ./adaf_attack-0.10.1-py3-none-any.whl \
  --venv .venv --extras full \
  --manifest ./wheelhouse/release-manifest.json
```

Use `--index-url` only with an organization-approved package index, or
`--find-links ./wheelhouse` for an offline install.

## Release access and support boundary

Before installation, obtain the approved wheel, matching `SHA256SUMS`, and
`release-manifest.json` from the private GitHub release channel or an approved
internal package index. If you cannot access those assets, request access from
the repository owner; there is no public PyPI fallback.

CI proves clean-artifact installation, guided troubleshooting, documented
subcommand validity, offline engagement product surfaces, packaging, and safe
command contracts. It isolates readiness state in disposable CI directories and
fails closed on missing or malformed JSON contracts. It does not prove the behavior of a customer's AD forest, proxy,
custom CA, endpoint security, Kerberos realm, or production rollback target.
Those require an authorized target.
