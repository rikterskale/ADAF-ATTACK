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
not invent a public package URL or use an unapproved mirror. A containerized
development environment may be added later, but live AD/Kerberos behavior
still needs host and network integration testing.

## First ten minutes

After installing an approved wheel, run this safe sequence. It does not contact
AD or modify a target:

```bash
python -m pip check
adaf-attack --version
adaf-attack --format json doctor --explain
adaf-attack --format json list-capabilities
adaf-attack --format json paths
adaf-attack --format json workflow-profiles
```

If every command exits with status 0 and the JSON payload has `"ok": true`,
the base installation is usable. Optional warnings are expected when TUI,
Kerberos, reporting, Certipy, or Impacket command-line tools were not selected.

For a deterministic report demonstration, run:

```bash
python scripts/render_demo_engagement.py
adaf-attack engagement report --session output/demo-engagement --engagement-id DEMO-2026-001
adaf-attack engagement package --session output/demo-engagement --output demo-engagement.zip --profile client
```

For live AD, stop here and read [the disposable lab procedure](LIVE_AD_LAB_VALIDATION.md)
or your organization's approved engagement runbook before supplying credentials.

## Feature availability

| Surface | Install | External setup | Network/target required | Release status |
|---|---|---|---|---|
| CLI, capability help, paths, doctor | Base | None | No | CI |
| LDAP/AD reconnaissance | Base | Authorized account and DNS | Yes | Manual lab |
| TUI | `[tui]` or `[full]` | Terminal supporting Textual | No | CI smoke |
| Kerberos, Impacket adapters | `[kerberos]` or `[full]` | DNS/time/realm and tool PATH | Usually | Manual lab |
| HTML reports | `[reports]` or `[full]` | None | No | CI |
| PDF reports | `[reports]` or `[full]` | None | No | CI |
| Certipy workflows | `[certipy]` | Certipy on PATH; separate dependency boundary | Yes | Manual lab |
| Evidence correlation and packaging | Base/full | Saved session or fixture | No | CI |
| Destructive capabilities | Base/full | Written authorization and approval token | Yes | Manual disposable lab |

`[full]` means operator features, not every external tool or a ready-to-use AD
environment. Experimental or target-dependent behavior is never implied by a
successful offline installation.

## Reproducible installs

The repository's `requirements-ci.txt` is the hashed CI lock. For a release,
the reliable user-facing reproducibility boundary is the complete wheelhouse:

```bash
python -m pip download --only-binary=:all: --dest wheelhouse \
  "./adaf_attack-0.10.0-py3-none-any.whl[full]"
python -m pip hash wheelhouse/* > wheelhouse/SHA256SUMS.txt
```

Transfer the entire directory through the approved media process, then install
with `--no-index --find-links wheelhouse`. Never mix a partial wheelhouse with
the public internet and assume it is reproducible. Direct runtime constraints
are recorded in [requirements-runtime.txt](../requirements-runtime.txt); the
candidate wheelhouse remains the release artifact of record.

## Support boundary

CI proves installation, offline workflows, packaging, and safe command
contracts. It does not prove the behavior of a customer's AD forest, proxy,
custom CA, endpoint security, Kerberos realm, or production rollback target.
Those require the documented disposable lab and release sign-off evidence.
