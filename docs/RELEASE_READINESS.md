# Release readiness standard

Coverage alone does not prove that a new operator can install, diagnose, use,
upgrade, or safely remove ADAF-ATTACK. This document distinguishes exactly what
automation proves from what requires manual follow-up.

- **[CI]** is enforced by a named workflow/job or test today.
- **[MANUAL]** requires evidence for each release because hosted CI cannot
  reproduce the environment.
- **[GAP]** is not yet enforced.

Release bundles include `release-provenance.json`, binding artifact hashes to
the source revision and CI build context. Set `ADAF_RELEASE_PROVENANCE_KEY`
when a publisher needs an HMAC-signed provenance record; unsigned provenance
is an integrity record only.

## Supported install matrix

Source/editable tests and artifact smoke have different purposes:

| Surface | Current automated coverage |
|---|---|
| Source/editable tests | Ubuntu 24.04, Windows 2022, and macOS 14; Python 3.11, 3.12, 3.13, 3.14 |
| Built wheel | Ubuntu/Python 3.11, Ubuntu/Python 3.14, Windows/Python 3.12, macOS 14/Python 3.13 |
| Built sdist | Ubuntu/Python 3.13 |
| Windows installer | Windows PowerShell 5.1/Python 3.11 and PowerShell 7/Python 3.13/3.14 |
| Kali installer | Pinned Kali rolling container digest/system Python, built wheel |
| Published release | Scheduled/manual GitHub release-asset workflow on Ubuntu, Windows, macOS/Python 3.12; it can pass only after an asset is published |

The focused artifact matrix validates supported platform families without
duplicating the complete source test suite on every row. Python compatibility is
also proven by the full source matrix.

## 1. Proven installation and lifecycle

- [ ] Build wheel/sdist once, validate metadata, generate checksums and a
      `release-manifest.json`, and upload the exact artifacts consumed
      downstream. **[CI: package]**
- [ ] In a clean venv install the selected downloaded artifact, run `pip check`,
      compare package metadata to `adaf_attack.__version__`, and exercise
      `--version`, `doctor --explain`, `list-capabilities`, and `paths`.
      **[CI: artifact-smoke]**
- [ ] From the same wheel-only environment, run `doctor --profile
      user-readiness`, `quickstart`, and `demo`. Full/operator artifact rows
      additionally exercise the evidence report and package workflow.
      **[CI: artifact-smoke; release-readiness]**
- [ ] PowerShell installer consumes the downloaded wheel, validates Python
      3.11-3.14, and proves its user PATH shim/environment ownership plus upgrade,
      uninstall-preserves-data, and explicit data deletion. **[CI:
      windows-installer]**
- [ ] Kali performs a real built-wheel install plus both uninstall paths, while
      the non-Kali rejection guard remains exercised on Ubuntu. **[CI:
      kali-installer; scripts]**
- [ ] Latest/specified published wheel and release manifest install from the
      private GitHub release channel on three OS families. **[CI:
      published-artifact-smoke, once a release asset exists]**
- [ ] Record the first successful published-artifact workflow for the candidate.
      **[MANUAL]** No current source branch can prove an asset has already been
      published.
- [ ] Attach the readiness summary, exact production-extra lock, and artifact
      hashes to the release record.
      **[MANUAL: release manager]**
- [ ] Reproduce the air-gapped wheelhouse path with candidate artifacts and the
      organization's transfer controls. **[MANUAL]**

## 2. Guided onboarding and troubleshooting

- [ ] README includes prerequisites, release/source paths, verification, first
      offline success, offline installation, lifecycle, and troubleshooting.
      **[CI: test_install_contracts]**
- [ ] Windows/Linux canonical guides and the macOS guide use current commands,
      valid links, and explicit data-preservation behavior. **[CI:
      test_install_contracts; test_docs_commands]**
- [ ] Troubleshooting covers PATH/new terminal, Python/launcher, venv/PEP 668,
      execution policy/SmartScreen, proxy/custom CA, air-gap, dependency
      conflicts, and sanitized diagnostics. **[CI: test_install_contracts]**
- [ ] A person unfamiliar with the project completes the first-ten-minutes
      walkthrough from a release artifact without reading source. **[MANUAL]**
      Use [USER_READINESS.md](USER_READINESS.md) as the canonical decision guide.
- [ ] The release artifact's `adaf-attack quickstart` completes on a clean,
      writable user environment and produces a demo session. **[CI: release-readiness]**

## 3. Feature and recovery validation

- [ ] Every registered capability is listed and has working generated help.
      **[CI: test_release_contracts]**
- [ ] Offline engagement, evidence, reports, package, and analysis commands run
      against deterministic fixtures; the clean base artifact also exercises the
      dashboard, asset, identity, Tier-0, blast-radius, domain, investigation,
      cleanup-status, and saved-mission surfaces. **[CI: operator-workflow;
      release-readiness]**
- [ ] Every destructive capability wires rollback or has a reviewed exemption;
      offline revertable kinds round-trip. **[CI: test_release_contracts;
      test_rollback_matrix]**
- [ ] Doctor profiles distinguish offline, operator, Certipy, and explicit
      live-AD preflight requirements; support bundles redact identifiers and
      secrets. **[CI: test_doctor_profiles]**
- [ ] Common authentication, connectivity, missing-input, invalid-file, and
      permission failures map to stable actionable codes with recovery text.
      **[CI: test_actionable_error_contract]** Provider-specific unknown failures
      remain intentionally classified as `RUN_FAILED`.

## 4. Packaging and documentation consistency

- [ ] `full`/`operator` exclude contributor tools, while `dev` remains the
      contributor surface. **[CI: test_install_contracts]**
- [ ] Markdown links, lifecycle sections, guide canonical paths, placeholder
      absence, version statements, Ruff pins, action SHA pins, and artifact jobs
      remain consistent. **[CI: workflow-contract; test_install_contracts]**
- [ ] Changelog, release notes, and known limitations match the candidate.
      **[CI: test_install_contracts; MANUAL: release manager reviews content]**
- [ ] Dependency audit, SAST, secret scan, and SBOM succeed. **[CI: security;
      codeql]**

## Release checklist

```text
Version: __________  Release manager: __________  Date: __________

[ ] All required CI jobs pass on the release commit.
[ ] Candidate wheel/sdist, SHA256SUMS, and release-manifest.json are attached to the private GitHub release.
[ ] Published-artifact smoke passes on Ubuntu, Windows, and macOS.
[ ] Air-gapped install is recorded with candidate artifacts.
[ ] First-ten-minutes onboarding is completed by a new operator.
[ ] CHANGELOG, RELEASE, and known limitations are reviewed.
[ ] Rollback/recovery location for the exact release assets is recorded.
```

## Manual evidence pack

For every **[MANUAL]** checkbox above, complete the fill-in templates in
[RELEASE_EVIDENCE.md](RELEASE_EVIDENCE.md) and attach that page to the private
release record with artifact hashes.

## Remaining automation gaps

1. Organization-specific proxy, CA, endpoint, and air-gap *transfer* policies
   remain **[MANUAL]** (see [RELEASE_EVIDENCE.md](RELEASE_EVIDENCE.md) §3).
   The wheelhouse *build + offline install recipe* is documented and
   contract-tested; CI cannot reproduce each customer's media controls.
2. Published-artifact proof still requires a private release asset plus the
   scheduled/manual workflow (**[MANUAL]** until first successful publish).
