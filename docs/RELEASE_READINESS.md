# Release readiness standard

Coverage alone does not prove that a new operator can install, diagnose, use,
upgrade, or safely remove ADAF-ATTACK. This document distinguishes exactly what
automation proves from what requires release sign-off.

- **[CI]** is enforced by a named workflow/job or test today.
- **[MANUAL]** requires evidence for each release because hosted CI cannot
  reproduce the environment.
- **[GAP]** is not yet enforced.

## Supported install matrix

Source/editable tests and artifact smoke have different purposes:

| Surface | Current automated coverage |
|---|---|
| Source/editable tests | Ubuntu 24.04 and Windows 2022; Python 3.11, 3.12, 3.13 |
| Built wheel | Ubuntu/Python 3.11, Windows/Python 3.12, macOS 14/Python 3.13 |
| Built sdist | Ubuntu/Python 3.13 |
| Windows installer | Windows PowerShell 5.1/Python 3.11 and PowerShell 7/Python 3.13 |
| Kali installer | Pinned Kali rolling container digest/system Python, built wheel |
| Published release | Scheduled/manual GitHub release-asset workflow on Ubuntu, Windows, macOS/Python 3.12; it can pass only after an asset is published |

The focused artifact matrix validates supported platform families without
duplicating the complete source test suite on every row. Python compatibility is
also proven by the full source matrix.

## 1. Proven installation and lifecycle

- [ ] Build wheel/sdist once, validate metadata, generate checksums, and upload
      the exact artifacts consumed downstream. **[CI: package]**
- [ ] In a clean venv install the selected downloaded artifact, run `pip check`,
      compare package metadata to `adaf_attack.__version__`, and exercise
      `--version`, `doctor --explain`, `list-capabilities`, and `paths`.
      **[CI: artifact-smoke]**
- [ ] PowerShell installer consumes the downloaded wheel, validates Python
      3.11+, and proves its user PATH shim/environment ownership plus upgrade,
      uninstall-preserves-data, and explicit data deletion. **[CI:
      windows-installer]**
- [ ] Kali performs a real built-wheel install plus both uninstall paths, while
      the non-Kali rejection guard remains exercised on Ubuntu. **[CI:
      kali-installer; scripts]**
- [ ] Latest/specified published wheel installs from the private GitHub release
      channel on three OS families. **[CI: published-artifact-smoke, once a
      release asset exists]**
- [ ] Record the first successful published-artifact workflow for the candidate.
      **[MANUAL]** No current source branch can prove an asset has already been
      published.
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

## 3. Feature and recovery validation

- [ ] Every registered capability is listed and has working generated help.
      **[CI: test_release_contracts]**
- [ ] Offline engagement, evidence, reports, package, and analysis commands run
      against deterministic fixtures. **[CI: operator-workflow]**
- [ ] Every destructive capability wires rollback or has a reviewed exemption;
      offline revertable kinds round-trip. **[CI: test_release_contracts;
      test_rollback_matrix]**
- [ ] Live LDAP/Kerberos/AD CS/coercion/relay and destructive rollback operate
      correctly in a disposable authorized forest. **[MANUAL]** Hosted CI does
      not provide a domain and must never be described as proving this.
- [ ] Every error path is guaranteed to map to the actionable error catalog.
      **[GAP]** Representative doctor/CLI contracts are automated, not every
      possible target/provider failure.

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

## Release sign-off checklist

```text
Version: __________  Release manager: __________  Date: __________

[ ] All required CI jobs pass on the release commit.
[ ] Candidate wheel/sdist and SHA256SUMS are attached to the private GitHub release.
[ ] Published-artifact smoke passes on Ubuntu, Windows, and macOS.
[ ] Air-gapped install is recorded with candidate artifacts.
[ ] First-ten-minutes onboarding is completed by a new operator.
[ ] Live-AD capability and one destructive rollback are recorded in an authorized lab.
[ ] CHANGELOG, RELEASE, and known limitations are reviewed.
[ ] Rollback/recovery location for the exact release assets is recorded.
```

## Remaining automation gaps

1. A credential-gated disposable AD forest workflow for network capabilities and
   target-side cleanup.
2. Broader actionable-error catalog coverage.
3. Reproducible validation of organization-specific proxy, CA, endpoint, and
   air-gap transfer policies.
