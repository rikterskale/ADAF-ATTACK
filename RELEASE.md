# ADAF-ATTACK 0.10.1 release notes

## Operator capabilities

- PKINIT, certificate request, gMSA/LAPS, and SYSVOL workflows include explicit
  force gates and evidence handling.
- Offline analysis, reporting, engagement packaging, and rollback contracts are
  exercised in CI.
- `adaf-attack guide` is the authoritative install→closeout next-step command
  shared by CLI and TUI.

## Installation and lifecycle

- Supported runtime: Python 3.11-3.14.
- `full` is an operator bundle (`tui`, `kerberos`, and `reports`) and does not
  install contributor-only test/lint/type-check tools.
- Built wheels are smoked on Ubuntu, Windows, and macOS; the sdist is smoked on
  Ubuntu. Windows PowerShell 5.1/7 and Kali installer paths have lifecycle jobs.
- Windows and Kali uninstall preserve workspaces by default. Data deletion
  requires an explicit option.
- Published packages are private GitHub release assets, not PyPI packages.
- The portable `scripts/install-approved-wheel.py` bootstrap supports approved
  internal indexes and offline wheelhouses without reusing an existing venv;
  it can verify a release manifest and all listed wheelhouse hashes.
- `scripts/build-release-wheelhouse.py` creates the reproducible offline
  dependency bundle, including `release-manifest.json` and `SHA256SUMS`.
- Mutating capabilities record rollback pre-state in each session
  (`cleanup.json`); `adaf-attack rollback` reverses pending changes.

## Upgrade note

Existing source environments that relied on `full` for pytest, Ruff, or mypy
must install `adaf-attack[dev,operator]`. Operator environments can continue to
use `adaf-attack[full]`.

## Known limitations

See [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md). In particular, hosted
CI does not prove a published artifact before a release asset exists.

## Release manager checklist (non-author usable)

Work the standard in [docs/RELEASE_READINESS.md](docs/RELEASE_READINESS.md), then
fill [docs/RELEASE_EVIDENCE.md](docs/RELEASE_EVIDENCE.md) for every **[MANUAL]**
item. Attach both the short summary below and the evidence pack to the private
release record.

### A. Version and artifacts

```text
[ ] pyproject.toml version == adaf_attack.__version__ == CHANGELOG latest released section
[ ] Candidate wheel + sdist built once from the release commit
[ ] SHA256SUMS and release-manifest.json generated and attached
[ ] release-provenance.json attached (HMAC optional via ADAF_RELEASE_PROVENANCE_KEY)
[ ] requirements-operator.txt / wheelhouse lock attached when shipping [full]/[operator]
```

Commands:

```bash
python -c "import tomllib, pathlib; from adaf_attack import __version__; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text(encoding='utf-8'))['project']['version'], __version__)"
python scripts/check_install_contracts.py
python scripts/check_release_readiness.py --repo-root .
```

### B. Automated gates

```text
[ ] CI ci-gate green on the release commit (lint, typecheck, tests, security,
    scripts, package, artifact-smoke, installers, operator-workflow,
    release-readiness, workflow-contract)
[ ] Short evidence summary below completed from CI job links
```

```text
Installation: PASS / FAIL
Clean artifact smoke: PASS / FAIL
Packaged offline demo: PASS / FAIL
Reports and evidence package: PASS / FAIL
Windows installer: PASS / FAIL
Kali installer: PASS / FAIL
Published artifact smoke: PASS / FAIL / NOT YET PUBLISHED
```

### C. Manual evidence (must use RELEASE_EVIDENCE.md)

```text
[ ] First-ten-minutes by a new operator on Windows, Kali/Linux, and macOS
[ ] Published-artifact smoke recorded once the private release asset exists
[ ] Air-gapped wheelhouse transfer reproduced with org controls
[ ] CHANGELOG / RELEASE / KNOWN_LIMITATIONS content reviewed for honesty
[ ] Narrow-terminal TUI spot-check (RELEASE_EVIDENCE §6)
[ ] SECURITY.md advisory link still valid
[ ] Rollback/recovery location for the exact release assets recorded
```

Also record the candidate hashes, `release-manifest.json`,
`requirements-operator.txt`, and supported OS/Python matrix.

Private cut `v0.10.1` records overall **10/10** with completed MANUAL evidence
and published-artifact-smoke green (see
[docs/VENDOR_SCORECARD.md](docs/VENDOR_SCORECARD.md)). Future cuts must refill
[docs/RELEASE_EVIDENCE.md](docs/RELEASE_EVIDENCE.md) before claiming 10 again.
