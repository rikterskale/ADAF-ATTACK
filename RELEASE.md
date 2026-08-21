# ADAF-ATTACK 0.10.0 release notes

## Operator capabilities

- PKINIT, certificate request, gMSA/LAPS, and SYSVOL workflows include explicit
  force gates and evidence handling.
- Offline analysis, reporting, engagement packaging, and rollback contracts are
  exercised in CI.

## Installation and lifecycle

- Supported runtime: Python 3.11-3.13.
- `full` is now an operator bundle (`tui`, `kerberos`, and `reports`) and no
  longer installs contributor-only test/lint/type-check tools.
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

## Release sign-off evidence

Every release candidate must attach this summary to the private release record:

```text
Installation: PASS / FAIL
Clean artifact smoke: PASS / FAIL
Packaged offline demo: PASS / FAIL
Reports and evidence package: PASS / FAIL
Windows installer: PASS / FAIL
Kali installer: PASS / FAIL
Published artifact smoke: PASS / FAIL / NOT YET PUBLISHED
```

Also record the candidate hashes, `release-manifest.json`,
`requirements-operator.txt`, and supported OS/Python matrix.
