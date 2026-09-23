# Contributing

Thanks for improving ADAF-ATTACK. This project runs a strict CI gate — every
lane must pass, including a **95% full-source branch coverage** requirement.
The steps below prepare CI-matched Ruff/mypy versions and local source checks.

## 1. Set up a development environment

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e ".[dev,operator]"
python -m pip install "ruff==0.16.3" "mypy==2.3.1"
```

> **Tooling versions must match CI.** The `[dev]` extra specifies lower bounds
> for Ruff and mypy. The command above installs their current pins from
> `requirements-ci.txt`. Keep these versions synchronized with that file when
> CI tooling changes.

## 2. Install the pre-commit hooks (recommended)

```bash
python -m pip install pre-commit
pre-commit install
```

Ruff's lint and format hooks run in a pinned pre-commit environment. The mypy
hook uses `python -m mypy` from your active project environment, so it relies
on the explicit mypy pin installed above. Keep that environment active when
committing or running the hooks:

```bash
pre-commit run --all-files
```

## 3. Run the local source checks

Run these before pushing, with the project environment active. They match
CI's source-check commands and coverage measurement. Hosted CI additionally
writes coverage XML and runs the full platform, security, installer, and
artifact validation lanes defined in `.github/workflows/ci.yml`.

```bash
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src/adaf_attack
python -m compileall -q src tests
python -m pytest --cov=adaf_attack --cov-branch --cov-report=term-missing --cov-fail-under=95
python scripts/check_cli_documentation.py
```

When adding or renaming a CLI command, update `docs/CLI_REFERENCE.md` in the
same change. The parity check compares the table with the registered Typer
commands and fails on missing, duplicate, or stale entries.

When bumping the version in `pyproject.toml`, also update the supported-version
table in `SECURITY.md` so the documented support range stays accurate.

On Windows, if pytest reports `PermissionError` for a global
`AppData\Local\Temp\pytest-of-*` directory, run tests through the repository
wrapper instead:

```powershell
.\scripts\Invoke-Tests.ps1 tests/test_workflow_engine.py
```

The wrapper redirects `TEMP`/`TMP` and pytest's base directory to writable
repository-local folders. It does not modify system ACLs and is safe to use on
managed workstations. The same arguments can be passed for coverage or a
full-suite run.

### About the coverage gate

The gate is **95%**, not 100%. The intent is high confidence without creating
pressure to write tests that exist only to move the number. New code needs
tests that exercise it — including error and edge branches. `python -m pytest ...
--cov-report=term-missing` lists uncovered lines under `Missing`; add *behavioral*
tests (named for what they verify) until the important branches are covered.

Do **not** add coverage-only tests, and never use `sys.settrace` or similar
line-injection tricks to force an otherwise-unreachable branch to register as
covered — if a branch is unreachable, delete it instead. Many capabilities are
tested offline with mocked LDAP connections and impacket modules — see existing
capability tests for the harness patterns.

> **Note on what green means.** Because the suite mocks LDAP/Kerberos/impacket,
> a passing run verifies control flow, parsing, redaction, and evidence
> handling — it does **not** guarantee behavior against a live domain
> controller. Validate live paths against the engagement scope before relying on them.

## 4. Pull requests

- Branch off `main`; keep commits focused.
- Ensure every check in step 3 passes locally.
- CI must be green (all lanes, including the production-readiness gate) before merge.
