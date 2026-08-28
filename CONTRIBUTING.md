# Contributing

Thanks for improving ADAF-ATTACK. This project runs a strict CI gate — every
lane must pass, including a **95% full-source coverage** requirement. The steps
below reproduce that gate locally so your first push goes green.

## 1. Set up a development environment

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e ".[dev,operator]"
```

> **Tooling versions must match CI.** The linters are version-sensitive:
> different `ruff` releases format and sort imports differently. CI pins
> `ruff==0.16.3` (see `requirements-ci.txt`). The `[dev]` extra only sets a
> lower bound, so either install the pinned linters explicitly
> (`pip install "ruff==0.16.3"`) or — simpler — use the pre-commit hooks below,
> which are pinned to the same version.

## 2. Install the pre-commit hooks (recommended)

```bash
python -m pip install pre-commit
pre-commit install
```

Now `ruff` (lint + format) and `mypy` run automatically on every commit, pinned
to the versions CI uses. Run them across the whole tree at any time:

```bash
pre-commit run --all-files
```

## 3. The checks CI runs

Run these before pushing; they mirror `.github/workflows/ci.yml`:

```bash
ruff check src tests
ruff format --check src tests
mypy src/adaf_attack
python -m compileall -q src tests
pytest --cov=adaf_attack --cov-report=term-missing --cov-fail-under=95
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
tests that exercise it — including error and edge branches. `pytest ...
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
