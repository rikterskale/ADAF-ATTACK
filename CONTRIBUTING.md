# Contributing

Thanks for improving ADAF-ATTACK. This project runs a strict CI gate — every
lane must pass, including a **100% full-source coverage** requirement. The steps
below reproduce that gate locally so your first push goes green.

## 1. Set up a development environment

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e ".[dev,kerberos,tui,reports]"
```

> **Tooling versions must match CI.** The linters are version-sensitive:
> different `ruff` releases format and sort imports differently. CI pins
> `ruff==0.16.1` (see `requirements-ci.txt`). The `[dev]` extra only sets a
> lower bound, so either install the pinned linters explicitly
> (`pip install "ruff==0.16.1"`) or — simpler — use the pre-commit hooks below,
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
pytest --cov=adaf_attack --cov-report=term-missing --cov-fail-under=100
```

### About the 100% coverage gate

New code needs tests that exercise it — including error and edge branches.
`pytest ... --cov-report=term-missing` lists any uncovered lines under
`Missing`; add targeted tests until that column is empty. Many capabilities are
tested offline with mocked LDAP connections and impacket modules — see existing
`tests/test_*_coverage*.py` files for the harness patterns.

## 4. Pull requests

- Branch off `main`; keep commits focused.
- Ensure every check in step 3 passes locally.
- CI must be green (all lanes, including the production-readiness gate) before merge.
