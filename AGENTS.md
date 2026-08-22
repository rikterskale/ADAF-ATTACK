# AGENTS.md

## What this is

`adaf-attack` — a proprietary, offline-capable Active Directory offensive toolkit (Typer CLI, entrypoint `adaf_attack.cli:app`). Not on PyPI; distributed via private release wheels. Authorized red-team use only.

## Layout

- `src/adaf_attack/` — all package code (`src/` layout). CLI split across `cli.py`, `cli_product_commands.py`, `cli_tool_commands.py`, `cli_ux_commands.py`, `cli_workflow_commands.py`.
- `src/adaf_attack/capabilities/` — capability implementations; registered via the `[project.entry-points."adaf_attack.capabilities"]` group.
- `tests/` — pytest suite; heavy use of mocked LDAP/impacket harnesses (see `tests/test_*_coverage*.py` for patterns).
- `scripts/` — installers (Kali `.sh`, Windows `.ps1`), CI contract validators, release manifest tooling.
- `docs/CLI_REFERENCE.md` — must stay in parity with registered Typer commands.

## Dev setup and checks

```bash
python -m pip install -e ".[dev,operator]"
pre-commit install   # pins ruff/mypy to CI versions
```

CI gate order (mirror before pushing):

```bash
ruff check src tests
ruff format --check src tests
mypy src/adaf_attack            # strict mode
python -m compileall -q src tests
pytest --cov=adaf_attack --cov-fail-under=95    # branch coverage (--cov-branch in CI)
python scripts/check_cli_documentation.py
```

Single test: `pytest tests/test_foo.py::test_bar` (mocked harnesses mean no network/AD needed).

## Hard-won gotchas

- **Coverage gate (95%)**: CI fails under 95% branch coverage of `adaf_attack`. New code needs tests covering error/edge branches too. Write *behavioral* tests named for the behavior under test — do not add coverage-only tests (or `sys.settrace`/line-injection tricks) purely to chase the last few percent.
- **Cross-platform matrix**: CI tests on Linux/Windows/macOS × Python 3.11–3.14; avoid platform-specific code paths or guard them.
- **Security lanes**: Bandit (`src`, medium severity/confidence) and a tracked-file secret scan run in CI — no hardcoded keys/tokens in non-test files.
- **Ruff version sensitivity**: CI pins `ruff==0.16.2` (`requirements-ci.txt`). The `[dev]` extra only sets a lower bound — different ruff versions format/sort imports differently and will fail CI. Use pre-commit hooks or pin explicitly.
- **mypy is strict** and only runs on `src/adaf_attack` (not tests).
- **CLI docs parity**: adding/renaming any Typer command requires updating `docs/CLI_REFERENCE.md` in the same change; `check_cli_documentation.py` fails on stale entries.
- **Windows pytest**: if `PermissionError` on global temp dirs, run via `.\scripts\Invoke-Tests.ps1 <args>` which redirects TEMP to repo-local folders.
- **Optional extras are separate on purpose**: `certipy-ad` conflicts with the pinned `cryptography`, so it lives in its own extra (`[certipy]`), not in `[full]`. Kerberos needs `[kerberos]` (impacket).
- **Reproducible builds**: CI builds with `SOURCE_DATE_EPOCH`, `PYTHONHASHSEED=0`, `TZ=UTC`, `LC_ALL=C` and verifies byte-identical rebuilds; use `--no-isolation` with pinned setuptools/wheel.
- **Contract validators in CI**: `scripts/check_install_contracts.py` and `check_release_readiness.py` enforce operator-facing contracts — changing CLI output shape, docs, or installer scripts can trip these lanes even when tests pass.
- **In-module rollback**: every mutating capability records pre-state via `adaf_attack.core.rollback.record_pre_state` into the session's `cleanup.json`; `adaf-attack rollback` reverses pending changes. New destructive capabilities must record rollback in-module (add a kind to `SUPPORTED_KINDS` if needed).

## Conventions

- Every non-interactive CLI command supports `--format json` returning a stable document with an `"ok": true` field; keep this contract for new commands.
- Destructive operations are gated behind `--force` / approval tokens; don't bypass these gates.
- Runtime dependency versions are pinned exactly in both `pyproject.toml` and `requirements-runtime.txt`; update both together.
