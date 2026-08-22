# Changelog

All notable changes are documented here. The project follows release versions
declared in `pyproject.toml`.

## Unreleased

### Added

- Global `--debug` flag: routes diagnostic logging to stderr (never stdout/JSON)
  for troubleshooting live runs, wired to the existing package logger.
- Value-pattern redaction: secrets are now redacted when they appear in
  unstructured fields (e.g. `notes`, `stdout`, log lines) whose key is not
  itself sensitive - Kerberos hashcat blobs, `LM:NT` hash pairs, PEM private
  keys, and cloud/VCS tokens. SHA-256 evidence digests are deliberately
  preserved.

### Changed

- Promoted development status from Alpha to Beta.
- Lowered the CI branch-coverage gate from 100% to 95% to remove the incentive
  to write coverage-only tests; behavioral tests are now the documented norm.

### Removed

- Removed a `sys.settrace` line-injection test and the unreachable branch it was
  gaming in `pkinit-auth`; replaced with a behavioral test.

### Fixed

- Repo hygiene: untracked the bundled review meta-prompt and tightened
  `.dockerignore` so the build context excludes venvs, tests, docs, and caches.

## 0.10.0

### Added

- Registered 40 offensive capabilities in the offensive capability catalog:
  ACL primitives (`add-member`, `acl-abuse`, `write-spn`, …), Server 2025 dMSA
  (`badsuccessor`, `dmsa-ouroboros`), ESC9–ESC16, Kerberos relay, golden cert,
  DPAPI backup key, SCCM, hybrid follow-ups, and joined workflows
  (`maq-rbcd-workflow`, `targeted-kerberoast`, `esc8-relay-workflow`, …).
- `adaf-attack workflow` command group: a CLI and agent-driven surface for the
  finding-driven guided workflow engine, sharing the durable workflow state the
  TUI drives (status, next, snapshot, inject, import-session, decide, transition,
  close, and related commands).
- Focused wheel/sdist smoke coverage across Ubuntu, Windows, and macOS.
- Artifact-based Windows and Kali installer lifecycle coverage.
- Scheduled/manual GitHub release-asset smoke workflow.
- Platform onboarding, offline installation, lifecycle, troubleshooting, and
  known-limitations documentation.
- Portable approved-wheel bootstrap, explicit data/config directory overrides,
  architecture support guidance, and machine-readable disposable-lab evidence.

### Changed

- Promoted the 40 offensive capability catalog capabilities from experimental
  tracking stubs to supported runners (ACL primitives, dMSA, ESC9–ESC16,
  Kerberos relay, golden cert, DPAPI backup key, SCCM, hybrid follow-ups, and
  joined workflows). Destructive paths require `--force` and record rollback.
- `full` now contains production operator extras (`tui`, `kerberos`, and
  `reports`) without contributor-only pytest, Ruff, or mypy dependencies.
- Contributor tooling remains available through `dev`; `operator` names the
  production bundle explicitly.
- Windows uninstall removes only installer-owned shim/PATH/environment state and
  preserves workspaces unless explicitly told to remove them.
- Help and planning commands tolerate read-only user preference storage; explicit
  configuration writes still report an actionable error.

### Known limitations

See [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md). Live AD behavior and
published-release availability cannot be proven by source-branch CI.
