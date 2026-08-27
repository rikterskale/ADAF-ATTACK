# Changelog

All notable changes are documented here. The project follows release versions
declared in `pyproject.toml`.

## Unreleased

> Empty after the `0.10.1` private release cut. New work lands here until the
> next versioned heading.

## 0.10.1

### Added

- Journey stage `fallback` commands and broader `blocked_because` narration
  (authorize pending, session not yet imported).
- `adaf-attack rollback` top-level alias for `cleanup`.
- TUI Engagement ID / approval-token fields and force/token Run gating.
- Kali installer structured JSON for ownership, Python, package, and completion
  failures (aligned with ERROR_CATALOG codes where applicable).
- Guide human output shows stage entry/exit criteria; TUI readiness embeds the
  shared journey next command; timeline emits recovery + duration/correlation
  coverage counts.
- `review` accepts `--session` / `--export` (full `plan` alias); plan/review
  expose top-level `prerequisites` and `recovery_command`.
- Shared `format_timeline_human` for `timeline` and `engagement replay`; JSON
  `run` payloads include `progress.stages` / observed stage transitions.
- Compact TUI layout contract test; release pillar bindings include Phase 2
  self-explain tests; doctor repair-text coverage includes `live-ad`.
- `adaf-attack guide`: authoritative next-step command for the full operator
  journey (install → offline first success → authorize → operate → report →
  closeout), shared by CLI and TUI via `core.journey`.
- Journey actions include risk, approvals, rollback implication, recovery
  command, and stage entry/exit criteria.
- Shared operator capability contract on capability-help, explain, plan,
  review, and TUI help/review panels.
- Doctor repair/keep text on every check; top-level `ready`.
- Timeline summary with status, duration, correlation, and stronger redaction.
- Progress stages from runner log lines (CLI spinner and TUI).
- TUI parameter form with refresh preservation and >8 `-P` overflow warning.
- Error catalog codes for guide/install/approval/secret mishaps.
- `docs/RELEASE_EVIDENCE.md`, issue templates, operator-first README,
  `docs/VENDOR_SCORECARD.md`, Windows installer JSON codes.
- Single-operator runbook, proprietary license terms, and a concrete private
  security-reporting channel.
- Safe command-template enrichment, target validation, evidence rationale, and
  built-in capability registration/docstring contract checks.

### Changed

- `workflow next` (and TUI workflow / What next panels) always take the
  authoritative next step from `core.journey.snapshot()`, matching `guide`.
  `recommendations[0]` is aligned to the journey primary.
- TUI Home uses the same user-readiness doctor snapshot as `guide`; Run no
  longer silently completes `authorize-scope`.
- Error recovery commands include `--workspace` / `--session` when known.
  Real approval-token failure text maps to `APPROVAL_TOKEN_*` catalog codes.
- `demo`, `init`, `setup`, doctor first-run, and TUI Quickstart hand off to
  `guide` only (no competing start ladders).
- First-ten-minutes canon is identical across README, USER_READINESS,
  FEATURE_MATRIX, INSTALLATION, RELEASE_EVIDENCE, and platform guides, and is
  enforced by install contracts (`pip check` → doctor → quickstart → guide →
  paths).
- `doctor --profile user-readiness` keeps unwritable path probes blocking
  (`paths --repair`); `offline` may stay advisory on read-only hosts. Editable
  installs treat metadata vs runtime version skew as advisory; wheels stay
  blocking.
- Journey / capability contracts emit uppercase risk (`OBSERVE`…). Windows
  `quote_path` normalizes to forward slashes before quoting.
- Windows installer `-Json` failures include `recovery_command`. Support
  bundles fail closed with `SECRET_IN_OUTPUT` when high-confidence secrets
  remain after redaction.
- Vendor scorecard re-scored from this pass’s evidence; Phase 4 proof tests
  lock behaviors, not scorecard prose. RELEASE_EVIDENCE adds narrow-terminal
  TUI MANUAL section and forbids inventing a public package URL.

### Fixed

- JSON-mode capability runs no longer allow Rich progress output to corrupt the
  stdout document; diagnostics remain on stderr or in debug logs.
- Partial enumeration failures now leave debug breadcrumbs instead of being
  silently swallowed.

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
  architecture support guidance, and machine-readable disposable evidence.

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
