# Changelog

All notable changes are documented here. The project follows release versions
declared in `pyproject.toml`.

## 0.10.0

### Added

- Registered 40 experimental offensive capabilities for roadmap tracking
  (`planned_offensive`): ACL primitives (`add-member`, `acl-abuse`,
  `write-spn`, …), Server 2025 dMSA (`badsuccessor`, `dmsa-ouroboros`),
  ESC9–ESC16, Kerberos relay, golden cert, DPAPI backup key, SCCM, hybrid
  follow-ups, and joined workflows (`maq-rbcd-workflow`, `targeted-kerberoast`,
  `esc8-relay-workflow`, …). Runners are inert tracking stubs (`status:
  experimental`); they do not change targets.
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
