# UX acceptance matrix

This matrix is the release checklist for the sixteen operator-facing UX
enhancements. Every item has a CLI entry point, a TUI surface where
appropriate, and a behavioral test location. The workflows remain
review-first: recommendations never execute commands automatically, and
destructive actions retain their existing `--force`, approval-token, and
rollback requirements.

Vendor scores after this UX pass are recorded in [VENDOR_SCORECARD.md](VENDOR_SCORECARD.md).
**No row may ship below 9.** A row is **10** only with stranger MANUAL proof,
CLI/TUI/docs agreement, a behavioral lock, and a productized failure path.

| # | Enhancement | CLI surface | TUI surface | Primary coverage | Score |
|---:|---|---|---|---|---:|
| 1 | First-run onboarding and offline demo | `quickstart`, `init`, `setup`, `demo` | Quickstart and first-launch wizard | `tests/test_cli_ux.py`, `tests/test_install_contracts.py` | 9 |
| 2 | Doctor and actionable preflight checks | `doctor`, `check`, `paths` | Readiness panel and target validation | `tests/test_doctor_prerequisites.py`, `tests/test_phase2_self_explain.py` | 9.5 |
| 3 | Kill-chain capability discovery | `list-capabilities --by-phase` | Phase-grouped capability list | `tests/test_ux_enhancements.py` | 9 |
| 4 | Plain-language explanations and safety ratings | `explain`, `capability-help` | Explain selected | `tests/test_novice_ux.py`, `tests/test_phase2_self_explain.py` | 9.5 |
| 5 | Review-first plans and risk previews | `plan`, `review` | Review checklist and acknowledgement gate | `tests/test_ux_enhancements.py`, `tests/test_phase2_self_explain.py` | 9.5 |
| 6 | Shell-safe copy-ready commands | `command`, plan output | Copy ready command | `tests/test_command_templates.py`, `tests/test_ux_hardening.py`, `tests/test_journey.py` | 9 |
| 7 | Prerequisite and dependency navigation | `capability dependencies` | Prerequisite/help panel | `tests/test_ux_ten_enhancements.py` | 9 |
| 8 | Structured progress stages | run output and plan payload | Progress/status panel | `tests/test_ux_ten_enhancements.py`, `tests/test_phase2_polish.py` | 9 |
| 9 | Evidence-backed next actions | `what-next`, `workflow next` | What next and copilot panels | `tests/test_journey.py`, `tests/test_phase4_vendor_proof.py` | 9.5 |
| 10 | Session findings dashboard and filters | `session show`, `engagement dashboard` | Findings dashboard | `tests/test_product_surfaces.py`, `tests/test_ux_ten_enhancements.py` | 9 |
| 11 | Unified search | `search`, `query` | Capability search box | `tests/test_ux_enhancements.py`, `tests/test_ux_hardening.py` | 9 |
| 12 | Session comparison | `session diff` | Compare sessions | `tests/test_ux_enhancements.py` | 9 |
| 13 | Target and OPSEC profiles | `profile` command group | Profile load/save/default controls | `tests/test_ux_ten_enhancements.py` | 9 |
| 14 | Favorites, recents, completions, and shortcuts | `favorites`, `recent`, `completions` | Pinning, recent targets, key help | `tests/test_ux_enhancements.py`, `tests/test_tui_app.py` | 9 |
| 15 | Timeline, rollback visibility, and redacted packaging | `timeline`, `cleanup-status`, `engagement package` | Timeline, reports, package evidence | `tests/test_standout_ux.py`, `tests/test_redaction.py` | 9.5 |
| 16 | Unified guided journey (install→closeout) | `guide`, `what-next`, `tour`, `workflow next` | Home / wizard complete / workflow panel | `tests/test_journey.py`, `tests/test_tui_app.py` | 9.5 |

Row 16 acceptance extras (Phase 1 spine):

- `guide`, `what-next`, and `workflow next` emit the same `suggested_command` for
  the same `--workspace` / `--session` snapshot.
- Journey actions include `risk`, `approvals`, `rollback_implication`,
  `recovery_command`, and stage `entry_criteria` / `exit_criteria`.
- Path-bearing suggested commands are shell-quoted.
- Failures include a `recovery_command` pointing at `adaf-attack guide`.

Phase 2 self-explain extras:

- Every doctor check includes remediation/repair text (keep-healthy for `ok`).
- `capability-help` / `explain` / `plan` / `review` expose the shared operator
  contract: risk, approvals, rollback implication, required `-P`, prerequisites,
  evidence produced, and stages.
- TUI help, review gate, readiness panel, and parameter form surface the same
  contract language before Run.
- Timeline events include status, duration, correlation, and a redacted summary.

## Release acceptance

Before a release is marked UX-complete:

1. Run the complete CI gate from `AGENTS.md`.
2. Run the offline quickstart from a clean virtual environment.
3. Run the CLI documentation validator so every documented command remains
   registered.
4. Exercise the TUI at both a normal terminal width and a narrow terminal
   width. The compact layout must keep search, capability selection, review,
   and execution controls reachable. Selecting a `-P`-heavy capability
   (for example `unpac-the-hash`, `golden-cert`, `dcshadow`, or
   `rbcd-ticket-workflow`) must show the dynamic parameter form before Run.
5. Confirm that generated commands quote values containing spaces or shell
   metacharacters, and that `capability-help` / `command` include required
   `-P` placeholders from the capability OptionSpec.
6. Confirm that timeline output contains status, duration, correlation, and
   safe detail fields without exposing secrets. Offline demo fixtures now
   include redacted `esc-chain.json` and `unpac.json` samples for day-2
   narrative review without live AD.

