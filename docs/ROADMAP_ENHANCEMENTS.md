# Verified completion roadmap

This roadmap turns the 2026-09-03 repository audit into trackable enhancements. It separates concrete correctness work from coverage/evidence gaps and environment-gated release checks. Status is intentionally conservative: a passing test suite does not close an item when important branches or operational paths remain unverified.

## Current baseline

| Area | Evidence | Status |
| --- | --- | --- |
| Source inventory and imports | 135 Python source files; module import sweep passed | ✅ Verified |
| Compilation | `python -m compileall -q src tests` passed | ✅ Verified |
| Static checks | Ruff check and strict mypy passed | ✅ Verified |
| Tests | 1,502 passed, 2 warnings, using the repository Windows test wrapper | ✅ Verified |
| Branch coverage | 96.27% total (`--cov-branch`), above the 95% gate but not exhaustive | ⚠️ Improve |
| Formatting | Ruff format check reports 13 files requiring formatting | ⚠️ Open |
| CLI documentation and install contracts | Both validators passed | ✅ Verified |
| Release readiness | Default AppData paths are not writable in this environment, so the documented offline doctor command returns `ok: false` | ⚠️ Environment-gated |
| Skipped protocol tests | Key credential/RBCD tests require impacket; TGT capture tests require socket permissions | ⚠️ Evidence gap |

The test result above is reproducible through `scripts/Invoke-Tests.ps1`, which redirects temporary state to repository-local directories on Windows. Direct pytest execution against the locked global temp directory is not a valid product failure signal for this checkout.

## Recommended implementation order

| Order | ID | Priority | Enhancement | Current state | Done when |
| ---: | --- | --- | --- | --- | --- |
| 1 | RM-001 | P0 | Restore the caller's working directory in `capabilities/ticket_forge.py` and add a regression test covering success and failure paths | ✅ Implemented and verified; full suite passes with 1,503 tests | Ticket forging cannot leak a changed process CWD, including when the underlying forger raises |
| 2 | RM-002 | P0 | Add behavioral evidence for native protocol paths: `core/drs_addentry.py`, `core/unpac.py`, `capabilities/pkinit_auth.py`, `capabilities/esc_chain.py`, and `capabilities/impacket_exec.py` | ✅ Implemented and verified with 12 focused tests; targeted coverage is 96%, 96%, 97%, 99%, and 100% respectively | Mocked protocol harnesses cover success, dependency absence, malformed responses, dispatch, and cleanup/error paths |
| 3 | RM-003 | P1 | Close capability edge-path coverage for campaign, credential, relay, spray, and workflow adapters | Several modules are 85–99% covered with identifiable missing branches | Each listed branch has a behavior-focused test or is documented as an intentionally unreachable/platform-gated path |
| 4 | RM-004 | P1 | Close CLI, workflow, journey, and TUI interaction branches | CLI 93%; journey 87%; TUI 96%; wrapper modules have smaller gaps | User-visible failure, cancellation, JSON, approval, and recovery paths are tested without weakening the CLI contract |
| 5 | RM-005 | P1 | Close core safety and portability branches: LDAP/auth, paths, redaction, rollback, runner, target, vault, and UX helpers | Most are 93–99%; `ldap_util.py` is 83% | Boundary conditions, permission errors, cleanup, rollback, and platform-specific branches are behaviorally covered |
| 6 | RM-006 | P2 | Decide and implement deferred ADCS enumeration checks, beginning with ESC5 and then the remaining explicitly deferred checks | `adcs_enum.py` documents an ESC5 ACL check as “not in this pass”; other ADCS capability gaps remain evidence items | Capability output either implements the check with tests and operator guidance or records a deliberate supported limitation |
| 7 | RM-007 | P2 | Make supported-environment readiness validation explicit for writable data/config/workspace paths | Release readiness is blocked only by the current host's locked default AppData paths | CI and release validation run in a writable supported environment and distinguish host configuration failures from product failures |
| 8 | RM-008 | P2 | Resolve the 13 Ruff formatting failures and keep the CI-pinned Ruff version aligned locally | `ruff check` passes; `ruff format --check` does not | Format check passes under the CI-pinned toolchain, with no unrelated behavior changes |
| 9 | RM-009 | P2 | Re-run release, install, offline-command, and user-acceptance certification after the P0/P1 work | Install/docs contracts pass; full release readiness is not currently certified | Release readiness, packaging, offline demos, rollback, and documented CLI journeys pass in a clean supported environment |

## Detailed backlog

### RM-001 — Ticket-forge process-state safety

`capabilities/ticket_forge.py` changed the process working directory before invoking the forger and had an empty `finally` block. This was the clearest implementation-first item because it was a concrete correctness defect, the fix was narrow, and it did not require a dependency, schema, or CLI contract change. It is now fixed and covered by success- and failure-path regression tests.

Scope:

- Replace the manual `os.chdir`/empty `finally` pattern with a restoration-safe context.
- Preserve the existing output and error behavior.
- Add tests proving the original CWD is restored after both successful and failing forge attempts.

### RM-002 — Native protocol evidence

The audit found low coverage in code that directly handles security-sensitive protocol behavior. The dedicated evidence suite is `tests/test_rm002_native_protocol_evidence.py` and now covers:

- `core/unpac.py` — PAC decryption, missing TGT handling, U2U request assembly, PAC recovery, and environment restoration; 96% targeted coverage.
- `core/drs_addentry.py` — request construction, bind rejection, RPC failure, AddEntry error/reply error, unbind, and successful remote modification; 96% targeted coverage.
- `capabilities/pkinit_auth.py` — `gettgtpkinit` fallback, ccache discovery, AS-REP key/NT hash extraction, and artifact recording; 97% targeted coverage.
- `capabilities/esc_chain.py` — ESC override normalization plus modern ESC9 and ESC8 runner dispatch; 99% targeted coverage.
- `capabilities/impacket_exec.py` — Kerberos, hash, AES, password, and no-credential argv construction; 100% targeted coverage.

Tests use the repository's mocked LDAP/impacket patterns and prove observable behavior, including optional dependency handling, malformed/native response parsing, cleanup, and failure reporting. The full branch-coverage gate now passes at 97.23% with 1,515 tests. The goal remains to avoid forcing every defensive or third-party implementation branch to 100% when that would only create brittle tests.

### RM-003 — Capability adapter closure

Prioritize missing branches in `campaign_run.py`, `credential_free.py`, `credential_inventory.py`, `ntlm_relay.py`, `relay_ops.py`, `unpac_the_hash.py`, `next_actions.py`, `password_spray.py`, `workflow_wrappers.py`, and the remaining small ADCS/attack-path gaps. Include timeout, partial-result, denial, cancellation, and JSON-output behavior where applicable.

### RM-004 — Operator journey closure

Prioritize the large, user-visible surfaces: `cli.py`, `core/journey.py`, and `tui/app.py`. Cover invalid input, approval/force gates, command failures, recovery prompts, non-interactive JSON responses, and terminal/UI fallbacks. Keep `docs/CLI_REFERENCE.md` synchronized if any command behavior or registration changes.

### RM-005 — Core safety and portability closure

Target the remaining branches in `core/auth.py`, `core/capability_profiles.py`, `core/cleanup.py`, `core/cli_contract.py`, `core/command_templates.py`, `core/engineering.py`, `core/ldap_util.py`, `core/outcomes.py`, `core/paths.py`, `core/redaction.py`, `core/rollback.py`, `core/runner.py`, `core/standout_ux.py`, `core/target.py`, `core/ux.py`, `core/ux_extra.py`, `core/vault.py`, and `core/workflow_engine.py`. Focus on permission errors, cleanup guarantees, redaction, rollback records, and cross-platform behavior.

### RM-006 — Explicit ADCS limitation decisions

`adcs_enum.py` contains an explicit ESC5 caveat: the CA server computer-object ACL check is not implemented in that pass. Treat this as a product decision item, not an accidental stub. For each deferred ESC check, choose one of:

- implement, test, document, and include in the capability contract; or
- retain as a named limitation with a safe operator-facing next action.

### RM-007 — Environment-gated release evidence

The release-readiness failure was caused by denied access to the host's default AppData data/config/workspace locations. Add or document a supported writable-path setup for readiness validation, then rerun the exact offline commands. Do not hide a real permission failure by changing the command's result semantics.

### RM-008 — Formatting gate

The formatter reports these files: `capabilities/__init__.py`, `capabilities/asrep_roast.py`, `capabilities/asreq_userhunt.py`, `capabilities/capability_catalog.py`, `capabilities/credential_ops.py`, `cli.py`, `core/auth.py`, `core/completions.py`, `core/ldap_util.py`, `core/registry.py`, `core/target.py`, `tests/test_auth.py`, and `tests/test_core_paths_and_next_actions.py`.

Apply formatting as a focused mechanical change, then rerun the CI-matching check. Do not combine it with behavior changes unless review explicitly wants that bundling.

### RM-009 — Release/UAT certification

After implementation work, certify the user-facing contracts again: clean editable install, CLI documentation parity, JSON output with `ok: true`, offline demo flows, rollback behavior, package/install contracts, and the full Windows/Linux/macOS test matrix. Record any remaining host-only limitations separately from product defects.

## Intentionally not counted as defects yet

The audit also found empty `pass` statements used for marker classes, empty exception handlers, best-effort permission cleanup, or optional playbook-only fallbacks. These should only become roadmap items when they mask a user-visible failure or violate a documented contract. Likewise, socket- and optional-impacket-skipped tests are evidence gaps until the supported test environment is available; they are not proof of a runtime defect by themselves.

## Decision

**RM-001 and RM-002 are complete.** Ticket forging restores CWD safely, and native protocol evidence now covers the five priority paths. The full suite passes with 1,515 tests at 97.23% branch coverage. Implement **RM-003 next**, the remaining capability adapter edge paths.
