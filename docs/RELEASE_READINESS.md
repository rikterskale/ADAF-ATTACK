# Release Readiness Standard

A release is **not** ready because `--cov-fail-under=100` passed. Coverage proves
lines executed under test; it does not prove a stranger can install the tool,
diagnose their own problems, exercise every feature, recover from a bad run, or
find the answer in the docs. This standard defines those gates concretely.

Each gate is tagged:

- **[CI]** — enforced automatically today by the named job in
  `.github/workflows/ci.yml`. If it regresses, the build goes red.
- **[MANUAL]** — a release-sign-off gate a human must perform and record for the
  candidate version. CI cannot prove it (no live AD lab, no clean OS image, no
  real end user).
- **[GAP]** — not yet enforced anywhere; a candidate for automation.

A version ships only when **every gate below is green and recorded** in the
release checklist at the end.

The five pillars are enforced as one build-breaking lane by the
**`release-readiness`** job in `.github/workflows/ci.yml`, which runs
`scripts/check_release_readiness.py` against a clean **base-wheel** install (the
exact artifact a new user gets). That script does two things: it drives the
installed `adaf-attack` console script to prove each pillar behaviorally, and it
parses `ci.yml` to assert each pillar is still wired to a live job/step and its
contract test — so this standard cannot silently decay back into a coverage
number. Deleting any enforcement point turns the build red.

---

## 0. Scope

- **"New user"** = someone who has never run this tool, on a supported platform,
  starting from the published artifact (release wheel/sdist or the installer
  script) and the docs — *not* from a developer checkout.
- **Supported platform matrix** (every install/troubleshoot gate must pass on
  each row):

  | OS | Python | Install path |
  |----|--------|--------------|
  | Ubuntu 24.04 | 3.11 / 3.12 / 3.13 | wheel, sdist |
  | Windows 2022 | 3.11 / 3.12 / 3.13 | `Install-AdafAttack.ps1` |
  | Kali (rolling) | system Python | `install-kali.sh` |

  A platform not proven for a release is **unsupported** for that release and
  must be labeled so in the release notes.

---

## 1. Proven installation

A new user can go from nothing to a working `adaf-attack` command.

- [ ] **Clean-env wheel install** succeeds, `pip check` is clean, entry points
      run (`--version`, `list-capabilities`). **[CI: package → "Install wheel in
      clean environment"]**
- [ ] **Clean-env sdist install** succeeds, `pip check` clean, `doctor` runs.
      **[CI: package → "Install source distribution…"]**
- [ ] **Builds are reproducible** and checksummed (`SHA256SUMS` verified twice).
      **[CI: package → "Verify reproducible distributions and checksums"]**
- [ ] **Windows installer** produces a working venv + console script and passes
      `doctor`. **[CI: windows-installer]**
- [ ] **Kali installer** guards against non-Kali hosts and exposes `--help`.
      **[CI: scripts → "Exercise Kali installer guard and help"]**
- [ ] **Fresh-machine install from the *release artifact*** (not the repo) on each
      supported-matrix row: install, `pip check`, `adaf-attack --version`.
      **[MANUAL]** — CI installs from a locally built wheel on hosted runners; it
      does not prove the *published* artifact installs on a clean OS image.
- [ ] **Offline / air-gapped install** documented and verified (operators run in
      isolated environments): sdist + pinned requirements install with
      `--no-index`. **[CI: package proves the mechanism; MANUAL for the release
      artifact]**

**Acceptance:** every matrix row has a recorded successful install from the
candidate artifact, with `pip check` clean.

---

## 2. Guided troubleshooting

When something is missing or misconfigured, the tool tells the user exactly what
to do — they never have to read source.

- [ ] **`doctor` reports the full runtime surface**: interpreter floor, required
      and optional packages, and the external CLI tools capabilities shell out to
      (`ntlmrelayx`, `certipy`). **[CI: doctor tests + operator-workflow]**
- [ ] **Every non-OK check carries actionable, copy-pasteable remediation**; the
      JSON contract (`id`, `status`, `value`, `remediation`) is stable.
      **[CI: test_cli_contract → doctor contract]**
- [ ] **Human output renders remediation verbatim** (no markup swallowing, e.g.
      `adaf-attack[kerberos]` shows intact). **[CI: doctor tests]**
- [ ] **Every user-facing failure maps to an actionable error**, not a raw
      traceback (`ERROR_CATALOG` / `ActionableError`). **[CI: test_cli_contract;
      GAP: coverage that *every* CLI error path routes through the catalog]**
- [ ] **`doctor` exits non-zero only on truly blocking problems**; degraded
      optional tooling is a warning, not a failure. **[CI: doctor tests]**
- [ ] **First-10-minutes walkthrough**: a person who has never used the tool
      follows only `doctor` + README from a fresh install to a first successful
      offline command, unaided. Record friction. **[MANUAL]**

**Acceptance:** on a machine deliberately missing each optional dependency,
`doctor --explain` names the gap and the exact fix, and the walkthrough
completes without reading code.

---

## 3. Full-feature validation

Every advertised capability actually works — or its limits are stated.

- [ ] **CLI surface smoke**: `--version`, `doctor`, `list-capabilities`, `paths`.
      **[CI: tests → CLI smoke]**
- [ ] **Offline operator lifecycle**: engagement init → validate → run → report
      (HTML **and** PDF) → package, plus the analysis command sweep
      (rank-paths, credential-exposure, bloodhound-reconcile, trust/delegation/
      adcs validation, campaign-compose, forest-campaign, purple-handoff, …).
      **[CI: operator-workflow]**
- [ ] **Every registered capability is reachable** — listed by
      `list-capabilities` and answered by `capability-help`. **[CI: tests →
      test_release_contracts::test_every_capability_is_reachable]** (Exercising
      each id's offline `plan` preview remains **[GAP]**.)
- [ ] **Network / live-AD capabilities validated against a test forest** —
      `ldap-enum`, `kerberoast`, `rbcd`, `esc-chain`/`cert-request` (with
      `certipy`), `ntlm-relay` (with `ntlmrelayx`), `coerce`, `dcsync`, etc. Run
      against a disposable lab DC; record command, output, and cleanup.
      **[MANUAL]** — CI cannot host a domain.
- [ ] **Optional-tooling capabilities degrade gracefully** when the tool is
      absent (e.g. `cert-request` emits a playbook without `certipy`).
      **[CI: capability tests]**

**Acceptance:** a capability is "shipped" only if it is (a) offline-tested, or
(b) lab-validated for this release with a recorded transcript, or (c) explicitly
marked experimental/unsupported in the docs.

---

## 4. Tested recovery paths

The tool never leaves a target — or the operator's own session — in a broken
state they can't undo.

- [ ] **Every destructive capability wires a rollback primitive**
      (`register_cleanup` / `record_pre_state`) or is exempted with a stated
      reason. **[CI: tests →
      test_release_contracts::test_destructive_capabilities_declare_rollback_or_are_exempt]**
- [ ] **Rollback restores state**, proven offline per destructive capability:
      each revertable kind (RBCD, ACL, template-mod, gpo-link, gpo-sysvol,
      shadow-creds) round-trips through `execute_cleanup` to `completed`, and
      advisory kinds are proven *not* auto-reverted. **[CI: tests →
      test_rollback_matrix]** (This matrix caught `shadow-creds` recording a
      rollback the engine could not execute.)
- [ ] **Destructive actions refuse without `--force`.** **[CI: operator-workflow
      → cleanup blocked without --force; capability tests]**
- [ ] **Interrupted / partial runs are recoverable**: sessions are resumable and
      a failed campaign phase stops or continues per policy without corrupting the
      evidence session. **[CI: campaign tests]**
- [ ] **Vault key loss is handled gracefully** (secret material becomes
      unreadable with a clear error, never a crash or silent plaintext).
      **[CI: vault tests]**
- [ ] **Cleanup is idempotent and reports partial failure** (already-reverted or
      inaccessible items don't abort the rest). **[CI: cleanup tests]**

**Acceptance:** for every `destructive=True` capability there is a recorded test
proving the rollback path restores the prior state, and a manual spot-check of at
least one destructive capability's rollback in the lab for the release.

---

## 5. Documentation

Everything above is discoverable and current without reading source.

- [ ] **Per-platform install guide** exists and its commands are current
      (README, `docs/KALI.md`, `docs/WINDOWS.md`, novice guides). **[CI:
      workflow-contract asserts the files exist; tests → test_docs_commands
      asserts every documented `adaf-attack` command/capability is real and runs
      a safe offline subset]**
- [ ] **Troubleshooting is documented** and points at `doctor --explain`.
      **[CI: README covers it]**
- [ ] **Per-capability help** is available (`capability-help`) and every
      capability appears in `list-capabilities`. **[CI: operator-workflow]**
- [ ] **Contributor guide** (`CONTRIBUTING.md`) reproduces the CI gate locally.
      **[CI: file exists; MANUAL: a contributor confirms it works]**
- [ ] **CHANGELOG / RELEASE notes** updated for the version, including **known
      limitations and unsupported platforms/capabilities**. **[MANUAL]**
- [ ] **Version bump** is consistent across `pyproject.toml`,
      `adaf_attack.__version__`, and the CI smoke assertions. **[CI: package
      asserts `__version__`; MANUAL: bump before tagging]**
- [ ] **Security posture is current**: dependency audit clean, SBOM generated,
      no tracked secrets. **[CI: security]**

**Acceptance:** a new user can answer "how do I install / fix / use / undo this"
from the docs alone, and the release notes state what is *not* covered.

---

## Release sign-off checklist

Copy into the release PR/issue; a version ships only when all are checked.

```
Version: __________        Release manager: __________        Date: __________

[ ] All CI lanes green on the release commit (lint, typecheck, tests, security,
    codeql, scripts, workflow-contract, package, operator-workflow,
    release-readiness, windows-installer, ci-gate)
[ ] §1 Install: fresh-artifact install recorded for every supported-matrix row
[ ] §2 Troubleshooting: doctor green per platform; first-10-min walkthrough done
[ ] §3 Features: offline lifecycle green; lab-validation transcript attached for
    network capabilities; experimental features labeled
[ ] §4 Recovery: destructive-capability rollback matrix green; one lab rollback
    spot-check recorded
[ ] §5 Docs: install/troubleshoot/use/undo current; CHANGELOG + version bumped;
    known limitations stated
[ ] Rollback/repro info captured: exact artifacts + SHA256SUMS archived
```

---

## Turning [MANUAL]/[GAP] gates into [CI]

Priority order to reduce human sign-off cost over time:

1. ~~**Capability reachability test**~~ — **DONE.** `tests/test_release_contracts.py`
   asserts every registered capability is listed and has working help. (§3)
2. ~~**Destructive-rollback matrix test**~~ — **DONE.** `test_release_contracts.py`
   enforces the wiring; `test_rollback_matrix.py` proves each revertable kind
   round-trips through `execute_cleanup` and advisory kinds are not
   auto-reverted. (§4)
3. ~~**Docs-command test**~~ — **DONE.** `test_docs_commands.py` asserts every
   `adaf-attack` command/capability referenced in fenced doc blocks is real and
   runs a safe offline subset. (§2, §5)
4. **Published-artifact install job** — a scheduled workflow that installs the
   last release from PyPI/release assets on clean OS images. (§1)
5. **Lab harness** — an opt-in, credential-gated workflow against a disposable
   test forest for the network capabilities. (§3, §4)

> The `workflow-contract` job also now asserts these contract tests and the
> readiness docs stay present, and that the pre-commit `ruff` pin matches the
> `requirements-ci.txt` pin — so the enforced gates cannot be silently removed
> or drift out of sync.
```
