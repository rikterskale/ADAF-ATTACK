# Vendor readiness scorecard (v0.10.1 hardening baseline)

Judged like a commercial vendor selling to a mature red / purple / CISO buyer.
Scores are for the **operator product**, not line coverage alone.

**Scoring rule:** commands and behavioral tests win over commentary. A row is
**10** only when a new operator can complete it from the published command,
CLI/TUI/docs agree, a behavioral test locks the contract, and the failure path
is a product.

Private release: https://github.com/rikterskale/ADAF-ATTACK/releases/tag/v0.10.1  
Filled MANUAL pack (scratch): `../tmp/adaf-ux-pass/evidence/RELEASE_EVIDENCE_FILLED.md`

## Baseline vs current hardening

| Dimension | Phase 0 audit | Current source | Notes |
|---|---:|---:|---|
| Zero-guess journey (`guide` omniscience) | 8.5 | **9.0** | Shared snapshot and recovery locks; broader TUI-state manual proof remains |
| First ten minutes deterministic | 6.5 | **9.0** | Clean-artifact smoke now runs the exact doctor/quickstart/guide spine |
| Failures as products | 7.0 | **9.0** | End-to-end classified failures and generic support-bundle recovery |
| CLI / TUI / docs one product | 8.0 | **9.0** | Offline-first TUI wizard and automated 80-column interaction proof |
| Vendor packaging / release UX | 8.0 | **9.5** | Published artifact proof on all three OS families; physical transfer remains manual |
| Safety as product | 9.0 | **9.5** | Gates intact; support-bundle fail-closed; normalized demo findings are redacted |
| Engineering bar | 9.0 | **9.0** | Behavioral and release contracts remain the shipping gate |
| **Overall product** | **~7.8** | **~9.1** | No 10/10 claim without repeatable stranger and customer-environment proof |

## UX_ACCEPTANCE_MATRIX row scores

| # | Enhancement | Phase 0 | Current source | Evidence |
|---:|---|---:|---:|---|
| 1 | First-run onboarding / offline demo | 8.0 | **9.0** | Normalized demo findings plus exact artifact first-ten smoke |
| 2 | Doctor / actionable preflight | 8.5 | **9.0** | `pip check` inconsistency now blocks user readiness |
| 3 | Kill-chain capability discovery | 9.0 | **9.0** | Strong automated contract; stranger proof remains manual |
| 4 | Plain-language explain / safety | 9.0 | **9.0** | Shared operator contract |
| 5 | Review-first plans / risk previews | 9.0 | **9.0** | Plan/review operator contract |
| 6 | Shell-safe copy-ready commands | 8.5 | **9.0** | Quoted path and journey tests |
| 7 | Prerequisite / dependency nav | 8.5 | **9.0** | Extras errors and doctor remediation |
| 8 | Structured progress stages | 8.5 | **9.0** | Stage labels, breadcrumb, and timeline metadata |
| 9 | Evidence-backed next actions | 8.5 | **9.0** | `guide` = `what-next` = `workflow next` |
| 10 | Session findings dashboard | 9.0 | **9.0** | Quickstart now produces a meaningful dashboard |
| 11 | Unified search | 9.0 | **9.0** | Compact layout and evidence search |
| 12 | Session comparison | 9.0 | **9.0** | Behavioral comparison contract |
| 13 | Target / OPSEC profiles | 9.0 | **9.0** | Profile and TUI controls |
| 14 | Favorites / recents / completions | 9.0 | **9.0** | Non-secret persistence contracts |
| 15 | Timeline / rollback / redacted packaging | 8.5 | **9.0** | Idempotent rollback-kind proof and fail-closed redaction |
| 16 | Unified guided journey | 8.5 | **9.0** | Offline-first TUI spine and shared snapshot |

**No row below 9.** A score of 10 remains reserved for repeatable stranger proof,
customer-environment failure evidence, and release-manager sign-off for the exact
candidate. Kali host behavior and organization air-gap transfer controls remain
manual release evidence.

## Published v0.10.1 evidence

The published evidence below proves the v0.10.1 artifact as released. The
current-source hardening scores above apply to the next candidate and require a
fresh release evidence pack before publication.

1. First-ten-minutes — Windows clean venv + Linux docker wheel — **PASS** (macOS via smoke)
2. Published-artifact smoke — https://github.com/rikterskale/ADAF-ATTACK/actions/runs/33112303284 — **PASS**
3. Air-gapped wheelhouse `--no-index --find-links` — **PASS**
4. Release-manager checklist / SECURITY advisory channel — **PASS**
5. Narrow-terminal TUI compact-layout suite — **PASS**

## Local verification commands

```bash
ruff check src tests
ruff format --check src tests
mypy src/adaf_attack
python -m compileall -q src tests
.\scripts\Invoke-Tests.ps1 --cov=adaf_attack --cov-branch --cov-fail-under=95
python scripts/check_cli_documentation.py
python scripts/check_install_contracts.py
python scripts/check_release_readiness.py --repo-root .
```

## Vendor SE first-ten-minutes script

```bash
python -m pip check
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace ./quickstart
adaf-attack --format json guide --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack --format json paths
```

Windows installer: `.\scripts\Install-AdafAttack.ps1 -Package .\adaf_attack-*-py3-none-any.whl -Extras full -Json`  
Kali: `bash scripts/install-kali.sh --package ./adaf_attack-*-py3-none-any.whl --json`
