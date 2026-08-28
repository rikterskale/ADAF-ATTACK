# Vendor readiness scorecard (v0.10.1 hardening baseline)

Judged like a commercial vendor selling to a mature red / purple / CISO buyer.
Scores are for the **operator product**, not line coverage alone.

**Scoring rule:** commands and behavioral tests win over commentary. A row is
**10** only when a new operator can complete it from the published command,
CLI/TUI/docs agree, a behavioral test locks the contract, and the failure path
is a product.

Private release: https://github.com/rikterskale/ADAF-ATTACK/releases/tag/v0.10.1  
Durable published evidence: [RELEASE_EVIDENCE_0.10.1.md](RELEASE_EVIDENCE_0.10.1.md)

## Baseline vs current hardening

| Dimension | Phase 0 audit | Current source | Notes |
|---|---:|---:|---|
| Zero-guess journey (`guide` omniscience) | 8.5 | **9.5** | `blocked_because`, entry/exit, and lost-operator `guide` recovery on every stage; TUI-state manual proof remains |
| First ten minutes deterministic | 6.5 | **9.0** | Automated doctor/quickstart/guide spine is locked; stranger first-ten MANUAL is still uncaptured |
| Failures as products | 7.0 | **9.0** | Classified failures plus support-bundle recovery; customer-environment proof remains MANUAL |
| CLI / TUI / docs one product | 8.0 | **9.5** | Empty surfaces and destructive confirm quote the same `guide` / rollback contract |
| Vendor packaging / release UX | 8.0 | **9.5** | Score honesty locked; published-artifact smoke green; physical transfer remains MANUAL |
| Safety as product | 9.0 | **9.5** | Gates intact; confirmation copy names rollback and what is not rolled back |
| Engineering bar | 9.0 | **9.5** | Phase 1–3 behavioral locks plus catalog Environment inference |
| **Overall product** | **~7.8** | **~9.3** | No 10/10 claim without repeatable stranger and customer-environment proof |

## UX_ACCEPTANCE_MATRIX row scores

| # | Enhancement | Phase 0 | Current source | Evidence |
|---:|---|---:|---:|---|
| 1 | First-run onboarding / offline demo | 8.0 | **9.0** | Normalized demo findings plus exact artifact first-ten smoke |
| 2 | Doctor / actionable preflight | 8.5 | **9.0** | `pip check` inconsistency now blocks user readiness |
| 3 | Kill-chain capability discovery | 9.0 | **9.0** | Strong automated contract; stranger proof remains manual |
| 4 | Plain-language explain / safety | 9.0 | **9.5** | Shared operator contract now includes rollback command and after-run next step |
| 5 | Review-first plans / risk previews | 9.0 | **9.5** | Plan/review quote the same risk, approvals, and rollback implication |
| 6 | Shell-safe copy-ready commands | 8.5 | **10.0** | Native argv renderer, declared shell dialect, and manual-copy fallback |
| 7 | Prerequisite / dependency nav | 8.5 | **9.0** | Extras errors and doctor remediation |
| 8 | Structured progress stages | 8.5 | **9.5** | Every stage has entry/exit, fallback, and `blocked_because` |
| 9 | Evidence-backed next actions | 8.5 | **10.0** | Redacted finding/artifact basis is identical across every next-action surface |
| 10 | Session findings dashboard | 9.0 | **9.5** | Empty findings/sessions/graph name the same `suggested_command` as `guide` |
| 11 | Unified search | 9.0 | **9.0** | Compact layout and evidence search |
| 12 | Session comparison | 9.0 | **9.0** | Behavioral comparison contract |
| 13 | Target / OPSEC profiles | 9.0 | **9.0** | Profile and TUI controls |
| 14 | Favorites / recents / completions | 9.0 | **9.0** | Non-secret persistence contracts |
| 15 | Timeline / rollback / redacted packaging | 8.5 | **9.5** | Destructive confirm quotes rollback command and Not rolled back |
| 16 | Unified guided journey | 8.5 | **10.0** | Shared snapshot/renderer plus fail-closed session and corrupt-state recovery |

**No row below 9.** Rows 6, 9, and 16 reach 10 through repeatable isolated
new-operator contracts, cross-surface parity, behavioral locks, and productized
failure paths. Phases 1–3 raised several 9.0 rows to 9.5; they do not mint an
overall 10. Overall 10 remains reserved for customer-environment evidence and
release-manager sign-off for the exact candidate. Kali host behavior and
organization air-gap transfer controls remain manual release evidence.

## Published v0.10.1 evidence

The published evidence below proves the automated v0.10.1 artifact checks. The
durable record identifies manual evidence that was not captured. Current-source
hardening applies to the next candidate and requires a fresh completed pack.

1. Automated first-ten-minutes — clean artifact environments — **PASS**
2. Published-artifact smoke — https://github.com/rikterskale/ADAF-ATTACK/actions/runs/33112303284 — **PASS**
3. Air-gapped wheelhouse `--no-index --find-links` — **PASS**
4. Release-manager checklist / SECURITY advisory channel — **AUTOMATED CONTRACT PASS**
5. Narrow-terminal TUI compact-layout suite — **AUTOMATED PASS; MANUAL SPOT-CHECK NOT RECORDED**

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

Paste this exact sequence (the first-ten canon). Do not add live DC
commands. `guide` is the only next-step after quickstart.

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
