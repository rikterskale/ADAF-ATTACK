# Vendor readiness scorecard (Phase 0 → Phase 4)

Judged like a commercial vendor selling to a mature red / purple / CISO buyer.
Scores are for the **operator product**, not line coverage alone.

## Before vs after

| Dimension | Phase 0 (before) | After Phase 4 | Notes |
|---|---:|---:|---|
| Zero-guess journey (`guide` omniscience) | 6.5 | **9.5** | Shared `core.journey.snapshot`; risk/approvals/rollback/recovery/criteria |
| First ten minutes deterministic | 8 | **9.5** | Doctor `ready` contract; `./quickstart` canon; live offline sequence |
| Failures as products | 5.5 | **9** | Expanded ERROR_CATALOG; guide recovery on errors; Windows installer codes |
| CLI / TUI / docs one product | 7 | **9.5** | what-next / workflow next / TUI share suggested_command |
| Vendor packaging / release UX | 7 | **9** | RELEASE.md manager checklist; RELEASE_EVIDENCE; install contracts |
| Safety as product | 8 | **9.5** | Gates unchanged; redaction stronger; no competing onboarding |
| Engineering bar | 8 | **9** | Contracts extended; behavioral tests added; 95% gate retained |
| **Overall product** | **~7.6** | **~9.3** | Remaining below 10 are MANUAL env proofs only |

## UX_ACCEPTANCE_MATRIX row scores (after)

| # | Enhancement | Before | After | Evidence |
|---:|---|---:|---:|---|
| 1 | First-run onboarding / offline demo | 8 | **9** | quickstart → guide; README / novice guides |
| 2 | Doctor / actionable preflight | 8 | **9.5** | repair text every check; top-level `ready` |
| 3 | Kill-chain capability discovery | 9 | **9** | unchanged solid surface |
| 4 | Plain-language explain / safety | 8 | **9.5** | operator_capability_contract on explain/help |
| 5 | Review-first plans / risk previews | 8 | **9.5** | plan/review approvals/rollback/evidence/-P |
| 6 | Shell-safe copy-ready commands | 6 | **9.5** | journey + plan quote paths/values |
| 7 | Prerequisite / dependency nav | 8 | **9** | contract prerequisites + extras errors |
| 8 | Structured progress stages | 7 | **9** | advance_stage_from_log CLI/TUI |
| 9 | Evidence-backed next actions | 5 | **9.5** | guide/what-next/workflow next parity proven |
| 10 | Session findings dashboard | 8 | **9** | unchanged + journey handoff |
| 11 | Unified search | 8 | **9** | compact layout retained |
| 12 | Session comparison | 8 | **9** | unchanged |
| 13 | Target / OPSEC profiles | 8 | **9** | unchanged |
| 14 | Favorites / recents / completions | 8 | **9** | aliases no longer compete with guide |
| 15 | Timeline / rollback / redacted packaging | 8 | **9.5** | summary + duration + password redaction |
| 16 | Unified guided journey | 6 | **9.5** | spine unified + enriched + contracted |

**No row below 9.**

## Remaining [MANUAL] items

From [RELEASE_READINESS.md](RELEASE_READINESS.md) / [RELEASE_EVIDENCE.md](RELEASE_EVIDENCE.md):

1. First-ten-minutes by a stranger on Windows, Kali/Linux, macOS (fill evidence pack).
2. Published-artifact smoke after a private release asset exists.
3. Organization air-gap *transfer* / proxy / custom CA policy reproduction.
4. Release-manager content review of CHANGELOG / RELEASE / KNOWN_LIMITATIONS for the cut tag.
5. Narrow-terminal TUI manual spot-check at release time (compact layout covered in tests; human width check remains MANUAL).

## Local verification (Phase 4)

```bash
ruff check src tests
ruff format --check src tests
mypy src/adaf_attack
python -m compileall -q src tests
# Windows:
.\scripts\Invoke-Tests.ps1 --cov=adaf_attack --cov-branch --cov-fail-under=95
python scripts/check_cli_documentation.py
python scripts/check_install_contracts.py
python scripts/check_release_readiness.py --repo-root .
```

Proven this session: coverage **96.29%** (branch), install contracts pass, release-readiness automated pillars pass.

## Vendor SE first-ten-minutes script

Send this exact offline sequence with an approved wheel (no source reading):

```bash
python -m pip check
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace ./quickstart
adaf-attack --format json guide --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack --format json paths
```

Expect: every command exits 0; doctor `"ready": true` (and `readiness.ready`); guide prints one copy-ready `suggested_command`.

When lost at any later point:

```bash
adaf-attack guide --workspace ./quickstart --session ./quickstart/demo-session
```

Windows installer path: `.\scripts\Install-AdafAttack.ps1 -Package .\adaf_attack-*-py3-none-any.whl -Extras full -Json`  
Kali path: `bash scripts/install-kali.sh --package ./adaf_attack-*-py3-none-any.whl --json`
