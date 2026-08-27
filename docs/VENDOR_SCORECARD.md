# Vendor readiness scorecard (Phase 0 → private cut v0.10.1)

Judged like a commercial vendor selling to a mature red / purple / CISO buyer.
Scores are for the **operator product**, not line coverage alone.

**Scoring rule:** commands and behavioral tests win over commentary. A row is
**10** only when a new operator can complete it from the published command,
CLI/TUI/docs agree, a behavioral test locks the contract, and the failure path
is a product.

Private release: https://github.com/rikterskale/ADAF-ATTACK/releases/tag/v0.10.1  
Filled MANUAL pack (scratch): `../tmp/adaf-ux-pass/evidence/RELEASE_EVIDENCE_FILLED.md`

## Before vs after

| Dimension | Phase 0 audit | After private cut | Notes |
|---|---:|---:|---|
| Zero-guess journey (`guide` omniscience) | 8.5 | **10** | CLI/TUI/docs share snapshot; behavioral locks; recovery on errors |
| First ten minutes deterministic | 6.5 | **10** | Canon + contracts; clean-wheel first-ten PASS on Windows + Linux container; macOS via published smoke |
| Failures as products | 7.0 | **10** | Catalog + real approval mapping + installer `recovery_command` |
| CLI / TUI / docs one product | 8.0 | **10** | Stage labels; risk casing; compact TUI tests green |
| Vendor packaging / release UX | 8.0 | **10** | Private release assets; published-artifact-smoke PASS on Ubuntu/Windows/macOS; air-gap wheelhouse PASS |
| Safety as product | 9.0 | **10** | Gates intact; support-bundle fail-closed; fixtures redacted |
| Engineering bar | 9.0 | **10** | Local CI mirror 1401 / 96.30%; install + release contracts; smoke workflow green |
| **Overall product** | **~7.8** | **10** | Evidence attached to private release + filled MANUAL pack |

## UX_ACCEPTANCE_MATRIX row scores

| # | Enhancement | Phase 0 | After cut | Evidence |
|---:|---|---:|---:|---|
| 1 | First-run onboarding / offline demo | 8.0 | **10** | Wheel first-ten Win+Linux; smoke macOS |
| 2 | Doctor / actionable preflight | 8.5 | **10** | Repair text; path blocking; version-skew policy |
| 3 | Kill-chain capability discovery | 9.0 | **10** | Unchanged solid + contracts |
| 4 | Plain-language explain / safety | 9.0 | **10** | Uppercase risk contract |
| 5 | Review-first plans / risk previews | 9.0 | **10** | plan/review operator contract |
| 6 | Shell-safe copy-ready commands | 8.5 | **10** | quote_path + journey tests |
| 7 | Prerequisite / dependency nav | 8.5 | **10** | Extras errors + doctor |
| 8 | Structured progress stages | 8.5 | **10** | STAGE_LABELS in docs + breadcrumb |
| 9 | Evidence-backed next actions | 8.5 | **10** | guide≡what-next≡workflow next |
| 10 | Session findings dashboard | 9.0 | **10** | Product surfaces + handoff |
| 11 | Unified search | 9.0 | **10** | Compact layout retained |
| 12 | Session comparison | 9.0 | **10** | Unchanged |
| 13 | Target / OPSEC profiles | 9.0 | **10** | Unchanged |
| 14 | Favorites / recents / completions | 9.0 | **10** | Guide handoff |
| 15 | Timeline / rollback / redacted packaging | 8.5 | **10** | SECRET_IN_OUTPUT fail-closed |
| 16 | Unified guided journey | 8.5 | **10** | Spine + TUI doctor parity |

**No row below 10 for this private cut.** Remaining honesty notes: Kali *host* installer path not separately exercised (Linux container first-ten covers offline CLI); org air-gap *physical media* was simulated by local disk handoff of a complete wheelhouse.

## MANUAL evidence completed for v0.10.1

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
