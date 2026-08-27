# Vendor readiness scorecard (Phase 0 → Phase 4)

Judged like a commercial vendor selling to a mature red / purple / CISO buyer.
Scores are for the **operator product**, not line coverage alone.

**Scoring rule:** commands and behavioral tests win over commentary. A row is
**10** only when a new operator can complete it from the published command,
CLI/TUI/docs agree, a behavioral test locks the contract, and the failure path
is a product. Do not inflate a **9** to a **10** without stranger MANUAL proof.

Audit baseline (Phase 0, this pass): overall **~7.8** — see
`../tmp/adaf-ux-pass/review/00_gap_scorecard.md` when working from the UX scratch
tree. In-repo prior claim of ~9.3 was aspirational and is superseded below.

## Before vs after (this UX pass)

| Dimension | Phase 0 audit | After Phase 1–2 | Notes |
|---|---:|---:|---|
| Zero-guess journey (`guide` omniscience) | 8.5 | **9.0** | TUI shares doctor snapshot; no silent authorize; journey follows authorized workflows without demo |
| First ten minutes deterministic | 6.5 | **9.0** | Single canon + install-contract fence; stranger MANUAL still open |
| Failures as products | 7.0 | **9.0** | Real approval messages map to `APPROVAL_TOKEN_*`; Kali codes catalogued; Windows `recovery_command` |
| CLI / TUI / docs one product | 8.0 | **9.0** | Stage labels in README/USER_READINESS; risk uppercase; tour/home default-workspace documented |
| Vendor packaging / release UX | 8.0 | **8.5** | Contracts + installer JSON parity; published-asset / air-gap transfer remain MANUAL |
| Safety as product | 9.0 | **9.5** | Gates unchanged; support-bundle fail-closed on secret hits; fixtures stay redacted |
| Engineering bar | 9.0 | **9.0** | Focused suites green; full AGENTS.md CI mirror deferred to Phase 4 |
| **Overall product** | **~7.8** | **~9.0** | Not 10: MANUAL stranger proofs + published-artifact smoke |

## UX_ACCEPTANCE_MATRIX row scores (after Phase 1–2)

| # | Enhancement | Phase 0 audit | After Phase 1–2 | Evidence |
|---:|---|---:|---:|---|
| 1 | First-run onboarding / offline demo | 8.0 | **9.0** | Canon quickstart → guide; contract-tested fences |
| 2 | Doctor / actionable preflight | 8.5 | **9.5** | Repair text; user-readiness blocks unwritable paths; version-skew check |
| 3 | Kill-chain capability discovery | 9.0 | **9.0** | Unchanged solid surface |
| 4 | Plain-language explain / safety | 9.0 | **9.5** | `OBSERVE`… risk on journey + operator contract |
| 5 | Review-first plans / risk previews | 9.0 | **9.5** | plan/review approvals/rollback/evidence/-P |
| 6 | Shell-safe copy-ready commands | 8.5 | **9.0** | Windows `quote_path` forward-slash normalization |
| 7 | Prerequisite / dependency nav | 8.5 | **9.0** | Contract prerequisites + extras errors |
| 8 | Structured progress stages | 8.5 | **9.0** | `STAGE_LABELS` mirrored in operator docs |
| 9 | Evidence-backed next actions | 8.5 | **9.5** | `recommendations[0]` ≡ guide `suggested_command` |
| 10 | Session findings dashboard | 9.0 | **9.0** | Unchanged + journey handoff |
| 11 | Unified search | 9.0 | **9.0** | Compact layout retained |
| 12 | Session comparison | 9.0 | **9.0** | Unchanged |
| 13 | Target / OPSEC profiles | 9.0 | **9.0** | Unchanged |
| 14 | Favorites / recents / completions | 9.0 | **9.0** | Aliases hand off to guide |
| 15 | Timeline / rollback / redacted packaging | 8.5 | **9.5** | `SECRET_IN_OUTPUT` fail-closed on support bundle |
| 16 | Unified guided journey | 8.5 | **9.5** | Spine unified; TUI doctor parity; behavioral locks |

**No row below 9.** Rows are not **10** until stranger MANUAL evidence + full CI mirror for this branch.

## Remaining [MANUAL] items

From [RELEASE_READINESS.md](RELEASE_READINESS.md) / [RELEASE_EVIDENCE.md](RELEASE_EVIDENCE.md):

1. First-ten-minutes by a stranger on Windows, Kali/Linux, macOS (fill evidence pack).
2. Published-artifact smoke after a private release asset exists.
3. Organization air-gap *transfer* / proxy / custom CA policy reproduction.
4. Release-manager content review of CHANGELOG / RELEASE / KNOWN_LIMITATIONS for the cut tag.
5. Narrow-terminal TUI manual spot-check at release time (compact layout covered in tests; human width check remains MANUAL).

Scratch copies of the fill-in pack live under the UX audit tree
(`review/manual_evidence/`) when using the default scratch path outside the repo.

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

Phase 4 CI mirror (branch `ux/phase1-guided-spine`, local):

- `ruff check` / `ruff format --check` / `mypy` / `compileall` — pass
- `pytest --cov=adaf_attack --cov-branch --cov-fail-under=95` — **1401 passed**, branch coverage **96.30%**
- `check_cli_documentation.py` / `check_install_contracts.py` — pass
- `check_release_readiness.py` — pass under project `.venv` (system-site `pip check` may fail on unrelated packages)
- First-ten script (`92_first_ten_minutes.ps1`) — pass with project `.venv` on PATH
- Transcript: UX scratch `logs/ci_mirror.txt` (outside the git tree)

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
