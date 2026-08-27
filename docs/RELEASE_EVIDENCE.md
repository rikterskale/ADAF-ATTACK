# Release evidence templates (manual)

Use this one-page pack for every **[MANUAL]** item in
[RELEASE_READINESS.md](RELEASE_READINESS.md). Attach the completed copy to the
private release record with wheel hashes and `release-manifest.json`.

Do **not** invent a public package URL. Operators install from the private
GitHub release channel or an approved internal index / wheelhouse only.

```text
Version: __________
Release manager: __________
Date (UTC): __________
Candidate commit SHA: __________
Wheel SHA256: __________
Sdist SHA256: __________
release-manifest.json present: YES / NO
release-provenance.json present: YES / NO (signed: YES / NO)
```

## 1. First-ten-minutes (new operator)

Operator is unfamiliar with the repo and has only an approved wheel +
SHA256SUMS + release-manifest. No source reading. Prefer the scratch scripts
`92_first_ten_minutes.sh` / `92_first_ten_minutes.ps1` when available outside
the tree; otherwise paste the canon below.

| OS | Python | Result | Notes |
|---|---|---|---|
| Windows | 3.__ | PASS / FAIL | |
| Kali/Linux | 3.__ | PASS / FAIL | |
| macOS (offline CLI) | 3.__ | PASS / FAIL | |

Commands run (must all exit 0; first-ten canon):

```text
python -m pip check
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace ./quickstart
adaf-attack --format json guide --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack --format json paths
```

Doctor `"ready": true` observed: YES / NO  
Guide suggested_command pasted and executed successfully: YES / NO  
Optional after success — `workflow next` same `suggested_command` as guide: YES / NO / SKIPPED  
Evidence attached (redacted doctor JSON / paths): __________

If doctor is not ready because paths are unwritable:

```text
adaf-attack paths --repair
adaf-attack --format json doctor --profile user-readiness --explain
```

## 2. Published-artifact smoke

Private GitHub release asset URL/tag: __________  
`published-artifact-smoke` workflow run URL: __________  
Ubuntu / Windows / macOS rows: PASS / FAIL / NOT YET PUBLISHED  

## 3. Air-gapped wheelhouse

Wheelhouse built with `scripts/build-release-wheelhouse.py` extras: __________  
Transfer method (approved media / internal mirror): __________  
Install used `--no-index --find-links`: YES / NO  
`pip check` after offline install: PASS / FAIL  
`doctor --profile user-readiness` ready: YES / NO  
Org proxy / custom CA notes (if any): __________

## 4. Readiness summary attachment

| Check | Result |
|---|---|
| All required CI jobs green on release commit | PASS / FAIL |
| CHANGELOG / RELEASE.md / KNOWN_LIMITATIONS reviewed | PASS / FAIL |
| Rollback/recovery location for exact assets recorded | PASS / FAIL |
| requirements-operator.txt / wheelhouse lock attached | PASS / FAIL |
| Version triple matches (pyproject / `__version__` / CHANGELOG) | PASS / FAIL |
| `guide` suggested_command works after quickstart | PASS / FAIL |
| Install contracts + release-readiness scripts green | PASS / FAIL |

## 5. Security disclosure path check

| Check | Result |
|---|---|
| SECURITY.md private advisory link still valid | PASS / FAIL |
| No secrets in demo fixtures / release notes | PASS / FAIL |
| Support-bundle redaction spot-check (no live secrets) | PASS / FAIL |

## 6. Narrow-terminal TUI spot-check

Compact layout is covered by automated tests. At release time, a human still
confirms a narrow terminal (≤80 columns) can search, select, review, and run.
Selecting a `-P`-heavy capability (`unpac-the-hash`, `golden-cert`, `dcshadow`,
or `rbcd-ticket-workflow`) must show the dynamic parameter form before Run.

| Check | Result |
|---|---|
| Width ≤80: search / select / review / run reachable | PASS / FAIL |
| `-P`-heavy cap shows parameter form before Run | PASS / FAIL |
| Home Cmd matches `adaf-attack guide` for same workspace | PASS / FAIL |

Terminal / OS notes: __________

Signer / attestor: __________
Date signed (UTC): __________
