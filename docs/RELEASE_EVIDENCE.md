# Release evidence templates (manual)

Use this one-page pack for every **[MANUAL]** item in
[RELEASE_READINESS.md](RELEASE_READINESS.md). Attach the completed copy to the
private release record with wheel hashes and `release-manifest.json`.

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
SHA256SUMS + release-manifest. No source reading.

| OS | Python | Result | Notes |
|---|---|---|---|
| Windows | 3.__ | PASS / FAIL | |
| Kali/Linux | 3.__ | PASS / FAIL | |
| macOS (offline CLI) | 3.__ | PASS / FAIL | |

Commands run (must all exit 0):

```text
python -m pip check
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace ./quickstart
adaf-attack --format json guide --workspace ./quickstart --session ./quickstart/demo-session
```

Doctor `"ready": true` observed: YES / NO  
Guide suggested_command pasted and executed successfully: YES / NO  
Evidence attached (redacted doctor JSON / paths): __________

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

## 4. Readiness summary attachment

| Check | Result |
|---|---|
| All required CI jobs green on release commit | PASS / FAIL |
| CHANGELOG / RELEASE.md / KNOWN_LIMITATIONS reviewed | PASS / FAIL |
| Rollback/recovery location for exact assets recorded | PASS / FAIL |
| requirements-operator.txt / wheelhouse lock attached | PASS / FAIL |

Signer / attestor: __________
