# Live capability readiness matrix

[`LIVE_CAPABILITY_MATRIX.json`](LIVE_CAPABILITY_MATRIX.json) is the machine-readable
release contract for every registered capability. The validator compares it
with the runtime registry, so adding a capability without adding a
classification fails CI.

Each row states whether the feature needs a live network, which optional tools
and disposable fixtures it needs, whether it mutates the lab, and which
sanitized evidence files a reviewer should retain. `live-mutating` always
requires a snapshot, explicit approval, and rollback evidence.

Validate it from a checkout:

```bash
python scripts/validate_live_capability_matrix.py
```

This proves classification completeness and safety metadata. It does not claim
that a feature works against a real domain; that proof remains the manual
procedure in [LIVE_AD_LAB_VALIDATION.md](LIVE_AD_LAB_VALIDATION.md).
