# Published release evidence: v0.10.1

This durable record captures evidence that can be verified from the private
GitHub release and its workflows. It does not replace the per-candidate manual
template in [RELEASE_EVIDENCE.md](RELEASE_EVIDENCE.md).

## Release identity

| Field | Value |
|---|---|
| Tag | `v0.10.1` |
| Published (UTC) | `2026-08-27T20:08:30Z` |
| Publisher | `rikterskale` |
| Tagged commit | `7e5bbc74c48dca50277e92f59535dcb8cc4ee192` |
| Private release | <https://github.com/rikterskale/ADAF-ATTACK/releases/tag/v0.10.1> |
| Published-artifact smoke | <https://github.com/rikterskale/ADAF-ATTACK/actions/runs/33112303284> |

The published-artifact smoke completed successfully on Ubuntu 24.04, Windows
2022, and macOS 14 after all required assets were attached.

## Published assets

| Asset | SHA256 |
|---|---|
| `adaf_attack-0.10.1-py3-none-any.whl` | `fffe417db5beadb7237f29c423c00a3f7ad65854d32dd0a7658c0075354a9b5f` |
| `adaf_attack-0.10.1.tar.gz` | `ea3ec4124fbebef1243023da7d8110c1e22022b8dc2f96cf01b157dd51320144` |
| `release-manifest.json` | `630b58b2d53c6d620b206bcd4c6b3fb09e416f12739ac22e659e79ffb3a80b53` |
| `release-provenance.json` | `398fdaf60362dc6948ed09520dac04bf937826ff23bb88e681c86782051abe6d` |
| `SHA256SUMS` | `6e4568b002f73166cd863fd9f3e5851576efafcc176306bbbc7592c96374f9e4` |
| `sbom.json` | `23e9ba9ceca906f0384b77e44aed5adbefd397447844a1787c84557d7c780939` |

## Manual evidence status

**Manual evidence not captured in this repository:**

- the identity and notes of an unfamiliar operator completing first-ten-minutes;
- organization-specific physical air-gap transfer controls;
- the release-time narrow-terminal TUI spot-check; and
- release-manager sign-off for customer-specific proxy, CA, and endpoint policy.

Those items remain required for a future release and must be recorded with a
completed copy of [RELEASE_EVIDENCE.md](RELEASE_EVIDENCE.md). No score of 10 is
claimed from automated evidence alone.
