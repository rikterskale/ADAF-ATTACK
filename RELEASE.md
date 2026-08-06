# ADAF-ATTACK v0.10.0

## Tier A — close attack loops

- **pkinit-auth** — PKINIT TGT from shadow-cred key/cert (certipy when available; PFX + playbook always). Requires --force.
- **cert-request** — Real ESC1 enroll via certipy req; seeds template/CA from adcs-enum. Requires --force.
- **gmsa-laps-enum** — Secret read with --include-secrets (gMSA ManagedPassword blob parse + LAPS attrs).
- **gpo-sysvol** — SYSVOL reachability/write probe; optional stage with --force --gpo --payload.

## CLI

- --sam, --key, --cert, --pfx (pkinit)
- --gpo, --payload or @file (sysvol stage)

## Tests

56 unit tests (gMSA blob parser, PFX roundtrip, prior suite).
