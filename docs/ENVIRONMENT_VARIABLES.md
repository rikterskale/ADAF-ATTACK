# Environment variables

Complete reference for all `ADAF_*` environment variables recognized by
ADAF-ATTACK. Variables are grouped by subsystem.

## Paths and workspace

| Variable | Default | Description |
|----------|---------|-------------|
| `ADAF_ATTACK_DATA_DIR` | `~/.local/share/adaf-attack` (Linux/macOS) · `%LOCALAPPDATA%\adaf-attack` (Windows) | Override the application data root (workspaces, sessions, SQLite index). |
| `ADAF_ATTACK_CONFIG_DIR` | XDG `~/.config/adaf-attack` (Linux) · platform equivalent | Override the configuration directory (preferences, saved defaults). |
| `ADAF_ATTACK_WORKSPACE` | `<data_dir>/workspaces` | Override the default workspace directory. Equivalent to `--workspace` on the CLI. |

## Vault and credentials

| Variable | Default | Description |
|----------|---------|-------------|
| `ADAF_SESSION_VAULT_KEY` | *(none — required for secret storage)* | Fernet key used to encrypt/decrypt secret material in the session vault. Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Never written to disk by ADAF-ATTACK. |

## Approval and authorization

| Variable | Default | Description |
|----------|---------|-------------|
| `ADAF_APPROVAL_HMAC_KEY` | *(none — required for approval verification)* | Shared HMAC-SHA256 key used to sign and verify scoped approval tokens. Required whenever a capability's `ApprovalPolicy` is `SCOPED_TOKEN` or when running engagement plans with side-effect/destructive phases. |
| `ADAF_APPROVAL_TOKEN` | *(none)* | Pre-set approval token passed to the CLI instead of the `--approval-token` flag. Useful in scripted pipelines where the token is injected from a secret store. |

## Environment and safety

| Variable | Default | Description |
|----------|---------|-------------|
| `ADAF_ATTACK_ENV` | *(empty)* | When set to `prod` or `production`, the built-in HMAC approval verifier is blocked. This forces operators to either deploy an asymmetric JWKS verifier or explicitly acknowledge the shared-secret risk. |
| `ADAF_APPROVAL_HMAC_ACKNOWLEDGE_PROD` | *(empty)* | Set to `1`, `true`, or `yes` to explicitly accept the built-in HMAC verifier when `ADAF_ATTACK_ENV=prod`. This is a deliberate opt-in for environments that have not yet migrated to JWKS. |

## Container and platform

| Variable | Default | Description |
|----------|---------|-------------|
| `ADAF_ATTACK_IN_CONTAINER` | *(empty)* | Set to `1` by the Dockerfile. When detected, the CLI warns that live AD/Kerberos workflows require host network integration and are not supported inside the container image. |
| `ADAF_ATTACK_CONTAINER_ACKNOWLEDGE_LIVE` | *(empty)* | Set to `1`, `true`, or `yes` to suppress the container live-AD warning. Use only when the container has been configured with host networking, DNS, and clock synchronization. |

## Release and CI

| Variable | Default | Description |
|----------|---------|-------------|
| `ADAF_RELEASE_PROVENANCE_KEY` | *(none)* | Signing key used by the release pipeline to generate provenance attestations in `release-manifest.json`. Not used at runtime. |
