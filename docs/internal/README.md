# Internal engineering documentation

These documents support maintainers and release reviewers rather than the
single-operator workflow:

- [Release readiness](../RELEASE_READINESS.md)
- [Product UX](../PRODUCT_UX.md)
- [Standout UX](../STANDOUT_UX.md)
- [UX acceptance matrix](../UX_ACCEPTANCE_MATRIX.md)

The files remain at their established paths because CI contract validators and
release tooling intentionally reference those stable locations. The
[operator runbook](../RUNBOOK.md) and platform guides are the supported daily
operator surface.

## Architecture and reference documentation

- [Architecture](../ARCHITECTURE.md) — component boundaries, data flow, trust model
- [Environment variables](../ENVIRONMENT_VARIABLES.md) — complete `ADAF_*` variable reference
- [Session data model](../SESSION_DATA_MODEL.md) — session directory layout and schemas
- [Engagement and campaign schema](../ENGAGEMENT_SCHEMA.md) — YAML schema for plans and campaigns
- [Approval tokens](../APPROVAL_TOKENS.md) — token format, generation, and production deployment
- [Vault operations](../VAULT_OPERATIONS.md) — key management, operations, threat model
- [Rollback matrix](../ROLLBACK_MATRIX.md) — what each destructive capability reverts
- [Plugin authoring](../PLUGIN_AUTHORING.md) — entry-point extension contract
- [Engineering foundations](../ENGINEERING.md) — Pydantic contracts, SessionStore, execution controls
