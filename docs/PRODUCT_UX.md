# Product surfaces

The product layer turns saved evidence into polished operator and client workflows:

- `guide` is the authoritative next-step command for the full operator journey
  (install → offline first success → authorize → operate → report → closeout).
  CLI and TUI share `core.journey.snapshot()`. `tour` and `home` orient against
  the default workspace only; custom workspaces use `guide --workspace …`.
- `command-center` is the mission-control view.
- `impact-map` connects evidence to findings, assets, and impact.
- `investigate` provides zero-noise, read-only evidence review.
- `story` builds an executive narrative.
- `replay` presents a session as a reviewable timeline.
- `confidence` identifies conclusions that need more evidence.
- `product-templates` lists repeatable assessment patterns.
- `deliverables` shows report and evidence-package readiness.

The finding-driven `workflow` command group remains the durable spine for
scoping through closure; `guide` and `workflow next` emit the same copy-ready
`suggested_command` and redacted `evidence_basis` for the current top action.
CLI and TUI render that document through the same journey summary composer.

This iteration intentionally excludes collaborative finding rooms (#6) and operator workspace profiles (#10); existing triage and configuration behavior is unchanged.

See the [UX acceptance matrix](UX_ACCEPTANCE_MATRIX.md) for the complete
checklist, CLI/TUI mapping, and release verification steps.
