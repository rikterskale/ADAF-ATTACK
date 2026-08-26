# Standout operator UX

The standout UX layer is evidence-first and works equally from the CLI and TUI:

- `guide` is the single authoritative next-step command; CLI and TUI share
  `core.journey.snapshot()` so the same copy-ready command appears everywhere.
- `cockpit` combines findings, graph paths, priority focus, and explainability.
- `what-if` simulates graph evidence changes in a temporary file and never changes the source graph or contacts a target.
- `timeline` normalizes the append-only audit log into a replayable sequence.
- `copilot` produces explainable suggestions only; it does not execute commands.
- `collaboration` summarizes finding owners, notes, comments, tags, and status.
- Existing report, evidence-package, AD CS validation, and CLI/TUI parity workflows remain the execution and delivery surfaces.

The live safety-governor concept was intentionally not added in this iteration, per request. Existing authorization, force, engagement, and rollback safeguards remain unchanged. `guide --advance` only completes safe offline bookkeeping steps and never bypasses `--force`, approval tokens, or review gates.
