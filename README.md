# ADAF-ATTACK

**Aggressive Active Directory offensive toolkit for senior internal red teamers.**

ADAF-ATTACK is designed for experienced operators who already have authorization and operational judgment. It prioritizes speed and breadth over heavy safety gates.

> This tool is intended for authorized internal red team use only.

## Philosophy

- No plan-only mode
- No lab certification gates
- No containment / labAddressRanges checks
- Lightweight professional controls only:
  - `--force` required for destructive actions
  - Clear visual warnings
  - Secrets redacted by default (opt-in with `--include-secrets`)
  - Full session / workspace logging

## Status

Early scaffold. Capability surface and attack-path engine under active development.

## Quick Start (development)

```bash
python -m pip install -e ".[dev]"
adaf-attack --help
```

## Design Goals

- Single CLI covering the major AD attack surface
- Modular capability system (easy to extend)
- Native attack-path graph generation
- High-quality Textual TUI (planned)
- Clean result packaging and evidence handling
- Optional engagement metadata (logging only, never enforced)

## Relationship to ADAF-RedTeam

| Aspect              | ADAF-RedTeam              | ADAF-ATTACK                          |
|---------------------|---------------------------|--------------------------------------|
| Primary use         | Controlled validation     | Aggressive internal red team ops     |
| Plan-only           | Default                   | None                                 |
| Lab certification   | Required                  | None                                 |
| Containment checks  | Hard gate                 | None                                 |
| Destructive actions | Heavily gated             | `--force` + warning                  |
| Secrets             | Always redacted           | Redacted by default, opt-in override |

## License

Private. Internal use only.
