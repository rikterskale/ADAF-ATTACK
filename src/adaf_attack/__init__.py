"""ADAF-ATTACK — Aggressive AD offensive toolkit for senior internal red teamers."""

__version__ = "0.10.1"

# Small, dependency-light public API for offline evidence enrichment.  The CLI
# and capability registry remain available through their existing modules.
from adaf_attack.core.command_templates import (
    build_exploit_commands,
    emit_ranked_paths,
)
from adaf_attack.core.ux_extra import (
    format_next_actions_block,
    format_stages_progress,
)

__all__ = [
    "__version__",
    "build_exploit_commands",
    "emit_ranked_paths",
    "format_next_actions_block",
    "format_stages_progress",
]
