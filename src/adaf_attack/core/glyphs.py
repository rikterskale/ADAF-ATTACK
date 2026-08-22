"""Unified, colorblind-friendly severity + status glyphs.

Every human-rendered CLI surface should reach for these instead of ad-hoc emoji
or color-only markers. Two rendering modes:

- ``rich`` (default): Rich markup with high-contrast, semantically-named colors
  (green/yellow/red are avoided as sole indicators - each glyph is also a
  distinct printable character).
- ``ascii``: colorless fallback for pipes, --no-color, and environments where
  Rich markup would leak into JSON output.

Adding a new status? Extend :data:`STATUS_GLYPHS` in one place and every
consumer picks it up.
"""

from __future__ import annotations

from typing import Literal

RenderMode = Literal["rich", "ascii"]

# Distinct printable characters so meaning survives without color.
STATUS_GLYPHS: dict[str, tuple[str, str, str]] = {
    # key: (label, ascii_glyph, rich_color)
    "ok": ("OK", "[+]", "green"),
    "warning": ("WARN", "[!]", "yellow"),
    "error": ("ERR", "[x]", "red"),
    "info": ("INFO", "[i]", "cyan"),
    "skipped": ("SKIP", "[-]", "dim"),
    "pending": ("PEND", "[?]", "magenta"),
}

SEVERITY_GLYPHS: dict[str, tuple[str, str, str]] = {
    "critical": ("CRITICAL", "[!!!]", "bright_red"),
    "high": ("HIGH", "[!!]", "red"),
    "medium": ("MEDIUM", "[!]", "yellow"),
    "low": ("LOW", "[.]", "blue"),
    "info": ("INFO", "[i]", "cyan"),
}


def render_status(key: str, *, mode: RenderMode = "rich") -> str:
    """Return a colored (rich) or plain (ascii) status marker."""
    label, ascii_glyph, color = STATUS_GLYPHS.get(
        key, (key.upper(), f"[{key[:3].upper()}]", "white")
    )
    if mode == "ascii":
        return f"{ascii_glyph} {label}"
    return f"[{color}]{ascii_glyph} {label}[/{color}]"


def render_severity(key: str, *, mode: RenderMode = "rich") -> str:
    """Return a colored or plain severity marker for findings."""
    label, ascii_glyph, color = SEVERITY_GLYPHS.get(
        key, (key.upper(), f"[{key[:1].upper()}]", "white")
    )
    if mode == "ascii":
        return f"{ascii_glyph} {label}"
    return f"[{color}]{ascii_glyph} {label}[/{color}]"


def status_keys() -> tuple[str, ...]:
    return tuple(STATUS_GLYPHS)


def severity_keys() -> tuple[str, ...]:
    return tuple(SEVERITY_GLYPHS)
