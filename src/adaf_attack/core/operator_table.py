"""Shared adaptive tables and clipboard support for the operator CLI.

The JSON contract remains the source of truth for automation.  These helpers
only affect human-readable tables and deliberately use fixed subprocess
arguments for clipboard providers; no shell is involved.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from rich.table import Table


@dataclass(frozen=True)
class TableColumn:
    """Description of one adaptive operator-table column."""

    name: str
    min_width: int = 3
    max_width: int = 40
    justify: Literal["default", "left", "center", "right", "full"] = "left"
    style: str | None = None
    no_wrap: bool = False


def _display_width(value: Any) -> int:
    return max((len(line) for line in str(value).splitlines()), default=0)


def adaptive_widths(
    columns: Sequence[TableColumn], rows: Sequence[Sequence[Any]], *, width: int | None = None
) -> list[int]:
    """Allocate practical widths from terminal space and observed content.

    The first pass gives each column its content width.  If the table is wider
    than the terminal, flexible columns are reduced first while respecting a
    useful minimum.  ``--full`` callers can pass a larger explicit width or
    skip truncation in the table renderer.
    """
    terminal_width = width or shutil.get_terminal_size((120, 24)).columns
    natural = []
    for index, column in enumerate(columns):
        observed = max(
            [_display_width(column.name)]
            + [_display_width(row[index]) for row in rows if index < len(row)]
        )
        natural.append(min(column.max_width, max(column.min_width, observed)))

    separators = max(0, len(columns) - 1) * 3 + 2
    available = max(sum(column.min_width for column in columns), terminal_width - separators)
    widths = natural[:]
    while sum(widths) > available:
        candidates = [
            index for index, column in enumerate(columns) if widths[index] > column.min_width
        ]
        if not candidates:
            break
        index = max(candidates, key=lambda item: widths[item] - columns[item].min_width)
        widths[index] -= 1
    return widths


def adaptive_table(
    title: str,
    columns: Sequence[TableColumn],
    rows: Iterable[Sequence[Any]],
    *,
    full: bool = False,
    width: int | None = None,
) -> tuple[Table, list[list[str]]]:
    """Build a Rich table and its plain-text rows for clipboard support."""
    plain_rows = [[str(value) for value in row] for row in rows]
    widths = adaptive_widths(columns, plain_rows, width=width)
    table = Table(title=title, show_header=True, header_style="bold", expand=False)
    for column, column_width in zip(columns, widths, strict=True):
        table.add_column(
            column.name,
            width=column_width,
            max_width=None if full else column_width,
            justify=column.justify,
            style=column.style,
            no_wrap=column.no_wrap,
            overflow="fold" if full else "ellipsis",
        )
    for row in plain_rows:
        table.add_row(*row)
    return table, plain_rows


def table_text(columns: Sequence[TableColumn], rows: Sequence[Sequence[str]]) -> str:
    """Return a stable tab-separated representation suitable for copying."""
    header = [column.name for column in columns]
    return "\n".join("\t".join(row) for row in [header, *rows]) + "\n"


def copy_to_clipboard(value: str) -> dict[str, Any]:
    """Copy text using the first available platform clipboard provider."""
    candidates: list[list[str]]
    if os.name == "nt":
        candidates = [["clip"]]
    elif shutil.which("pbcopy"):
        candidates = [["pbcopy"]]
    else:
        candidates = [
            ["wl-copy"],
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
        ]

    for command in candidates:
        if shutil.which(command[0]) is None:
            continue
        try:
            subprocess.run(command, input=value, text=True, check=True, capture_output=True)
        except (OSError, subprocess.SubprocessError):
            continue
        return {"ok": True, "provider": command[0], "characters": len(value)}
    return {
        "ok": False,
        "provider": None,
        "characters": len(value),
        "reason": "No supported clipboard provider found (clip, pbcopy, wl-copy, xclip, or xsel).",
    }


__all__ = ["TableColumn", "adaptive_table", "adaptive_widths", "copy_to_clipboard", "table_text"]
