"""Behavioral tests for adaptive human tables and clipboard handling."""

from __future__ import annotations

from typing import Any

from adaf_attack.core.operator_table import (
    TableColumn,
    adaptive_table,
    adaptive_widths,
    copy_to_clipboard,
    table_text,
)


def test_adaptive_widths_reduce_flexible_columns_to_terminal_width() -> None:
    columns = [
        TableColumn("ID", min_width=4, max_width=20),
        TableColumn("Summary", min_width=8, max_width=80),
    ]
    widths = adaptive_widths(columns, [["short", "a very long operator-facing summary"]], width=30)
    assert widths[0] >= 4
    assert widths[1] >= 8
    assert sum(widths) <= 25


def test_adaptive_table_and_clipboard_text_are_plain_and_stable() -> None:
    columns = [TableColumn("ID"), TableColumn("Risk")]
    table, rows = adaptive_table("Capabilities", columns, [["ldap-enum", "observe"]])
    assert table.title == "Capabilities"
    assert table_text(columns, rows) == "ID\tRisk\nldap-enum\tobserve\n"


def test_copy_to_clipboard_reports_missing_provider(monkeypatch: Any) -> None:
    monkeypatch.setattr("adaf_attack.core.operator_table.shutil.which", lambda _name: None)
    result = copy_to_clipboard("operator table")
    assert result["ok"] is False
    assert result["characters"] == len("operator table")
