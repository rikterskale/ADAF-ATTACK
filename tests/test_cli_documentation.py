"""Keep the maintained CLI reference synchronized with Typer registration."""

from scripts.check_cli_documentation import validate


def test_cli_reference_covers_registered_commands() -> None:
    assert validate() == []
