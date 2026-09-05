"""Argv helpers so global CLI flags work after the subcommand."""

from __future__ import annotations

_VALUE_FLAGS = {"--format"}
_BOOL_FLAGS = {"--no-color", "--non-interactive", "--debug", "--version", "-V"}


def hoist_global_options(args: list[str]) -> list[str]:
    """Move root flags in front of the subcommand (``run x --format json``)."""
    extracted: list[str] = []
    rest: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token in _VALUE_FLAGS and index + 1 < len(args) and not args[index + 1].startswith("-"):
            extracted.extend([token, args[index + 1]])
            index += 2
            continue
        if token.startswith("--format="):
            extracted.append(token)
            index += 1
            continue
        if token in _BOOL_FLAGS:
            extracted.append(token)
            index += 1
            continue
        rest.append(token)
        index += 1
    return extracted + rest
