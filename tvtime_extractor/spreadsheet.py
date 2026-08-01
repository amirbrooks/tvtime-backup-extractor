from __future__ import annotations

from typing import Any

SPREADSHEET_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def spreadsheet_cell_needs_escape(value: object) -> bool:
    return isinstance(value, str) and value.startswith(SPREADSHEET_FORMULA_PREFIXES)


def spreadsheet_safe_cell(value: Any) -> Any:
    """Neutralize text that spreadsheet applications could evaluate as a formula."""

    if spreadsheet_cell_needs_escape(value):
        return f"'{value}"
    return value
