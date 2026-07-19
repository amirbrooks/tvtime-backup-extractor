from __future__ import annotations

import unicodedata

_PRESERVED_JOINERS = frozenset({"\u200c", "\u200d"})


def _has_visible_base(text: str) -> bool:
    """Return whether text contains a glyph-bearing character, not only marks/formatting."""

    for character in text:
        category = unicodedata.category(character)
        if category[0] not in {"C", "M", "Z"}:
            return True
    return False


def normalize_display_text(value: object, *, fallback: str = "") -> str:
    """Normalize recovered text exactly as the human-readable reports display it."""

    text = str(value or "")
    text = "".join(
        " "
        if (
            unicodedata.category(character) == "Cc"
            or (unicodedata.category(character) == "Cf" and character not in _PRESERVED_JOINERS)
        )
        else character
        for character in text
    )
    normalized = " ".join(text.split())
    return normalized if normalized and _has_visible_base(normalized) else fallback


def has_display_text(value: object) -> bool:
    """Return whether recovered text remains visible after display normalization."""

    return bool(normalize_display_text(value))
