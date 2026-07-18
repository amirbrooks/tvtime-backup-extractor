from __future__ import annotations


class TVTimeError(Exception):
    """A user-actionable error that should not produce a traceback by default."""

    exit_code = 1


class UserInputError(TVTimeError):
    """Invalid or unsafe user input."""

    exit_code = 2


class PartialExtractionError(TVTimeError):
    """The extractor completed its inventory but one or more files failed."""

    exit_code = 3
