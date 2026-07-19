from __future__ import annotations

import errno
from enum import Enum


class ErrorCode(str, Enum):
    RECOVERY_FAILED = "recovery_failed"
    INVALID_INPUT = "invalid_input"
    INSUFFICIENT_SPACE = "insufficient_space"
    OUTPUT_EXISTS = "output_exists"
    UNSAFE_PATH = "unsafe_path"
    BACKUP_UNENCRYPTED = "backup_unencrypted"
    BACKUP_UNFINISHED = "backup_unfinished"
    APP_DATA_MISSING = "app_data_missing"
    SOURCE_CHANGED = "source_changed"
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    BACKUP_PASSWORD_REJECTED = "backup_password_rejected"
    PARTIAL_EXTRACTION = "partial_extraction"
    CANCELLED = "cancelled"


class TVTimeError(Exception):
    """A user-actionable error that should not produce a traceback by default."""

    exit_code = 1
    error_code = ErrorCode.RECOVERY_FAILED


class UserInputError(TVTimeError):
    """Invalid or unsafe user input."""

    exit_code = 2
    error_code = ErrorCode.INVALID_INPUT


class InsufficientSpaceError(TVTimeError):
    """The selected destination ran out of usable working space."""

    error_code = ErrorCode.INSUFFICIENT_SPACE


class OutputExistsError(UserInputError):
    """A fresh-output invariant would be violated."""

    error_code = ErrorCode.OUTPUT_EXISTS


class UnsafePathError(UserInputError):
    """A selected or derived filesystem path failed a safety check."""

    error_code = ErrorCode.UNSAFE_PATH


class BackupUnencryptedError(UserInputError):
    """The selected backup was not confirmed as encrypted."""

    error_code = ErrorCode.BACKUP_UNENCRYPTED


class BackupUnfinishedError(UserInputError):
    """The selected backup was not explicitly marked finished."""

    error_code = ErrorCode.BACKUP_UNFINISHED


class AppDataMissingError(UserInputError):
    """The selected backup did not contain the required TV Time data."""

    error_code = ErrorCode.APP_DATA_MISSING


class SourceChangedError(TVTimeError):
    """The source backup changed after its extraction snapshot was recorded."""

    error_code = ErrorCode.SOURCE_CHANGED


class UnsupportedSchemaError(TVTimeError):
    """Recovered TV Time data used a schema this release cannot interpret safely."""

    error_code = ErrorCode.UNSUPPORTED_SCHEMA


class PartialExtractionError(TVTimeError):
    """The extractor completed its inventory but one or more files failed."""

    exit_code = 3
    error_code = ErrorCode.PARTIAL_EXTRACTION

    def __init__(self, message: str, *, extraction_result: object | None = None) -> None:
        super().__init__(message)
        self.extraction_result = extraction_result


class BackupPasswordError(TVTimeError):
    """The encrypted backup could not be unlocked with the supplied password."""

    error_code = ErrorCode.BACKUP_PASSWORD_REJECTED


class RecoveryCancelled(TVTimeError):
    """The user cancelled a recovery before its completion checkpoint."""

    exit_code = 130
    error_code = ErrorCode.CANCELLED


_SPACE_ERRNOS = frozenset(
    value
    for value in (
        errno.ENOSPC,
        getattr(errno, "EDQUOT", None),
    )
    if value is not None
)


def is_insufficient_space_error(error: BaseException) -> bool:
    """Return whether an OS failure means the destination cannot accept more data."""

    return isinstance(error, OSError) and error.errno in _SPACE_ERRNOS


def insufficient_space_error() -> InsufficientSpaceError:
    """Create the path-free, user-actionable storage error used by every entry point."""

    return InsufficientSpaceError(
        "The destination ran out of free space while writing private recovery data. Preserve the "
        "incomplete output and retry with a fresh folder on a volume with more available space."
    )
