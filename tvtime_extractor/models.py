from __future__ import annotations

import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import RecoveryCancelled, UserInputError
from .extract import (
    BackupFileSnapshot,
    BackupPreflightSnapshot,
    ExtractionResult,
    public_summary,
)

BACKUP_PREFLIGHT_RECEIPT_SCHEMA_VERSION = 1
BACKUP_PREFLIGHT_RECEIPT_CONTRACT = "tvtime-backup-preflight-receipt-v0.2"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAXIMUM_RECEIPT_INTEGER = (1 << 63) - 1
_MAXIMUM_RECEIPT_UNSIGNED_INTEGER = (1 << 64) - 1


class RecoveryStage(str, Enum):
    PREFLIGHT = "preflight"
    EXTRACTION = "extraction"
    ANALYSIS = "analysis"
    REPORT = "report"
    COMPLETE = "complete"


class RecoveryEventKind(str, Enum):
    STARTED = "started"
    PROGRESS = "progress"
    COMPLETED = "completed"


@dataclass(frozen=True)
class RecoveryEvent:
    stage: RecoveryStage
    kind: RecoveryEventKind
    message: str
    current: int | None = None
    total: int | None = None
    details: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "stage": self.stage.value,
            "kind": self.kind.value,
            "message": self.message,
        }
        if self.current is not None:
            value["current"] = self.current
        if self.total is not None:
            value["total"] = self.total
        if self.details:
            value["details"] = self.details
        return value


ProgressCallback = Callable[[RecoveryEvent], None]


class CancellationToken:
    """Thread-safe cooperative cancellation checked at safe stage boundaries."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._state = "active"
        self._cause: BaseException | None = None
        self._signal_pending = False

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self, cause: BaseException | None = None) -> bool:
        with self._lock:
            if self._state != "active":
                return False
            self._state = "cancelled"
            self._cause = cause
            self._event.set()
            return True

    def mark_signal_pending(self) -> None:
        """Record a signal without taking a lock inside Python's signal handler."""

        self._signal_pending = True

    def _apply_pending_signal_locked(self) -> None:
        if not self._signal_pending:
            return
        self._signal_pending = False
        if self._state == "active":
            self._state = "cancelled"
            self._cause = None
            self._event.set()

    def seal_for_commit(self) -> bool:
        """Atomically let cancellation or the final directory commit win, never both."""

        with self._lock:
            self._apply_pending_signal_locked()
            if self._state == "cancelled":
                return False
            if self._state == "active":
                self._state = "sealed"
            return self._state in {"sealed", "finished"}

    def try_finish(self) -> bool:
        """Atomically make success terminal unless cancellation won the race."""

        with self._lock:
            self._apply_pending_signal_locked()
            if self._state == "cancelled":
                return False
            if self._state == "finished":
                return True
            self._state = "finished"
            return True

    def raise_if_cancelled(self) -> None:
        with self._lock:
            self._apply_pending_signal_locked()
            cancelled = self._state == "cancelled"
            cause = self._cause
        if not cancelled:
            return
        if cause is not None:
            raise cause
        raise RecoveryCancelled(
            "Recovery was cancelled. Any output without a complete run marker must not be "
            "analyzed; start again with a new destination."
        )


@dataclass(frozen=True)
class DestinationDirectoryIdentity:
    """Stable directory identity: POSIX device/inode or Windows volume/file index."""

    device: int
    inode: int

    @classmethod
    def from_dict(cls, value: object) -> DestinationDirectoryIdentity:
        if not isinstance(value, dict) or set(value) != {"device", "inode"}:
            raise UserInputError("The destination directory identity was malformed.")
        device = value.get("device")
        inode = value.get("inode")
        maximum = (1 << 64) - 1
        if any(
            isinstance(candidate, bool)
            or not isinstance(candidate, int)
            or candidate < 0
            or candidate > maximum
            for candidate in (device, inode)
        ):
            raise UserInputError("The destination directory identity was malformed.")
        return cls(device=device, inode=inode)


def _receipt_integer(value: object, *, unsigned: bool = False) -> int:
    maximum = _MAXIMUM_RECEIPT_UNSIGNED_INTEGER if unsigned else _MAXIMUM_RECEIPT_INTEGER
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        raise UserInputError("The backup preflight receipt was malformed.")
    return value


def _backup_file_snapshot_from_receipt(value: object) -> BackupFileSnapshot:
    fields = {
        "mode",
        "size",
        "modified_ns",
        "changed_ns",
        "device",
        "inode",
        "sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise UserInputError("The backup preflight receipt was malformed.")
    sha256 = value.get("sha256")
    if not isinstance(sha256, str) or _SHA256_PATTERN.fullmatch(sha256) is None:
        raise UserInputError("The backup preflight receipt was malformed.")
    return BackupFileSnapshot(
        mode=_receipt_integer(value.get("mode"), unsigned=True),
        size=_receipt_integer(value.get("size")),
        modified_ns=_receipt_integer(value.get("modified_ns")),
        changed_ns=_receipt_integer(value.get("changed_ns")),
        device=_receipt_integer(value.get("device"), unsigned=True),
        inode=_receipt_integer(value.get("inode"), unsigned=True),
        sha256=sha256,
    )


def _backup_file_snapshot_receipt(value: BackupFileSnapshot) -> dict[str, object]:
    return {
        "mode": value.mode,
        "size": value.size,
        "modified_ns": value.modified_ns,
        "changed_ns": value.changed_ns,
        "device": value.device,
        "inode": value.inode,
        "sha256": value.sha256,
    }


@dataclass(frozen=True)
class BackupPreflightReceipt:
    """Strict source identity/content receipt carried between native helper processes."""

    snapshot: BackupPreflightSnapshot
    backup_regular_files: int
    backup_logical_bytes: int

    @classmethod
    def from_dict(cls, value: object) -> BackupPreflightReceipt:
        fields = {
            "schema_version",
            "contract",
            "root_device",
            "root_inode",
            "backup_regular_files",
            "backup_logical_bytes",
            "manifest_plist",
            "manifest_database",
            "status_plist",
        }
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or value.get("schema_version") != BACKUP_PREFLIGHT_RECEIPT_SCHEMA_VERSION
            or value.get("contract") != BACKUP_PREFLIGHT_RECEIPT_CONTRACT
        ):
            raise UserInputError("The backup preflight receipt was malformed.")
        return cls(
            snapshot=BackupPreflightSnapshot(
                root_device=_receipt_integer(value.get("root_device"), unsigned=True),
                root_inode=_receipt_integer(value.get("root_inode"), unsigned=True),
                manifest_plist=_backup_file_snapshot_from_receipt(value.get("manifest_plist")),
                manifest_database=_backup_file_snapshot_from_receipt(
                    value.get("manifest_database")
                ),
                status_plist=_backup_file_snapshot_from_receipt(value.get("status_plist")),
            ),
            backup_regular_files=_receipt_integer(value.get("backup_regular_files")),
            backup_logical_bytes=_receipt_integer(value.get("backup_logical_bytes")),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": BACKUP_PREFLIGHT_RECEIPT_SCHEMA_VERSION,
            "contract": BACKUP_PREFLIGHT_RECEIPT_CONTRACT,
            "root_device": self.snapshot.root_device,
            "root_inode": self.snapshot.root_inode,
            "backup_regular_files": self.backup_regular_files,
            "backup_logical_bytes": self.backup_logical_bytes,
            "manifest_plist": _backup_file_snapshot_receipt(self.snapshot.manifest_plist),
            "manifest_database": _backup_file_snapshot_receipt(self.snapshot.manifest_database),
            "status_plist": _backup_file_snapshot_receipt(self.snapshot.status_plist),
        }

    def matches(
        self,
        *,
        snapshot: BackupPreflightSnapshot,
        backup_regular_files: int,
        backup_logical_bytes: int,
    ) -> bool:
        return (
            self.snapshot == snapshot
            and self.backup_regular_files == backup_regular_files
            and self.backup_logical_bytes == backup_logical_bytes
        )


@dataclass(frozen=True)
class RecoveryRequest:
    backup_directory: Path
    output_directory: Path
    acknowledge_sensitive_output: bool = False
    include_raw_cache: bool = False
    include_decrypted_manifest: bool = False
    destination_parent_identity: DestinationDirectoryIdentity | None = None
    backup_receipt: BackupPreflightReceipt | None = None

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> RecoveryRequest:
        expected_fields = {
            "backup_directory",
            "output_directory",
            "destination_parent_identity",
            "acknowledge_sensitive_output",
            "include_raw_cache",
            "include_decrypted_manifest",
            "backup_receipt",
        }
        if set(value) != expected_fields:
            raise UserInputError("The recovery request did not match the required fields.")
        backup = value.get("backup_directory")
        output = value.get("output_directory")
        if not isinstance(backup, str) or not backup:
            raise UserInputError("A backup directory is required.")
        if not isinstance(output, str) or not output:
            raise UserInputError("A fresh destination directory is required.")
        option_names = (
            "acknowledge_sensitive_output",
            "include_raw_cache",
            "include_decrypted_manifest",
        )
        if any(name in value and not isinstance(value[name], bool) for name in option_names):
            raise UserInputError("Recovery option values must be true or false.")
        return cls(
            backup_directory=Path(backup),
            output_directory=Path(output),
            acknowledge_sensitive_output=value.get("acknowledge_sensitive_output") is True,
            include_raw_cache=value.get("include_raw_cache") is True,
            include_decrypted_manifest=value.get("include_decrypted_manifest") is True,
            destination_parent_identity=DestinationDirectoryIdentity.from_dict(
                value.get("destination_parent_identity")
            ),
            backup_receipt=(
                None
                if value.get("backup_receipt") is None
                else BackupPreflightReceipt.from_dict(value.get("backup_receipt"))
            ),
        )


@dataclass(frozen=True)
class PreflightResult:
    encrypted: bool
    snapshot_state: str
    backup_date: str
    backup_regular_files: int
    backup_logical_bytes: int
    manifest_database_bytes: int
    destination_free_bytes: int
    minimum_working_bytes: int
    warnings: tuple[str, ...] = ()

    @property
    def has_minimum_space(self) -> bool:
        return self.destination_free_bytes >= self.minimum_working_bytes

    def as_dict(self) -> dict[str, object]:
        return {
            "encrypted": self.encrypted,
            "snapshot_state": self.snapshot_state,
            "backup_date": self.backup_date,
            "backup_regular_files": self.backup_regular_files,
            "backup_logical_bytes": self.backup_logical_bytes,
            "manifest_database_bytes": self.manifest_database_bytes,
            "destination_free_bytes": self.destination_free_bytes,
            "minimum_working_bytes": self.minimum_working_bytes,
            "has_minimum_space": self.has_minimum_space,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class RecoveryResult:
    preflight: PreflightResult
    extraction: ExtractionResult
    analysis: dict[str, Any]
    report: dict[str, Any]

    def as_cli_dict(self) -> dict[str, object]:
        """Return a CLI-only result that deliberately includes local result paths."""

        return {
            "preflight": self.preflight.as_dict(),
            "extraction": public_summary(self.extraction),
            "analysis": self.analysis,
            "report": self.report,
        }
