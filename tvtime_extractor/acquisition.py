from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import secrets
import sqlite3
import stat
import tarfile
import zipfile
import zlib
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from .analyze import analyze_extraction
from .errors import (
    AppDataMissingError,
    BackupPasswordError,
    PartialExtractionError,
    SourceChangedError,
    TVTimeError,
    UnsafePathError,
    UnsupportedSchemaError,
    UserInputError,
    insufficient_space_error,
    is_insufficient_space_error,
)
from .extract import PRIMARY_DOMAIN, ExtractionResult
from .integrity import reconcile_raw_tree
from .report import build_report
from .safety import (
    EXTRACTION_DIRECTORY_NAME,
    EXTRACTION_RUN_STATE_CONTRACT,
    EXTRACTION_RUN_STATE_SCHEMA_VERSION,
    anchored_bound_output_root,
    harden_private_descriptor,
    held_destination_parent,
    is_within,
    nearest_git_root,
    no_link_absolute_path,
    regular_binary_reader,
    require_bound_destination_parent,
    require_private_local_destination,
    safe_join,
    secure_directory,
    secure_file,
    write_csv_private,
    write_json_private_atomic,
    write_text_private,
)

ANDROID_PACKAGE_NAME = "com.tozelabs.tvshowtime"
ANDROID_BACKUP_MAGIC = b"ANDROID BACKUP\n"
ANDROID_BACKUP_MAXIMUM_HEADER_BYTES = 16 * 1024
ANDROID_BACKUP_MAXIMUM_UNPACKED_BYTES = 8 * 1024 * 1024 * 1024
ANDROID_DATABASE_MAXIMUM_BYTES = 768 * 1024 * 1024
ANDROID_ARCHIVE_MAXIMUM_MEMBERS = 250_000
OFFICIAL_EXPORT_MAXIMUM_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
OFFICIAL_EXPORT_MAXIMUM_CSV_BYTES = 128 * 1024 * 1024
OFFICIAL_EXPORT_MAXIMUM_TOTAL_BYTES = 256 * 1024 * 1024
OFFICIAL_EXPORT_MAXIMUM_ROWS = 100_000
OFFICIAL_EXPORT_MAXIMUM_CELL_BYTES = 8 * 1024 * 1024
OFFICIAL_EXPORT_FILENAMES = frozenset({"tracking-prod-records.csv", "tracking-prod-records-v2.csv"})

_ANDROID_DATABASE_TARGETS = {
    "apps/com.tozelabs.tvshowtime/db/DioCache.db": (
        PRIMARY_DOMAIN,
        "Documents",
        "DioCache.db",
    ),
    "apps/com.tozelabs.tvshowtime/db/libCachedImageData.db": (
        PRIMARY_DOMAIN,
        "Library",
        "Application Support",
        "libCachedImageData.db",
    ),
}
_ANDROID_DATABASE_BASE_TARGETS = dict(_ANDROID_DATABASE_TARGETS)
for _database_source, _database_target in tuple(_ANDROID_DATABASE_BASE_TARGETS.items()):
    for _sidecar_suffix in ("-wal", "-shm", "-journal"):
        _ANDROID_DATABASE_TARGETS[f"{_database_source}{_sidecar_suffix}"] = (
            *_database_target[:-1],
            f"{_database_target[-1]}{_sidecar_suffix}",
        )
_ANDROID_SNAPSHOT_TARGETS = {target[-1]: target for target in _ANDROID_DATABASE_TARGETS.values()}
_ANDROID_SNAPSHOT_CANDIDATES = {
    filename: (("db", filename), ("databases", filename), (filename,))
    for filename in _ANDROID_SNAPSHOT_TARGETS
}


class RecoverySourceKind(str, Enum):
    IOS_ENCRYPTED_BACKUP = "ios_encrypted_backup"
    ANDROID_LEGACY_BACKUP = "android_legacy_backup"
    ANDROID_PRESERVED_SNAPSHOT = "android_preserved_snapshot"
    TVTIME_OFFICIAL_EXPORT = "tvtime_official_export"


class AndroidBackupEncryption(str, Enum):
    NONE = "none"
    AES_256 = "AES-256"


SourceIdentity = tuple[int, int]
SourceFileReceipt = tuple[str, int, str, SourceIdentity]


@dataclass(frozen=True)
class AndroidBackupHeader:
    version: int
    compressed: bool
    encryption: AndroidBackupEncryption
    payload_offset: int
    vendor_prefix_lines: int = 0


@dataclass(frozen=True)
class AcquisitionPreflight:
    source_kind: RecoverySourceKind
    source_bytes: int
    source_sha256: str
    android_backup_version: int | None = None
    compressed: bool | None = None
    encrypted: bool | None = None
    warnings: tuple[str, ...] = ()
    source_identity: SourceIdentity | None = None
    source_files: tuple[SourceFileReceipt, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "source_kind": self.source_kind.value,
            "android_backup_version": self.android_backup_version,
            "compressed": self.compressed,
            "encrypted": self.encrypted,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class AcquiredRecoveryResult:
    source_preflight: AcquisitionPreflight
    extraction: ExtractionResult
    analysis: dict[str, Any]
    report: dict[str, Any]


def _source_file_snapshot(
    path: Path,
    *,
    cancellation_check: Callable[[], None] | None = None,
    allow_empty: bool = False,
) -> tuple[int, str, SourceIdentity]:
    digest = hashlib.sha256()
    byte_count = 0
    with regular_binary_reader(path, require_private=False) as (handle, opened):
        if (
            (opened.st_size <= 0 and not allow_empty)
            or opened.st_size < 0
            or opened.st_size > ANDROID_BACKUP_MAXIMUM_UNPACKED_BYTES
        ):
            raise UserInputError("The selected Android source had an unsafe byte size.")
        while True:
            if cancellation_check is not None:
                cancellation_check()
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            byte_count += len(chunk)
            if byte_count > ANDROID_BACKUP_MAXIMUM_UNPACKED_BYTES:
                raise UserInputError("The selected Android source had an unsafe byte size.")
            digest.update(chunk)
    if byte_count != opened.st_size:
        raise SourceChangedError("The selected Android source changed while it was inspected.")
    return byte_count, digest.hexdigest(), (int(opened.st_dev), int(opened.st_ino))


def _require_source_identity(metadata: os.stat_result, expected: SourceIdentity | None) -> None:
    if expected is not None and (int(metadata.st_dev), int(metadata.st_ino)) != expected:
        raise SourceChangedError("The selected source identity changed during acquisition.")


def _parse_ascii_header_line(payload: bytes, start: int) -> tuple[bytes, int]:
    end = payload.find(b"\n", start)
    if end < 0:
        raise UserInputError("The Android backup header was incomplete.")
    line = payload[start:end]
    if not line or any(byte < 0x20 or byte > 0x7E for byte in line):
        raise UserInputError("The Android backup header was malformed.")
    return line, end + 1


def _android_magic_offset(payload: bytes) -> tuple[int, int]:
    if payload.startswith(ANDROID_BACKUP_MAGIC):
        return 0, 0
    # Some vendor-local backups prepend a short text envelope. Accept only a
    # line-aligned Android header within five bounded ASCII lines; arbitrary
    # scanning could misclassify unrelated or attacker-controlled files.
    cursor = 0
    for line_count in range(1, 6):
        _line, cursor = _parse_ascii_header_line(payload, cursor)
        if payload.startswith(ANDROID_BACKUP_MAGIC, cursor):
            return cursor, line_count
    raise UserInputError("The selected file was not a supported Android backup container.")


def parse_android_backup_header(payload: bytes) -> AndroidBackupHeader:
    if not payload or len(payload) > ANDROID_BACKUP_MAXIMUM_HEADER_BYTES:
        raise UserInputError("The Android backup header had an unsafe byte size.")
    magic_offset, vendor_prefix_lines = _android_magic_offset(payload)
    cursor = magic_offset + len(ANDROID_BACKUP_MAGIC)
    version_line, cursor = _parse_ascii_header_line(payload, cursor)
    compressed_line, cursor = _parse_ascii_header_line(payload, cursor)
    encryption_line, cursor = _parse_ascii_header_line(payload, cursor)
    try:
        version = int(version_line.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise UserInputError("The Android backup version was malformed.") from exc
    if version < 1 or version > 5:
        raise UnsupportedSchemaError("This Android backup version is not supported safely.")
    if compressed_line not in {b"0", b"1"}:
        raise UserInputError("The Android backup compression flag was malformed.")
    try:
        encryption = AndroidBackupEncryption(encryption_line.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise UnsupportedSchemaError(
            "This Android backup encryption method is not supported safely."
        ) from exc
    return AndroidBackupHeader(
        version=version,
        compressed=compressed_line == b"1",
        encryption=encryption,
        payload_offset=cursor,
        vendor_prefix_lines=vendor_prefix_lines,
    )


def inspect_android_backup(
    source: Path,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> AcquisitionPreflight:
    source = no_link_absolute_path(source)
    byte_count, digest, identity = _source_file_snapshot(
        source,
        cancellation_check=cancellation_check,
    )
    with regular_binary_reader(source, require_private=False) as (handle, metadata):
        _require_source_identity(metadata, identity)
        header_bytes = handle.read(ANDROID_BACKUP_MAXIMUM_HEADER_BYTES)
    return _android_backup_preflight(
        header_bytes=header_bytes,
        byte_count=byte_count,
        digest=digest,
        identity=identity,
    )


def _android_backup_preflight(
    *,
    header_bytes: bytes,
    byte_count: int,
    digest: str,
    identity: SourceIdentity,
) -> AcquisitionPreflight:
    header = parse_android_backup_header(header_bytes)
    warnings: tuple[str, ...] = ()
    if header.vendor_prefix_lines:
        warnings = ("vendor_backup_envelope_detected",)
    if header.encryption is not AndroidBackupEncryption.NONE:
        raise UnsupportedSchemaError(
            "Encrypted Android backup containers are not enabled until their key-derivation "
            "and integrity contract can be validated against synthetic cross-platform vectors."
        )
    return AcquisitionPreflight(
        source_kind=RecoverySourceKind.ANDROID_LEGACY_BACKUP,
        source_bytes=byte_count,
        source_sha256=digest,
        source_identity=identity,
        android_backup_version=header.version,
        compressed=header.compressed,
        encrypted=False,
        warnings=warnings,
    )


def inspect_android_backup_descriptor(
    descriptor: int,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> AcquisitionPreflight:
    """Inspect a captured Android archive through its already-held file identity."""

    try:
        original_offset = os.lseek(descriptor, 0, os.SEEK_CUR)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= ANDROID_BACKUP_MAXIMUM_UNPACKED_BYTES
        ):
            raise UserInputError("The selected Android source had an unsafe byte size.")
        os.lseek(descriptor, 0, os.SEEK_SET)
        duplicate = os.dup(descriptor)
        digest = hashlib.sha256()
        byte_count = 0
        header_bytes = b""
        with os.fdopen(duplicate, "rb", buffering=0) as handle:
            while True:
                if cancellation_check is not None:
                    cancellation_check()
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                if len(header_bytes) < ANDROID_BACKUP_MAXIMUM_HEADER_BYTES:
                    remaining = ANDROID_BACKUP_MAXIMUM_HEADER_BYTES - len(header_bytes)
                    header_bytes += chunk[:remaining]
                byte_count += len(chunk)
                if byte_count > ANDROID_BACKUP_MAXIMUM_UNPACKED_BYTES:
                    raise UserInputError("The selected Android source had an unsafe byte size.")
                digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise UnsafePathError("The captured Android backup could not be inspected safely.") from exc
    finally:
        with suppress(OSError, UnboundLocalError):
            os.lseek(descriptor, original_offset, os.SEEK_SET)
    if byte_count != before.st_size or any(
        getattr(before, field, None) != getattr(after, field, None)
        for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    ):
        raise SourceChangedError("The captured Android backup changed while it was inspected.")
    return _android_backup_preflight(
        header_bytes=header_bytes,
        byte_count=byte_count,
        digest=digest.hexdigest(),
        identity=(int(before.st_dev), int(before.st_ino)),
    )


class _BoundedDecompressingReader(io.RawIOBase):
    def __init__(self, source: BinaryIO, *, compressed: bool) -> None:
        self._source = source
        self._decompressor = zlib.decompressobj() if compressed else None
        self._buffer = bytearray()
        self._finished = False
        self._source_exhausted = False
        self._total = 0

    def readable(self) -> bool:
        return True

    def readinto(self, target: bytearray | memoryview) -> int:
        if self._finished and not self._buffer:
            return 0
        view = memoryview(target).cast("B")
        while len(self._buffer) < len(view) and not self._finished:
            if self._decompressor is None:
                decoded = self._source.read(1024 * 1024)
                if not decoded:
                    self._finished = True
            else:
                pending = self._decompressor.unconsumed_tail
                if pending:
                    chunk = pending
                elif not self._source_exhausted:
                    chunk = self._source.read(1024 * 1024)
                    self._source_exhausted = not chunk
                else:
                    chunk = b""
                remaining = ANDROID_BACKUP_MAXIMUM_UNPACKED_BYTES - self._total
                output_limit = min(
                    max(1, len(view) - len(self._buffer)), remaining + 1, 1024 * 1024
                )
                try:
                    decoded = self._decompressor.decompress(chunk, output_limit)
                except zlib.error as exc:
                    raise UnsupportedSchemaError(
                        "The Android backup compression stream was invalid."
                    ) from exc
                if len(decoded) > remaining:
                    raise UnsupportedSchemaError(
                        "The Android backup exceeded the safe expanded-byte limit."
                    )
                if (
                    self._source_exhausted
                    and not self._decompressor.unconsumed_tail
                    and not decoded
                ):
                    if not self._decompressor.eof or self._decompressor.unused_data:
                        raise UnsupportedSchemaError(
                            "The Android backup compression stream was incomplete."
                        )
                    self._finished = True
            self._total += len(decoded)
            if self._total > ANDROID_BACKUP_MAXIMUM_UNPACKED_BYTES:
                raise UnsupportedSchemaError(
                    "The Android backup exceeded the safe expanded-byte limit."
                )
            self._buffer.extend(decoded)
        count = min(len(view), len(self._buffer))
        view[:count] = self._buffer[:count]
        del self._buffer[:count]
        return count


@contextmanager
def _android_tar_stream(
    source: Path,
    header: AndroidBackupHeader,
    *,
    expected_identity: SourceIdentity | None,
) -> Iterator[BinaryIO]:
    with regular_binary_reader(source, require_private=False) as (handle, metadata):
        _require_source_identity(metadata, expected_identity)
        handle.seek(header.payload_offset)
        reader = io.BufferedReader(
            _BoundedDecompressingReader(handle, compressed=header.compressed),
            buffer_size=1024 * 1024,
        )
        try:
            yield reader
        finally:
            reader.close()


def _open_private_binary_target(path: Path) -> tuple[int, BinaryIO]:
    secure_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        harden_private_descriptor(descriptor, expected_type=stat.S_IFREG, mode=0o600)
        handle = os.fdopen(descriptor, "wb")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, handle


def _copy_stream_private(
    source: BinaryIO,
    target: Path,
    *,
    declared_size: int,
    cancellation_check: Callable[[], None] | None,
) -> tuple[int, str]:
    if declared_size <= 0 or declared_size > ANDROID_DATABASE_MAXIMUM_BYTES:
        raise UnsupportedSchemaError("An Android database had an unsafe declared byte size.")
    digest = hashlib.sha256()
    byte_count = 0
    _descriptor, handle = _open_private_binary_target(target)
    try:
        with handle:
            while True:
                if cancellation_check is not None:
                    cancellation_check()
                chunk = source.read(min(1024 * 1024, declared_size - byte_count + 1))
                if not chunk:
                    break
                byte_count += len(chunk)
                if byte_count > declared_size or byte_count > ANDROID_DATABASE_MAXIMUM_BYTES:
                    raise UnsupportedSchemaError(
                        "An Android database exceeded its safe declared byte size."
                    )
                digest.update(chunk)
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        # The fresh private output is intentionally retained as incomplete.
        raise
    if byte_count != declared_size:
        raise PartialExtractionError("An Android database ended before its declared byte size.")
    secure_file(target)
    return byte_count, digest.hexdigest()


def _copy_regular_source_private(
    source: Path,
    target: Path,
    *,
    expected_identity: SourceIdentity | None,
    cancellation_check: Callable[[], None] | None,
) -> tuple[int, str]:
    with regular_binary_reader(source, require_private=False) as (handle, opened):
        _require_source_identity(opened, expected_identity)
        return _copy_stream_private(
            handle,
            target,
            declared_size=int(opened.st_size),
            cancellation_check=cancellation_check,
        )


def _safe_archive_name(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise UnsafePathError("The Android backup contained an unsafe archive member name.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise UnsafePathError("The Android backup contained an unsafe archive member name.")
    return path.as_posix()


def _inventory_file_id(relative_path: str) -> str:
    return hashlib.sha1(
        b"tvtime-acquired-android-v1\x00" + relative_path.encode("utf-8")
    ).hexdigest()


def _inventory_row(
    *,
    relative_path: str,
    byte_size: int,
    sha256: str,
) -> dict[str, object]:
    domain, _, domain_relative = relative_path.partition("/")
    return {
        "file_id": _inventory_file_id(relative_path),
        "domain": domain,
        "relative_path": domain_relative,
        "declared_size": byte_size,
        "actual_size": byte_size,
        "size_match": True,
        "mtime": "",
        "sha256": sha256,
    }


def _create_acquisition_layout(output_root: Path) -> tuple[Path, Path, Path, Path]:
    output_root = secure_directory(output_root)
    extraction_root = secure_directory(output_root / EXTRACTION_DIRECTORY_NAME)
    raw_root = secure_directory(extraction_root / "raw")
    metadata_root = secure_directory(extraction_root / "metadata")
    secure_directory(extraction_root / "manifest")
    secure_directory(extraction_root / ".tmp")
    write_json_private_atomic(
        metadata_root / "run_state.json",
        {
            "schema_version": EXTRACTION_RUN_STATE_SCHEMA_VERSION,
            "contract": EXTRACTION_RUN_STATE_CONTRACT,
            "status": "incomplete",
            "message": "Acquisition did not reach its safe completion checkpoint.",
        },
    )
    return extraction_root, raw_root, metadata_root, extraction_root / ".tmp"


def _seal_acquisition(
    *,
    extraction_root: Path,
    metadata_root: Path,
    inventory: list[dict[str, object]],
    cancellation_check: Callable[[], None] | None,
) -> ExtractionResult:
    inventory = sorted(inventory, key=lambda row: str(row["relative_path"]))
    write_csv_private(
        metadata_root / "inventory.csv",
        inventory,
        [
            "file_id",
            "domain",
            "relative_path",
            "declared_size",
            "actual_size",
            "size_match",
            "mtime",
            "sha256",
        ],
        spreadsheet_safe=False,
    )
    write_text_private(metadata_root / "domains.txt", PRIMARY_DOMAIN + "\n")
    byte_count = sum(int(row["actual_size"]) for row in inventory)
    completed_utc = datetime.now(timezone.utc).isoformat()
    summary: dict[str, Any] = {
        "bundle_id": ANDROID_PACKAGE_NAME,
        "domains": [PRIMARY_DOMAIN],
        "files_expected": len(inventory),
        "files_extracted": len(inventory),
        "failures": [],
        "bytes_extracted": byte_count,
        "selected_declared_bytes": byte_count,
        "size_discrepancies": [],
        "decrypted_manifest_included": False,
        "completed_utc": completed_utc,
    }
    write_json_private_atomic(metadata_root / "summary.json", summary)
    snapshot = reconcile_raw_tree(
        extraction_root,
        cancellation_check=cancellation_check,
    )
    write_json_private_atomic(
        metadata_root / "run_state.json",
        {
            "schema_version": EXTRACTION_RUN_STATE_SCHEMA_VERSION,
            "contract": EXTRACTION_RUN_STATE_CONTRACT,
            "status": "complete",
            "completed_utc": completed_utc,
            "files_expected": len(inventory),
            "files_extracted": len(inventory),
            "bytes_extracted": byte_count,
            "selected_declared_bytes": byte_count,
            "size_discrepancy_count": 0,
            "source_snapshot": snapshot.as_dict(),
        },
        before_replace=lambda: reconcile_raw_tree(
            extraction_root,
            expected=snapshot,
            cancellation_check=cancellation_check,
        ),
    )
    temporary_root = extraction_root / ".tmp"
    try:
        temporary_root.rmdir()
    except OSError as exc:
        raise UnsafePathError(
            "The private acquisition staging directory was not empty at completion."
        ) from exc
    return ExtractionResult(extraction_root=extraction_root, summary=summary)


def _acquire_android_archive_into(
    source: Path,
    output_root: Path,
    *,
    source_preflight: AcquisitionPreflight,
    cancellation_check: Callable[[], None] | None,
) -> ExtractionResult:
    if source_preflight.source_identity is None:
        raise SourceChangedError("The selected Android backup identity was not bound.")
    with regular_binary_reader(source, require_private=False) as (handle, metadata):
        _require_source_identity(metadata, source_preflight.source_identity)
        header_bytes = handle.read(ANDROID_BACKUP_MAXIMUM_HEADER_BYTES)
    header = parse_android_backup_header(header_bytes)
    extraction_root, raw_root, metadata_root, _temp_root = _create_acquisition_layout(output_root)
    inventory: list[dict[str, object]] = []
    seen: set[str] = set()
    member_count = 0
    with _android_tar_stream(
        source,
        header,
        expected_identity=source_preflight.source_identity,
    ) as stream:
        try:
            with tarfile.open(fileobj=stream, mode="r|") as archive:
                for member in archive:
                    if cancellation_check is not None:
                        cancellation_check()
                    member_count += 1
                    if member_count > ANDROID_ARCHIVE_MAXIMUM_MEMBERS:
                        raise UnsupportedSchemaError(
                            "The Android backup exceeded the safe archive-member limit."
                        )
                    name = _safe_archive_name(member.name)
                    target_parts = _ANDROID_DATABASE_TARGETS.get(name)
                    if target_parts is None:
                        continue
                    if name in seen:
                        raise UnsupportedSchemaError(
                            "The Android backup contained a duplicate required database."
                        )
                    if not member.isfile():
                        raise UnsafePathError(
                            "A required Android database was not a regular archive member."
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise PartialExtractionError(
                            "A required Android database could not be opened from the backup."
                        )
                    if member.size == 0 and name != "apps/com.tozelabs.tvshowtime/db/DioCache.db":
                        seen.add(name)
                        continue
                    target = safe_join(raw_root, *target_parts)
                    byte_size, digest = _copy_stream_private(
                        extracted,
                        target,
                        declared_size=int(member.size),
                        cancellation_check=cancellation_check,
                    )
                    relative = target.relative_to(raw_root).as_posix()
                    inventory.append(
                        _inventory_row(
                            relative_path=relative,
                            byte_size=byte_size,
                            sha256=digest,
                        )
                    )
                    seen.add(name)
        except tarfile.TarError as exc:
            raise UnsupportedSchemaError("The Android backup TAR stream was invalid.") from exc
    if "apps/com.tozelabs.tvshowtime/db/DioCache.db" not in seen:
        raise AppDataMissingError(
            "The Android backup did not contain TV Time's required DioCache.db database."
        )
    current_size, current_digest, current_identity = _source_file_snapshot(
        source,
        cancellation_check=cancellation_check,
    )
    if (
        current_size != source_preflight.source_bytes
        or current_digest != source_preflight.source_sha256
        or current_identity != source_preflight.source_identity
    ):
        raise SourceChangedError("The selected Android backup changed during acquisition.")
    return _seal_acquisition(
        extraction_root=extraction_root,
        metadata_root=metadata_root,
        inventory=inventory,
        cancellation_check=cancellation_check,
    )


def _select_snapshot_database(root: Path, filename: str) -> Path | None:
    selected: Path | None = None
    for parts in _ANDROID_SNAPSHOT_CANDIDATES[filename]:
        # Revalidate every existing component, not only the final database.
        # A regular file reached through a linked `db`/`databases` directory is
        # outside the user-selected snapshot and must never be copied.
        try:
            candidate = no_link_absolute_path(safe_join(root, *parts))
        except ValueError as exc:
            raise UnsafePathError(
                "The Android snapshot database path crossed an unsafe ancestor."
            ) from exc
        if not candidate.exists():
            continue
        if candidate.is_symlink() or not candidate.is_file():
            raise UnsafePathError("An Android snapshot database was not a regular file.")
        if selected is not None:
            raise UnsupportedSchemaError(
                "The Android snapshot contained multiple candidates for one database."
            )
        selected = candidate
    return selected


def _snapshot_android_databases(
    source: Path,
    *,
    cancellation_check: Callable[[], None] | None,
) -> tuple[SourceFileReceipt, ...]:
    snapshots: list[SourceFileReceipt] = []
    for filename in _ANDROID_SNAPSHOT_TARGETS:
        selected = _select_snapshot_database(source, filename)
        if selected is None:
            if filename == "DioCache.db":
                raise AppDataMissingError(
                    "The preserved Android snapshot did not contain the required "
                    "DioCache.db database."
                )
            continue
        byte_count, digest, identity = _source_file_snapshot(
            selected,
            cancellation_check=cancellation_check,
            allow_empty=filename != "DioCache.db",
        )
        if byte_count == 0 and filename != "DioCache.db":
            continue
        snapshots.append((filename, byte_count, digest, identity))
    return tuple(snapshots)


def inspect_android_snapshot(
    source: Path,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> AcquisitionPreflight:
    source = no_link_absolute_path(source)
    if source.is_symlink() or not source.is_dir():
        raise UserInputError("The preserved Android snapshot directory was not found.")
    source_files = _snapshot_android_databases(
        source,
        cancellation_check=cancellation_check,
    )
    byte_count = sum(item[1] for item in source_files)
    aggregate = hashlib.sha256()
    for filename, size, digest, identity in source_files:
        aggregate.update(f"{filename}\0{size}\0{digest}\n".encode("ascii"))
        aggregate.update(f"{identity[0]}\0{identity[1]}\n".encode("ascii"))
    return AcquisitionPreflight(
        source_kind=RecoverySourceKind.ANDROID_PRESERVED_SNAPSHOT,
        source_bytes=byte_count,
        source_sha256=aggregate.hexdigest(),
        source_files=source_files,
        warnings=("already_preserved_snapshot_only",),
    )


def _official_export_members(
    source: Path,
    *,
    expected_identity: SourceIdentity | None,
) -> tuple[tuple[str, zipfile.ZipInfo | None], ...]:
    if source.name in OFFICIAL_EXPORT_FILENAMES:
        return ((source.name, None),)
    if source.suffix.casefold() != ".zip":
        raise UserInputError(
            "Select an official TV Time export ZIP or one of its supported tracking CSV files."
        )
    try:
        with regular_binary_reader(source, require_private=False) as (handle, opened):
            _require_source_identity(opened, expected_identity)
            with zipfile.ZipFile(handle) as archive:
                if len(archive.infolist()) > ANDROID_ARCHIVE_MAXIMUM_MEMBERS:
                    raise UnsupportedSchemaError(
                        "The official export exceeded the safe archive-member limit."
                    )
                selected: dict[str, zipfile.ZipInfo] = {}
                expanded_total = 0
                for member in archive.infolist():
                    expanded_total += int(member.file_size)
                    if expanded_total > OFFICIAL_EXPORT_MAXIMUM_ARCHIVE_BYTES:
                        raise UnsupportedSchemaError(
                            "The official export exceeded the safe expanded-byte limit."
                        )
                    name = _safe_archive_name(member.filename)
                    basename = PurePosixPath(name).name
                    if basename not in OFFICIAL_EXPORT_FILENAMES:
                        continue
                    if member.is_dir() or basename in selected:
                        raise UnsupportedSchemaError(
                            "The official export contained duplicate or invalid tracking files."
                        )
                    if (
                        member.file_size <= 0
                        or member.file_size > OFFICIAL_EXPORT_MAXIMUM_CSV_BYTES
                    ):
                        raise UnsupportedSchemaError(
                            "An official export tracking file had an unsafe byte size."
                        )
                    selected[basename] = member
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise UnsupportedSchemaError("The official TV Time export ZIP was invalid.") from exc
    if not selected:
        raise AppDataMissingError(
            "The official export did not contain a supported TV Time tracking CSV."
        )
    return tuple(sorted(selected.items()))


def inspect_official_export(
    source: Path,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> AcquisitionPreflight:
    source = no_link_absolute_path(source)
    byte_count, digest, identity = _source_file_snapshot(
        source,
        cancellation_check=cancellation_check,
    )
    members = _official_export_members(source, expected_identity=identity)
    encrypted = any(member is not None and bool(member.flag_bits & 0x1) for _, member in members)
    warnings: tuple[str, ...] = ()
    if len(members) == 1:
        warnings = ("official_export_partial_file_set",)
    return AcquisitionPreflight(
        source_kind=RecoverySourceKind.TVTIME_OFFICIAL_EXPORT,
        source_bytes=byte_count,
        source_sha256=digest,
        source_identity=identity,
        encrypted=encrypted,
        warnings=warnings,
    )


def _read_official_export_payloads(
    source: Path,
    members: tuple[tuple[str, zipfile.ZipInfo | None], ...],
    *,
    expected_identity: SourceIdentity,
    passphrase: str | None,
    cancellation_check: Callable[[], None] | None,
) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    total_bytes = 0
    password = bytearray(passphrase.encode("utf-8")) if passphrase else bytearray()
    try:
        if members[0][1] is None:
            with regular_binary_reader(source, require_private=False) as (handle, opened):
                _require_source_identity(opened, expected_identity)
                if opened.st_size > OFFICIAL_EXPORT_MAXIMUM_CSV_BYTES:
                    raise UnsupportedSchemaError(
                        "The official export tracking file had an unsafe byte size."
                    )
                payload = handle.read(OFFICIAL_EXPORT_MAXIMUM_CSV_BYTES + 1)
            if len(payload) != opened.st_size or len(payload) > OFFICIAL_EXPORT_MAXIMUM_CSV_BYTES:
                raise SourceChangedError(
                    "The official export tracking file changed while it was read."
                )
            return {members[0][0]: payload}
        try:
            with regular_binary_reader(source, require_private=False) as (source_handle, opened):
                _require_source_identity(opened, expected_identity)
                with zipfile.ZipFile(source_handle) as archive:
                    for basename, member in members:
                        if cancellation_check is not None:
                            cancellation_check()
                        if member is None:
                            raise UnsupportedSchemaError(
                                "The official export member contract was inconsistent."
                            )
                        try:
                            with archive.open(
                                member,
                                "r",
                                pwd=bytes(password) if password else None,
                            ) as handle:
                                payload = handle.read(OFFICIAL_EXPORT_MAXIMUM_CSV_BYTES + 1)
                        except RuntimeError as exc:
                            raise BackupPasswordError(
                                "The official export password was rejected."
                            ) from exc
                        except NotImplementedError as exc:
                            raise UnsupportedSchemaError(
                                "The official export ZIP encryption is not supported safely."
                            ) from exc
                        if len(payload) != member.file_size:
                            raise UnsupportedSchemaError(
                                "An official export tracking file changed or ended unexpectedly."
                            )
                        total_bytes += len(payload)
                        if total_bytes > OFFICIAL_EXPORT_MAXIMUM_TOTAL_BYTES:
                            raise UnsupportedSchemaError(
                                "The official export exceeded the safe combined "
                                "tracking-byte limit."
                            )
                        result[basename] = payload
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise UnsupportedSchemaError("The official TV Time export ZIP was invalid.") from exc
    finally:
        for index in range(len(password)):
            password[index] = 0
    return result


def _bounded_csv_rows(payload: bytes, *, expected_filename: str) -> list[dict[str, str]]:
    if not payload or len(payload) > OFFICIAL_EXPORT_MAXIMUM_CSV_BYTES:
        raise UnsupportedSchemaError("An official export CSV had an unsafe byte size.")
    try:
        text = payload.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise UnsupportedSchemaError("An official export CSV was not valid UTF-8.") from exc
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        fields = reader.fieldnames
        normalized_fields = [field.strip() for field in fields] if fields else []
        if (
            not fields
            or len(fields) != len(set(fields))
            or len(normalized_fields) != len(set(normalized_fields))
            or any(not field or len(field.encode("utf-8")) > 1024 for field in normalized_fields)
        ):
            raise UnsupportedSchemaError("An official export CSV header had an unsupported format.")
        rows: list[dict[str, str]] = []
        for row_number, row in enumerate(reader, 1):
            if row_number > OFFICIAL_EXPORT_MAXIMUM_ROWS:
                raise UnsupportedSchemaError(
                    "The official export exceeded the safe tracking-row limit."
                )
            if None in row or any(value is None for value in row.values()):
                raise UnsupportedSchemaError("An official export CSV row did not match its header.")
            normalized = {str(key).strip(): str(value) for key, value in row.items()}
            if any(
                len(value.encode("utf-8")) > OFFICIAL_EXPORT_MAXIMUM_CELL_BYTES
                for value in normalized.values()
            ):
                raise UnsupportedSchemaError(
                    "An official export CSV cell exceeded the safe byte limit."
                )
            rows.append(normalized)
    except csv.Error as exc:
        raise UnsupportedSchemaError("An official export CSV was malformed.") from exc
    if not rows:
        raise UnsupportedSchemaError(
            f"The supported official export file {expected_filename} contained no records."
        )
    return rows


def _first_value(row: dict[str, str], *names: str) -> str:
    for name in names:
        value = row.get(name, "").strip()
        if value:
            return value
    return ""


def _require_decimal(value: str, *, label: str) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise UnsupportedSchemaError(f"An official export row had an invalid {label}.")
    result = int(value)
    if result < 0 or result > 1_000_000:
        raise UnsupportedSchemaError(f"An official export row had an invalid {label}.")
    return result


def _official_export_payload_records(
    payloads: dict[str, bytes],
) -> list[tuple[str, str, bytes, int]]:
    library: dict[str, dict[str, object]] = {}
    episodes: list[dict[str, object]] = []
    watches: list[dict[str, object]] = []
    recognized_rows = 0

    episode_payload = payloads.get("tracking-prod-records-v2.csv")
    if episode_payload is not None:
        for row in _bounded_csv_rows(
            episode_payload,
            expected_filename="tracking-prod-records-v2.csv",
        ):
            event_type = _first_value(row, "type", "action").casefold()
            if event_type not in {"watch-episode", "watch_episode", "watch"}:
                continue
            episode_id = _first_value(row, "ep_id", "episode_id")
            created_at = _first_value(row, "created_at", "watched_at", "seen_date")
            season = _require_decimal(
                _first_value(row, "season_number", "season"),
                label="season number",
            )
            episode_number = _require_decimal(
                _first_value(row, "episode_number", "episode"),
                label="episode number",
            )
            if not episode_id or not created_at:
                raise UnsupportedSchemaError(
                    "An official export watched-episode row lacked its ID or timestamp."
                )
            show_id = _first_value(row, "show_id", "series_id", "show_uuid", "series_uuid")
            show_name = _first_value(row, "show_name", "series_name", "show", "series")
            episode_name = _first_value(row, "episode_name", "ep_name", "name")
            episodes.append(
                {
                    "id": episode_id,
                    "show": {"id": show_id, "name": show_name},
                    "season_number": season,
                    "number": episode_number,
                    "name": episode_name,
                    "air_date": _first_value(row, "air_date"),
                    "seen": True,
                    "seen_date": created_at,
                    "is_watched": True,
                    "runtime": _first_value(row, "runtime", "runtime_seconds"),
                }
            )
            if show_id or show_name:
                identity = show_id or hashlib.sha256(show_name.encode("utf-8")).hexdigest()
                library.setdefault(
                    "series:" + identity,
                    {
                        "uuid": "official-series-" + identity,
                        "entity_type": "series",
                        "filter": ["watched"],
                        "created_at": created_at,
                        "updated_at": created_at,
                        "sorting": [{"id": "watch_date", "value": created_at}],
                        "meta": {"id": show_id, "name": show_name},
                    },
                )
            recognized_rows += 1

    general_payload = payloads.get("tracking-prod-records.csv")
    if general_payload is not None:
        for row in _bounded_csv_rows(
            general_payload,
            expected_filename="tracking-prod-records.csv",
        ):
            if _first_value(row, "entity_type").casefold() != "movie":
                continue
            action = _first_value(row, "type", "action").casefold()
            if action not in {"follow", "towatch", "watch", "watch-movie", "watch_movie"}:
                continue
            movie_id = _first_value(row, "uuid", "movie_id", "id")
            created_at = _first_value(row, "created_at", "watched_at")
            if not movie_id or not created_at:
                raise UnsupportedSchemaError(
                    "An official export movie row lacked its ID or timestamp."
                )
            name = _first_value(row, "movie_name", "name", "title")
            existing = library.get("movie:" + movie_id)
            watched = action in {"watch", "watch-movie", "watch_movie"}
            if existing is None or watched:
                library["movie:" + movie_id] = {
                    "uuid": movie_id,
                    "entity_type": "movie",
                    "filter": ["watched" if watched else "watch_later"],
                    "watched_at": created_at if watched else "",
                    "created_at": created_at,
                    "updated_at": created_at,
                    "sorting": [
                        {
                            "id": "watched_date" if watched else "follow_date",
                            "value": created_at,
                        }
                    ],
                    "extended": {"is_watched": watched},
                    "meta": {
                        "name": name,
                        "imdb_id": _first_value(row, "imdb_id", "imdb"),
                    },
                }
            if watched:
                watches.append(
                    {
                        "uuid": movie_id,
                        "entity_type": "movie",
                        "type": "watch",
                        "watched_at": created_at,
                        "runtime": _first_value(row, "runtime", "runtime_seconds"),
                        "created_at": created_at,
                        "updated_at": created_at,
                    }
                )
            recognized_rows += 1
    if recognized_rows == 0:
        raise UnsupportedSchemaError(
            "The official export contained records, but no supported TV Time tracking rows were "
            "recognized. Preserve it and retry with a schema update."
        )

    def encoded(value: object) -> bytes:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    records: list[tuple[str, str, bytes, int]] = [
        (
            "official-export://library",
            "normalized",
            encoded({"data": {"id": "library", "type": "list", "objects": list(library.values())}}),
            200,
        )
    ]
    if episodes:
        records.append(
            (
                "official-export://episodes",
                "normalized",
                encoded({"data": episodes}),
                200,
            )
        )
    if watches:
        records.append(
            (
                "official-export://watches",
                "normalized",
                encoded({"data": {"type": "watch", "objects": watches}}),
                200,
            )
        )
    return records


def _write_official_export_cache(
    target: Path,
    records: list[tuple[str, str, bytes, int]],
) -> tuple[int, str]:
    _descriptor, handle = _open_private_binary_target(target)
    try:
        with handle, closing(sqlite3.connect(":memory:")) as source_connection:
            source_connection.execute(
                "CREATE TABLE cache_dio "
                "(key TEXT NOT NULL, subKey TEXT NOT NULL, content BLOB, statusCode INTEGER)"
            )
            source_connection.executemany(
                "INSERT INTO cache_dio (key, subKey, content, statusCode) VALUES (?, ?, ?, ?)",
                records,
            )
            source_connection.commit()
            serializer = getattr(source_connection, "serialize", None)
            if serializer is None:
                _backup_sqlite_to_held_target(source_connection, handle, target.parent)
            else:
                serialized = serializer()
                if (
                    not isinstance(serialized, bytes)
                    or not serialized
                    or len(serialized) > ANDROID_DATABASE_MAXIMUM_BYTES
                ):
                    raise TVTimeError(
                        "The normalized official export cache had an unsafe byte size."
                    )
                handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
            metadata = os.fstat(handle.fileno())
            if metadata.st_size <= 0 or metadata.st_size > ANDROID_DATABASE_MAXIMUM_BYTES:
                raise TVTimeError("The normalized official export cache had an unsafe byte size.")
            expected_identity = (int(metadata.st_dev), int(metadata.st_ino))
        secure_file(target)
        with regular_binary_reader(target, require_private=True) as (reader, opened):
            _require_source_identity(opened, expected_identity)
            digest = hashlib.sha256()
            byte_count = 0
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                byte_count += len(chunk)
                if byte_count > ANDROID_DATABASE_MAXIMUM_BYTES:
                    raise TVTimeError(
                        "The normalized official export cache had an unsafe byte size."
                    )
                digest.update(chunk)
            if byte_count != metadata.st_size:
                raise TVTimeError("The normalized official export cache changed while sealed.")
    except (OSError, sqlite3.Error) as exc:
        raise TVTimeError(
            "The normalized official export cache could not be created safely."
        ) from exc
    return byte_count, digest.hexdigest()


def _backup_sqlite_to_held_target(
    source_connection: sqlite3.Connection,
    target_handle: BinaryIO,
    private_parent: Path,
) -> None:
    """Materialize SQLite 3.10 output through an unlinked, retained POSIX inode."""

    if os.name == "nt" or not hasattr(os, "pread"):
        raise UnsupportedSchemaError(
            "Official-export normalization on this runtime lacks safe SQLite serialization."
        )
    staging_root = secure_directory(
        safe_join(private_parent, f".sqlite-compat-{secrets.token_hex(16)}")
    )
    staging = safe_join(staging_root, "normalized.sqlite")
    descriptor = -1
    destination_connection: sqlite3.Connection | None = None
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(staging, flags, 0o600)
        opened = harden_private_descriptor(descriptor, expected_type=stat.S_IFREG, mode=0o600)
        expected_identity = (int(opened.st_dev), int(opened.st_ino))
        destination_connection = sqlite3.connect(staging)
        visible = staging.lstat()
        if (
            not stat.S_ISREG(visible.st_mode)
            or (int(visible.st_dev), int(visible.st_ino)) != expected_identity
        ):
            raise UnsafePathError("The private SQLite staging identity changed before use.")
        staging.unlink()
        destination_connection.execute("PRAGMA journal_mode=OFF")
        source_connection.backup(destination_connection)
        destination_connection.commit()
        destination_connection.close()
        destination_connection = None
        os.fsync(descriptor)
        byte_size = os.fstat(descriptor).st_size
        if byte_size <= 0 or byte_size > ANDROID_DATABASE_MAXIMUM_BYTES:
            raise TVTimeError("The normalized official export cache had an unsafe byte size.")
        offset = 0
        while offset < byte_size:
            chunk = os.pread(descriptor, min(1024 * 1024, byte_size - offset), offset)
            if not chunk:
                raise TVTimeError("The normalized official export cache ended unexpectedly.")
            target_handle.write(chunk)
            offset += len(chunk)
    finally:
        if destination_connection is not None:
            with suppress(sqlite3.Error):
                destination_connection.close()
        if descriptor >= 0:
            os.close(descriptor)
        for suffix in ("", "-journal", "-wal", "-shm"):
            candidate = Path(f"{staging}{suffix}")
            with suppress(FileNotFoundError):
                metadata = candidate.lstat()
                if not stat.S_ISREG(metadata.st_mode):
                    raise UnsafePathError("The private SQLite staging tree was unsafe.")
                candidate.unlink()
        staging_root.rmdir()


def _acquire_official_export_into(
    source: Path,
    output_root: Path,
    *,
    source_preflight: AcquisitionPreflight,
    passphrase: str | None,
    cancellation_check: Callable[[], None] | None,
) -> ExtractionResult:
    if source_preflight.source_identity is None:
        raise SourceChangedError("The official export identity was not bound.")
    members = _official_export_members(
        source,
        expected_identity=source_preflight.source_identity,
    )
    payloads = _read_official_export_payloads(
        source,
        members,
        expected_identity=source_preflight.source_identity,
        passphrase=passphrase,
        cancellation_check=cancellation_check,
    )
    records = _official_export_payload_records(payloads)
    extraction_root, raw_root, metadata_root, _temp_root = _create_acquisition_layout(output_root)
    inventory: list[dict[str, object]] = []
    export_root = safe_join(raw_root, PRIMARY_DOMAIN, "Documents", "Official Export")
    for filename, payload in sorted(payloads.items()):
        target = safe_join(export_root, filename)
        secure_directory(target.parent)
        _descriptor, handle = _open_private_binary_target(target)
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        secure_file(target)
        digest = hashlib.sha256(payload).hexdigest()
        inventory.append(
            _inventory_row(
                relative_path=target.relative_to(raw_root).as_posix(),
                byte_size=len(payload),
                sha256=digest,
            )
        )
    cache_target = safe_join(raw_root, PRIMARY_DOMAIN, "Documents", "DioCache.db")
    cache_size, cache_digest = _write_official_export_cache(cache_target, records)
    inventory.append(
        _inventory_row(
            relative_path=cache_target.relative_to(raw_root).as_posix(),
            byte_size=cache_size,
            sha256=cache_digest,
        )
    )
    current_size, current_digest, current_identity = _source_file_snapshot(
        source,
        cancellation_check=cancellation_check,
    )
    if (
        current_size != source_preflight.source_bytes
        or current_digest != source_preflight.source_sha256
        or current_identity != source_preflight.source_identity
    ):
        raise SourceChangedError("The official TV Time export changed during acquisition.")
    return _seal_acquisition(
        extraction_root=extraction_root,
        metadata_root=metadata_root,
        inventory=inventory,
        cancellation_check=cancellation_check,
    )


def _acquire_android_snapshot_into(
    source: Path,
    output_root: Path,
    *,
    source_preflight: AcquisitionPreflight,
    cancellation_check: Callable[[], None] | None,
) -> ExtractionResult:
    extraction_root, raw_root, metadata_root, _temp_root = _create_acquisition_layout(output_root)
    inventory: list[dict[str, object]] = []
    expected_sources = {item[0]: item[3] for item in source_preflight.source_files}
    if "DioCache.db" not in expected_sources:
        raise SourceChangedError("The preserved Android snapshot identity was not bound.")
    for filename, target_parts in _ANDROID_SNAPSHOT_TARGETS.items():
        selected = _select_snapshot_database(source, filename)
        if selected is None:
            if filename == "DioCache.db":
                raise AppDataMissingError(
                    "The preserved Android snapshot did not contain DioCache.db."
                )
            continue
        if filename not in expected_sources:
            if filename != "DioCache.db":
                byte_count, _digest, _identity = _source_file_snapshot(
                    selected,
                    cancellation_check=cancellation_check,
                    allow_empty=True,
                )
                if byte_count == 0:
                    continue
            raise SourceChangedError("The preserved Android snapshot changed after inspection.")
        target = safe_join(raw_root, *target_parts)
        byte_size, digest = _copy_regular_source_private(
            selected,
            target,
            expected_identity=expected_sources.get(filename),
            cancellation_check=cancellation_check,
        )
        relative = target.relative_to(raw_root).as_posix()
        inventory.append(
            _inventory_row(
                relative_path=relative,
                byte_size=byte_size,
                sha256=digest,
            )
        )
    current_source_files = _snapshot_android_databases(
        source,
        cancellation_check=cancellation_check,
    )
    if current_source_files != source_preflight.source_files:
        raise SourceChangedError("The preserved Android snapshot changed during acquisition.")
    return _seal_acquisition(
        extraction_root=extraction_root,
        metadata_root=metadata_root,
        inventory=inventory,
        cancellation_check=cancellation_check,
    )


def recover_acquired_source(
    *,
    source_kind: RecoverySourceKind,
    source: Path,
    output_directory: Path,
    acknowledge_sensitive_output: bool,
    include_raw_cache: bool = False,
    source_passphrase: str | None = None,
    source_preflight: AcquisitionPreflight | None = None,
    cancellation_check: Callable[[], None] | None = None,
    destination_parent_descriptor: int | None = None,
    expected_parent_identity: tuple[int, int] | None = None,
) -> AcquiredRecoveryResult:
    if not acknowledge_sensitive_output:
        raise UserInputError(
            "Recovery requires explicit acknowledgement that the output contains private data."
        )
    source = no_link_absolute_path(source)
    output = no_link_absolute_path(output_directory)
    if (destination_parent_descriptor is None) != (expected_parent_identity is None):
        raise UserInputError("The acquisition destination binding was incomplete.")

    @contextmanager
    def bound_parent_context() -> Iterator[tuple[int, tuple[int, int], Path]]:
        if destination_parent_descriptor is not None and expected_parent_identity is not None:
            require_bound_destination_parent(
                output,
                destination_parent_descriptor=destination_parent_descriptor,
                expected_identity=expected_parent_identity,
            )
            yield destination_parent_descriptor, expected_parent_identity, output
            return
        with held_destination_parent(output) as binding:
            yield binding

    try:
        with bound_parent_context() as (parent_handle, parent_identity, visible_output):
            # Retain the exact validated parent across source hashing and all output work.
            # This prevents a replacement or remount from invalidating the destination
            # checks while a large acquisition source is inspected.
            require_private_local_destination(visible_output)
            if is_within(visible_output, source) or is_within(source, visible_output):
                raise UnsafePathError(
                    "The Android source and recovery destination must not overlap."
                )
            if nearest_git_root(visible_output) is not None:
                raise UnsafePathError("Refusing to place recovered data inside a Git repository.")
            if source_preflight is not None and source_preflight.source_kind is not source_kind:
                raise SourceChangedError("The inspected source kind changed before acquisition.")
            if source_kind is RecoverySourceKind.ANDROID_LEGACY_BACKUP:
                preflight = source_preflight or inspect_android_backup(
                    source, cancellation_check=cancellation_check
                )
                acquisition = _acquire_android_archive_into
            elif source_kind is RecoverySourceKind.ANDROID_PRESERVED_SNAPSHOT:
                preflight = source_preflight or inspect_android_snapshot(
                    source, cancellation_check=cancellation_check
                )
                acquisition = _acquire_android_snapshot_into
            elif source_kind is RecoverySourceKind.TVTIME_OFFICIAL_EXPORT:
                preflight = source_preflight or inspect_official_export(
                    source, cancellation_check=cancellation_check
                )
                acquisition = _acquire_official_export_into
            else:
                raise UserInputError(
                    "The selected acquisition source is not implemented by this route."
                )
            with anchored_bound_output_root(
                visible_output,
                destination_parent_descriptor=parent_handle,
                expected_parent_identity=parent_identity,
            ) as bound_output:
                if source_kind is RecoverySourceKind.TVTIME_OFFICIAL_EXPORT:
                    extraction = acquisition(
                        source,
                        bound_output,
                        source_preflight=preflight,
                        passphrase=source_passphrase,
                        cancellation_check=cancellation_check,
                    )
                else:
                    extraction = acquisition(
                        source,
                        bound_output,
                        source_preflight=preflight,
                        cancellation_check=cancellation_check,
                    )
                analysis = analyze_extraction(
                    extraction_directory=extraction.extraction_root,
                    include_raw_cache=include_raw_cache,
                    cancellation_check=cancellation_check,
                )
                report = build_report(
                    extraction_directory=extraction.extraction_root,
                    cancellation_check=cancellation_check,
                )
        visible_extraction = ExtractionResult(
            extraction_root=visible_output / EXTRACTION_DIRECTORY_NAME,
            summary=extraction.summary,
        )
        visible_report = dict(report)
        for key in ("report", "visual_report", "pdf_report"):
            value = visible_report.get(key)
            if value:
                candidate = Path(str(value))
                if not candidate.is_absolute():
                    visible_report[key] = str(visible_output / candidate)
        return AcquiredRecoveryResult(
            source_preflight=preflight,
            extraction=visible_extraction,
            analysis=analysis,
            report=visible_report,
        )
    except OSError as exc:
        if is_insufficient_space_error(exc):
            raise insufficient_space_error() from exc
        raise TVTimeError("Android acquisition failed safely.") from exc
