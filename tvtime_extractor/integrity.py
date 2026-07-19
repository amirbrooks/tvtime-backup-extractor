from __future__ import annotations

import csv
import hashlib
import io
import os
import stat
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import PartialExtractionError, UnsafePathError
from .safety import (
    iter_regular_files,
    regular_binary_reader,
    safe_domain_component,
    safe_join,
    safe_manifest_relative_path,
    validate_file_id,
)

SOURCE_SNAPSHOT_CONTRACT = "tvtime-source-snapshot-v0.2"
RAW_TREE_DIGEST_PREFIX = b"tvtime-raw-tree-digest-v0.2\x00"
MAXIMUM_INVENTORY_BYTES = 256 * 1024 * 1024
MAXIMUM_CONTRACT_INTEGER = (1 << 63) - 1
INVENTORY_FIELDS = (
    "file_id",
    "domain",
    "relative_path",
    "declared_size",
    "actual_size",
    "size_match",
    "mtime",
    "sha256",
)


@dataclass(frozen=True)
class SourceSnapshot:
    inventory_bytes: int
    inventory_sha256: str
    raw_tree_files: int
    raw_tree_bytes: int
    raw_tree_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": SOURCE_SNAPSHOT_CONTRACT,
            "inventory": {
                "bytes": self.inventory_bytes,
                "sha256": self.inventory_sha256,
            },
            "raw_tree": {
                "files": self.raw_tree_files,
                "bytes": self.raw_tree_bytes,
                "sha256": self.raw_tree_sha256,
            },
        }


@dataclass(frozen=True)
class _RegularFileDigest:
    byte_size: int
    sha256: str
    data: bytes | None = None


@dataclass(frozen=True)
class _InventoryEntry:
    relative_raw_path: str
    actual_size: int
    sha256: str


def _integrity_failure() -> PartialExtractionError:
    return PartialExtractionError(
        "The extracted raw data no longer matches its sealed private inventory. Preserve this "
        "output for diagnosis and run a fresh recovery into a new output folder."
    )


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _digest_regular_file(
    path: Path,
    *,
    capture: bool = False,
    maximum_bytes: int | None = None,
    expected_size: int | None = None,
    cancellation_check: Callable[[], None] | None = None,
) -> _RegularFileDigest:
    """Hash one private regular file through a stable, no-follow descriptor."""
    digest = hashlib.sha256()
    payload = bytearray() if capture else None
    byte_count = 0
    with regular_binary_reader(path, require_private=True) as (handle, opened):
        if maximum_bytes is not None and (opened.st_size <= 0 or opened.st_size > maximum_bytes):
            raise _integrity_failure()
        if expected_size is not None and opened.st_size != expected_size:
            raise _integrity_failure()
        while True:
            if cancellation_check is not None:
                cancellation_check()
            chunk = os.read(handle.fileno(), 1024 * 1024)
            if not chunk:
                break
            byte_count += len(chunk)
            if maximum_bytes is not None and byte_count > maximum_bytes:
                raise _integrity_failure()
            digest.update(chunk)
            if payload is not None:
                payload.extend(chunk)
    if byte_count != opened.st_size:
        raise _integrity_failure()
    return _RegularFileDigest(
        byte_size=byte_count,
        sha256=digest.hexdigest(),
        data=bytes(payload) if payload is not None else None,
    )


def _canonical_nonnegative_integer(value: str) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise _integrity_failure()
    parsed = int(value)
    if str(parsed) != value:
        raise _integrity_failure()
    return parsed


def _parse_inventory(payload: bytes) -> list[_InventoryEntry]:
    try:
        text = payload.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if tuple(reader.fieldnames or ()) != INVENTORY_FIELDS:
            raise _integrity_failure()
        entries: list[_InventoryEntry] = []
        seen_paths: set[str] = set()
        for row in reader:
            if None in row or any(row.get(field) is None for field in INVENTORY_FIELDS):
                raise _integrity_failure()
            file_id = row["file_id"]
            if file_id != validate_file_id(file_id):
                raise _integrity_failure()
            domain = row["domain"]
            if domain != safe_domain_component(domain):
                raise _integrity_failure()
            relative_path = row["relative_path"]
            relative = safe_manifest_relative_path(relative_path)
            if relative.as_posix() != relative_path:
                raise _integrity_failure()
            declared_size = _canonical_nonnegative_integer(row["declared_size"])
            actual_size = _canonical_nonnegative_integer(row["actual_size"])
            expected_size_match = "True" if declared_size == actual_size else "False"
            if row["size_match"] != expected_size_match:
                raise _integrity_failure()
            file_sha256 = row["sha256"]
            if (
                len(file_sha256) != 64
                or file_sha256 != file_sha256.lower()
                or any(character not in "0123456789abcdef" for character in file_sha256)
            ):
                raise _integrity_failure()
            relative_raw_path = f"{domain}/{relative_path}"
            if relative_raw_path in seen_paths:
                raise _integrity_failure()
            seen_paths.add(relative_raw_path)
            entries.append(
                _InventoryEntry(
                    relative_raw_path=relative_raw_path,
                    actual_size=actual_size,
                    sha256=file_sha256,
                )
            )
    except (UnicodeDecodeError, csv.Error, TypeError, ValueError) as exc:
        if isinstance(exc, PartialExtractionError):
            raise
        raise _integrity_failure() from exc
    return sorted(entries, key=lambda entry: entry.relative_raw_path.encode("utf-8"))


def _tree_membership(raw_root: Path) -> tuple[list[str], list[str]]:
    files = sorted(
        (path.relative_to(raw_root).as_posix() for path in iter_regular_files(raw_root)),
        key=lambda value: value.encode("utf-8"),
    )
    directories: list[str] = []

    def raise_walk_error(error: OSError) -> None:
        raise UnsafePathError("The extracted raw directory tree could not be validated.") from error

    for current_name, directory_names, _file_names in os.walk(
        raw_root,
        onerror=raise_walk_error,
        followlinks=False,
    ):
        current = Path(current_name)
        for name in sorted(directory_names):
            candidate = current / name
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise _integrity_failure() from exc
            if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
                raise UnsafePathError("The extracted raw data contained an unsafe directory.")
            directories.append(candidate.relative_to(raw_root).as_posix())
    return (
        sorted(directories, key=lambda value: value.encode("utf-8")),
        files,
    )


def _expected_directories(entries: list[_InventoryEntry]) -> list[str]:
    directories: set[str] = set()
    for entry in entries:
        parts = entry.relative_raw_path.split("/")[:-1]
        for count in range(1, len(parts) + 1):
            directories.add("/".join(parts[:count]))
    return sorted(directories, key=lambda value: value.encode("utf-8"))


def _canonical_tree_digest(entries: list[_InventoryEntry]) -> str:
    digest = hashlib.sha256(RAW_TREE_DIGEST_PREFIX)
    for entry in entries:
        path_bytes = entry.relative_raw_path.encode("utf-8")
        digest.update(struct.pack(">Q", len(path_bytes)))
        digest.update(path_bytes)
        digest.update(struct.pack(">Q", entry.actual_size))
        digest.update(bytes.fromhex(entry.sha256))
    return digest.hexdigest()


def source_snapshot_from_mapping(value: object) -> SourceSnapshot:
    """Decode the strict v0.2 source-snapshot shape from a completion marker."""

    if not isinstance(value, dict) or set(value) != {"contract", "inventory", "raw_tree"}:
        raise _integrity_failure()
    inventory = value.get("inventory")
    raw_tree = value.get("raw_tree")
    if (
        value.get("contract") != SOURCE_SNAPSHOT_CONTRACT
        or not isinstance(inventory, dict)
        or set(inventory) != {"bytes", "sha256"}
        or not isinstance(raw_tree, dict)
        or set(raw_tree) != {"files", "bytes", "sha256"}
    ):
        raise _integrity_failure()

    integers = (inventory.get("bytes"), raw_tree.get("files"), raw_tree.get("bytes"))
    hashes = (inventory.get("sha256"), raw_tree.get("sha256"))
    if (
        any(
            not isinstance(item, int)
            or isinstance(item, bool)
            or item < 0
            or item > MAXIMUM_CONTRACT_INTEGER
            for item in integers
        )
        or inventory.get("bytes") == 0
        or any(
            not isinstance(item, str)
            or len(item) != 64
            or item != item.lower()
            or any(character not in "0123456789abcdef" for character in item)
            for item in hashes
        )
    ):
        raise _integrity_failure()
    return SourceSnapshot(
        inventory_bytes=inventory["bytes"],
        inventory_sha256=inventory["sha256"],
        raw_tree_files=raw_tree["files"],
        raw_tree_bytes=raw_tree["bytes"],
        raw_tree_sha256=raw_tree["sha256"],
    )


def reconcile_raw_tree(
    extraction: Path,
    *,
    expected: SourceSnapshot | None = None,
    cancellation_check: Callable[[], None] | None = None,
) -> SourceSnapshot:
    """Prove that inventory.csv and every raw byte describe one exact private tree."""

    try:
        raw_root = safe_join(extraction, "raw")
        inventory_path = safe_join(extraction, "metadata", "inventory.csv")
    except ValueError as exc:
        raise UnsafePathError("The private extraction inventory path was unsafe.") from exc

    inventory_before = _digest_regular_file(
        inventory_path,
        capture=True,
        maximum_bytes=MAXIMUM_INVENTORY_BYTES,
        cancellation_check=cancellation_check,
    )
    if inventory_before.data is None:
        raise _integrity_failure()
    entries = _parse_inventory(inventory_before.data)
    expected_paths = [entry.relative_raw_path for entry in entries]
    expected_directories = _expected_directories(entries)

    if _tree_membership(raw_root) != (expected_directories, expected_paths):
        raise _integrity_failure()
    for entry in entries:
        path = safe_join(raw_root, *entry.relative_raw_path.split("/"))
        observed = _digest_regular_file(
            path,
            expected_size=entry.actual_size,
            cancellation_check=cancellation_check,
        )
        if observed.sha256 != entry.sha256:
            raise _integrity_failure()

    # Repeat both membership and byte checks so replacements, removals, additions,
    # and in-place mutations racing the first pass cannot become a sealed result.
    if _tree_membership(raw_root) != (expected_directories, expected_paths):
        raise _integrity_failure()
    for entry in entries:
        path = safe_join(raw_root, *entry.relative_raw_path.split("/"))
        observed = _digest_regular_file(
            path,
            expected_size=entry.actual_size,
            cancellation_check=cancellation_check,
        )
        if observed.sha256 != entry.sha256:
            raise _integrity_failure()

    inventory_after = _digest_regular_file(
        inventory_path,
        maximum_bytes=MAXIMUM_INVENTORY_BYTES,
        cancellation_check=cancellation_check,
    )
    if (
        inventory_after.byte_size != inventory_before.byte_size
        or inventory_after.sha256 != inventory_before.sha256
    ):
        raise _integrity_failure()

    snapshot = SourceSnapshot(
        inventory_bytes=inventory_before.byte_size,
        inventory_sha256=inventory_before.sha256,
        raw_tree_files=len(entries),
        raw_tree_bytes=sum(entry.actual_size for entry in entries),
        raw_tree_sha256=_canonical_tree_digest(entries),
    )
    if expected is not None and snapshot != expected:
        raise _integrity_failure()
    return snapshot
