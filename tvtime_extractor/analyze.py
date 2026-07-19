from __future__ import annotations

import csv
import hashlib
import json
import os
import plistlib
import sqlite3
import stat
import tempfile
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

from .display_text import has_display_text
from .errors import (
    AppDataMissingError,
    TVTimeError,
    UnsafePathError,
    UnsupportedSchemaError,
    insufficient_space_error,
    is_insufficient_space_error,
)
from .extract import PRIMARY_DOMAIN
from .integrity import reconcile_raw_tree, source_snapshot_from_mapping
from .safety import (
    MAXIMUM_COMPLETION_MARKER_BYTES,
    anchored_existing_extraction_root,
    iter_regular_files,
    prepare_analysis_layout,
    private_source_id,
    promote_directory_no_replace_atomic,
    read_json_regular,
    regular_binary_reader,
    require_private_descriptor,
    safe_join,
    secure_directory,
    secure_file,
    validate_extraction_directory,
    write_bytes_private,
    write_csv_private,
    write_json_private,
)

# Production cache-analysis safety envelope. These limits are deliberately far
# above ordinary TV Time recovery volumes while still bounding every allocation
# controlled by an untrusted cache database. Keep report-side parsing aligned
# with these constants rather than adding a second, looser parser.
MAXIMUM_CACHE_ROWS = 100_000
MAXIMUM_CACHE_KEY_BYTES = 256 * 1024
MAXIMUM_CACHE_SUBKEY_BYTES = 256 * 1024
MAXIMUM_CACHE_STATUS_BYTES = 32
MAXIMUM_TOTAL_CACHE_METADATA_BYTES = 32 * 1024 * 1024
MAXIMUM_CACHE_PAYLOAD_BYTES = 32 * 1024 * 1024
MAXIMUM_TOTAL_CACHE_PAYLOAD_BYTES = 256 * 1024 * 1024
MAXIMUM_CACHE_JSON_DEPTH = 128
MAXIMUM_CACHE_JSON_NODES = 1_000_000
MAXIMUM_CACHE_JSON_STRING_BYTES = 8 * 1024 * 1024
MAXIMUM_TOTAL_CACHE_JSON_NODES = 5_000_000
MAXIMUM_DERIVED_ROWS_PER_TABLE = 100_000
MAXIMUM_TOTAL_DERIVED_ROWS = 250_000
MAXIMUM_SQLITE_SNAPSHOT_FILE_BYTES = 512 * 1024 * 1024
MAXIMUM_SQLITE_SNAPSHOT_TOTAL_BYTES = 768 * 1024 * 1024
MAXIMUM_SQLITE_SCHEMA_OBJECTS = 100_000
MAXIMUM_SQLITE_SCHEMA_NAME_BYTES = 256 * 1024
MAXIMUM_SQLITE_SCHEMA_TOTAL_BYTES = 16 * 1024 * 1024
MAXIMUM_PLIST_BYTES = 32 * 1024 * 1024
MAXIMUM_ANALYSIS_CSV_BYTES = 64 * 1024 * 1024
MAXIMUM_ANALYSIS_CSV_ROWS = 100_000
MAXIMUM_ANALYSIS_CSV_CELL_BYTES = MAXIMUM_CACHE_JSON_STRING_BYTES
MAXIMUM_ANALYSIS_CSV_ROW_BYTES = 16 * 1024 * 1024
MAXIMUM_CSV_ESCAPE_ENTRIES = 100_000
MAXIMUM_ANALYSIS_SUMMARY_BYTES = 16 * 1024 * 1024
_SQLITE_SOURCE_STABLE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _cache_limit_error(subject: str, limit: int) -> UnsupportedSchemaError:
    return UnsupportedSchemaError(
        f"The recovered TV Time cache exceeded this release's safe {subject} limit "
        f"({limit:,}). Preserve the extraction and retry with an updated extractor; "
        "do not delete the backup."
    )


def _validate_cache_table_limits(connection: sqlite3.Connection) -> None:
    """Reject unsafe cache metadata and payloads before any ordered query."""

    row = connection.execute(
        "SELECT COUNT(*), "
        "COALESCE(SUM(CASE WHEN typeof(key) = 'text' THEN 0 ELSE 1 END), 0), "
        "COALESCE(SUM(CASE WHEN typeof(subKey) = 'text' THEN 0 ELSE 1 END), 0), "
        "COALESCE(SUM(CASE WHEN typeof(statusCode) IN ('integer','null') "
        "THEN 0 ELSE 1 END), 0), "
        "COALESCE(SUM(CASE WHEN typeof(content) IN ('blob','text','null') "
        "THEN 0 ELSE 1 END), 0), "
        "COALESCE(MAX(length(CAST(key AS BLOB))), 0), "
        "COALESCE(MAX(length(CAST(subKey AS BLOB))), 0), "
        "COALESCE(MAX(length(CAST(statusCode AS BLOB))), 0), "
        "COALESCE(SUM(length(CAST(key AS BLOB)) + length(CAST(subKey AS BLOB)) + "
        "COALESCE(length(CAST(statusCode AS BLOB)), 0)), 0), "
        "COALESCE(MAX(length(CAST(content AS BLOB))), 0), "
        "COALESCE(SUM(length(CAST(content AS BLOB))), 0) "
        "FROM cache_dio"
    ).fetchone()
    if row is None or len(row) != 11:
        raise UnsupportedSchemaError(
            "DioCache.db could not provide safe cache-size statistics. Preserve the extraction "
            "and check for an app-schema update."
        )
    try:
        (
            cache_rows,
            invalid_key_types,
            invalid_subkey_types,
            invalid_status_types,
            invalid_content_types,
            largest_key,
            largest_subkey,
            largest_status,
            total_metadata_bytes,
            largest_payload,
            total_payload_bytes,
        ) = (int(value or 0) for value in row)
    except (TypeError, ValueError, OverflowError) as exc:
        raise UnsupportedSchemaError(
            "DioCache.db returned invalid cache-size statistics. Preserve the extraction and "
            "check for an app-schema update."
        ) from exc
    if (
        min(
            cache_rows,
            invalid_key_types,
            invalid_subkey_types,
            invalid_status_types,
            invalid_content_types,
            largest_key,
            largest_subkey,
            largest_status,
            total_metadata_bytes,
            largest_payload,
            total_payload_bytes,
        )
        < 0
    ):
        raise UnsupportedSchemaError(
            "DioCache.db returned invalid cache-size statistics. Preserve the extraction and "
            "check for an app-schema update."
        )
    if invalid_key_types or invalid_subkey_types or invalid_status_types or invalid_content_types:
        raise UnsupportedSchemaError(
            "DioCache.db contained unsupported cache key, sub-key, status, or response value "
            "types. Preserve the extraction and check for an app-schema update."
        )
    if cache_rows > MAXIMUM_CACHE_ROWS:
        raise _cache_limit_error("cache-row count", MAXIMUM_CACHE_ROWS)
    if largest_key > MAXIMUM_CACHE_KEY_BYTES:
        raise _cache_limit_error("cache-key byte size", MAXIMUM_CACHE_KEY_BYTES)
    if largest_subkey > MAXIMUM_CACHE_SUBKEY_BYTES:
        raise _cache_limit_error("cache sub-key byte size", MAXIMUM_CACHE_SUBKEY_BYTES)
    if largest_status > MAXIMUM_CACHE_STATUS_BYTES:
        raise _cache_limit_error("cache-status byte size", MAXIMUM_CACHE_STATUS_BYTES)
    if total_metadata_bytes > MAXIMUM_TOTAL_CACHE_METADATA_BYTES:
        raise _cache_limit_error(
            "combined cache-metadata byte size",
            MAXIMUM_TOTAL_CACHE_METADATA_BYTES,
        )
    if largest_payload > MAXIMUM_CACHE_PAYLOAD_BYTES:
        raise _cache_limit_error("single-response byte size", MAXIMUM_CACHE_PAYLOAD_BYTES)
    if total_payload_bytes > MAXIMUM_TOTAL_CACHE_PAYLOAD_BYTES:
        raise _cache_limit_error(
            "combined cache-response byte size",
            MAXIMUM_TOTAL_CACHE_PAYLOAD_BYTES,
        )


def _validate_cache_json_complexity(
    value: object,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> int:
    """Bound JSON depth and nodes iteratively before downstream consumers inspect it."""

    def children(item: object) -> Iterator[object]:
        if isinstance(item, dict):
            for key, child in item.items():
                yield key
                yield child
        elif isinstance(item, list):
            yield from item

    node_count = 0
    stack: list[tuple[Iterator[object], int]] = [(iter((value,)), 0)]
    while stack:
        iterator, depth = stack[-1]
        try:
            item = next(iterator)
        except StopIteration:
            stack.pop()
            continue
        node_count += 1
        if node_count > MAXIMUM_CACHE_JSON_NODES:
            raise _cache_limit_error("JSON node count per response", MAXIMUM_CACHE_JSON_NODES)
        if depth > MAXIMUM_CACHE_JSON_DEPTH:
            raise _cache_limit_error("JSON nesting depth", MAXIMUM_CACHE_JSON_DEPTH)
        if isinstance(item, str):
            _bounded_utf8_length(
                item,
                subject="JSON string byte size",
                maximum_bytes=MAXIMUM_CACHE_JSON_STRING_BYTES,
            )
        if cancellation_check is not None and node_count % 4_096 == 0:
            cancellation_check()
        if isinstance(item, (dict, list)):
            stack.append((children(item), depth + 1))
    return node_count


def _bounded_utf8_length(value: str, *, subject: str, maximum_bytes: int) -> int:
    """Return strict UTF-8 length or raise the stable cache-limit domain error."""

    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise UnsupportedSchemaError(
            "The recovered TV Time data contained invalid Unicode text. Preserve the extraction "
            "and retry with an updated extractor; do not delete the backup."
        ) from exc
    if size > maximum_bytes:
        raise _cache_limit_error(subject, maximum_bytes)
    return size


def _cache_content_bytes(content: object) -> bytes:
    if content is None:
        return b""
    if isinstance(content, bytes):
        return content
    if isinstance(content, (bytearray, memoryview)):
        return bytes(content)
    if isinstance(content, str):
        return content.encode("utf-8")
    raise UnsupportedSchemaError(
        "DioCache.db contained an unsupported response value type. Preserve the extraction "
        "and check for an app-schema update."
    )


def _parse_cache_json(
    raw_content: bytes,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> tuple[object | None, bool, int]:
    if len(raw_content) > MAXIMUM_CACHE_PAYLOAD_BYTES:
        raise _cache_limit_error("single-response byte size", MAXIMUM_CACHE_PAYLOAD_BYTES)
    try:
        payload = json.loads(raw_content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, False, 0
    except RecursionError as exc:
        raise _cache_limit_error("JSON nesting depth", MAXIMUM_CACHE_JSON_DEPTH) from exc
    nodes = _validate_cache_json_complexity(
        payload,
        cancellation_check=cancellation_check,
    )
    return payload, True, nodes


class _DerivedRowBudget:
    """Bound cache-to-table fan-out without changing record identity semantics."""

    def __init__(self) -> None:
        self._counts: Counter[str] = Counter()
        self._total = 0

    def reserve(self, category: str, count: int) -> None:
        if count <= 0:
            return
        category_total = self._counts[category] + count
        if category_total > MAXIMUM_DERIVED_ROWS_PER_TABLE:
            raise _cache_limit_error(
                f"derived {category} row count",
                MAXIMUM_DERIVED_ROWS_PER_TABLE,
            )
        total = self._total + count
        if total > MAXIMUM_TOTAL_DERIVED_ROWS:
            raise _cache_limit_error(
                "combined derived-row count",
                MAXIMUM_TOTAL_DERIVED_ROWS,
            )
        self._counts[category] = category_total
        self._total = total


class _BoundedCSVCounter:
    """Minimal text sink that rejects a CSV row or file before it is written."""

    def __init__(self) -> None:
        self.total_bytes = 0

    def write(self, value: str) -> int:
        row_bytes = _bounded_utf8_length(
            value,
            subject="analysis CSV row byte size",
            maximum_bytes=MAXIMUM_ANALYSIS_CSV_ROW_BYTES,
        )
        self.total_bytes += row_bytes
        if self.total_bytes > MAXIMUM_ANALYSIS_CSV_BYTES:
            raise _cache_limit_error("analysis CSV file byte size", MAXIMUM_ANALYSIS_CSV_BYTES)
        return len(value)


def _spreadsheet_safe_row(
    row: Mapping[str, object],
    fields: Sequence[str],
) -> dict[str, object]:
    protected: dict[str, object] = {}
    for field in fields:
        value = row.get(field, "")
        text = "" if value is None else str(value)
        _bounded_utf8_length(
            text,
            subject="analysis CSV cell byte size",
            maximum_bytes=MAXIMUM_ANALYSIS_CSV_CELL_BYTES,
        )
        protected[field] = (
            "'" + value
            if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r"))
            else value
        )
    return protected


def _validate_analysis_csv_output(
    rows: Sequence[Mapping[str, object]],
    fields: Sequence[str],
) -> None:
    """Prove one generated CSV fits the sealed-output envelope before creating it."""

    if len(rows) > MAXIMUM_ANALYSIS_CSV_ROWS:
        raise _cache_limit_error("analysis CSV row count", MAXIMUM_ANALYSIS_CSV_ROWS)
    counter = _BoundedCSVCounter()
    writer = csv.DictWriter(counter, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        if not isinstance(row, Mapping):
            raise UnsupportedSchemaError(
                "The recovered TV Time data could not be represented as a bounded private table."
            )
        writer.writerow(_spreadsheet_safe_row(row, fields))


def _validate_csv_escape_metadata(value: object) -> None:
    """Bound analyzer-produced spreadsheet escape coordinates and their strings."""

    if not isinstance(value, Mapping):
        raise UnsupportedSchemaError("Analysis CSV escape metadata had an unsupported format.")
    entries = 0
    for filename, items in value.items():
        if not isinstance(filename, str) or not filename or not isinstance(items, list):
            raise UnsupportedSchemaError("Analysis CSV escape metadata had an unsupported format.")
        _bounded_utf8_length(
            filename,
            subject="analysis CSV escape filename byte size",
            maximum_bytes=1_024,
        )
        entries += len(items)
        if entries > MAXIMUM_CSV_ESCAPE_ENTRIES:
            raise _cache_limit_error(
                "analysis CSV escape-coordinate count",
                MAXIMUM_CSV_ESCAPE_ENTRIES,
            )
        for item in items:
            if not isinstance(item, Mapping) or set(item) != {"row", "field"}:
                raise UnsupportedSchemaError(
                    "Analysis CSV escape metadata had an unsupported format."
                )
            row_number = item.get("row")
            field = item.get("field")
            if (
                not isinstance(row_number, int)
                or isinstance(row_number, bool)
                or row_number < 1
                or row_number > MAXIMUM_ANALYSIS_CSV_ROWS
                or not isinstance(field, str)
                or not field
            ):
                raise UnsupportedSchemaError(
                    "Analysis CSV escape metadata had an unsupported format."
                )
            _bounded_utf8_length(
                field,
                subject="analysis CSV escape field byte size",
                maximum_bytes=1_024,
            )


def _validate_analysis_summary_output(value: Mapping[str, object]) -> None:
    """Keep the versionable analysis marker within native/Python envelopes."""

    _validate_cache_json_complexity(value)
    try:
        payload = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise UnsupportedSchemaError(
            "The private analysis summary could not be encoded safely."
        ) from exc
    if len(payload) > MAXIMUM_ANALYSIS_SUMMARY_BYTES:
        raise _cache_limit_error(
            "analysis-summary byte size",
            MAXIMUM_ANALYSIS_SUMMARY_BYTES,
        )


def _sqlite_limit_error(subject: str, limit: int) -> UnsupportedSchemaError:
    return UnsupportedSchemaError(
        f"A recovered SQLite database exceeded this release's safe {subject} limit "
        f"({limit:,}). Preserve the extraction and retry with an updated extractor; "
        "do not delete the backup."
    )


def _validate_sqlite_schema_limits(connection: sqlite3.Connection) -> None:
    values = connection.execute(
        "SELECT COUNT(*), COALESCE(MAX(length(CAST(name AS BLOB))), 0), "
        "COALESCE(SUM(length(CAST(name AS BLOB))), 0), "
        "COALESCE(SUM(CASE WHEN typeof(name) = 'text' THEN 0 ELSE 1 END), 0) "
        "FROM sqlite_master WHERE type IN ('table','view')"
    ).fetchone()
    if values is None or len(values) != 4:
        raise UnsupportedSchemaError(
            "A recovered SQLite database could not provide safe schema statistics."
        )
    try:
        object_count, largest_name, total_name_bytes, invalid_types = (
            int(value or 0) for value in values
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise UnsupportedSchemaError(
            "A recovered SQLite database returned invalid schema statistics."
        ) from exc
    if min(object_count, largest_name, total_name_bytes, invalid_types) < 0 or invalid_types:
        raise UnsupportedSchemaError(
            "A recovered SQLite database returned invalid schema statistics."
        )
    for subject, observed, limit in (
        ("schema-object count", object_count, MAXIMUM_SQLITE_SCHEMA_OBJECTS),
        ("schema-name byte size", largest_name, MAXIMUM_SQLITE_SCHEMA_NAME_BYTES),
        ("combined schema-name byte size", total_name_bytes, MAXIMUM_SQLITE_SCHEMA_TOTAL_BYTES),
    ):
        if observed > limit:
            raise _sqlite_limit_error(subject, limit)


def _same_sqlite_source(
    before: os.stat_result,
    after: os.stat_result,
) -> bool:
    return stat.S_ISREG(after.st_mode) and all(
        getattr(before, field, None) == getattr(after, field, None)
        for field in _SQLITE_SOURCE_STABLE_FIELDS
    )


def _sqlite_snapshot_sources(
    path: Path,
    *,
    expected_main_metadata: os.stat_result | None = None,
    require_private_source: bool = False,
) -> list[tuple[Path, os.stat_result]]:
    sources: list[tuple[Path, os.stat_result]] = []
    total_bytes = 0
    for suffix in ("", "-wal", "-shm", "-journal"):
        source = path.with_name(path.name + suffix)
        try:
            source.lstat()
        except FileNotFoundError:
            if not suffix:
                raise TVTimeError("A required SQLite database was not found.") from None
            continue
        except OSError as exc:
            raise TVTimeError("A recovered SQLite database could not be inspected safely.") from exc
        try:
            with regular_binary_reader(
                source,
                require_private=require_private_source,
            ) as (_held_source, opened_metadata):
                metadata = opened_metadata
        except UnsafePathError as exc:
            if require_private_source:
                raise
            raise TVTimeError(
                "A recovered SQLite database contained an unsafe file or sidecar."
            ) from exc
        if (
            not suffix
            and expected_main_metadata is not None
            and not _same_sqlite_source(expected_main_metadata, metadata)
        ):
            raise UnsafePathError(
                "A recovered SQLite database changed before its private snapshot."
            )
        if metadata.st_size < 0 or metadata.st_size > MAXIMUM_SQLITE_SNAPSHOT_FILE_BYTES:
            raise _sqlite_limit_error(
                "snapshot-file byte size",
                MAXIMUM_SQLITE_SNAPSHOT_FILE_BYTES,
            )
        total_bytes += metadata.st_size
        if total_bytes > MAXIMUM_SQLITE_SNAPSHOT_TOTAL_BYTES:
            raise _sqlite_limit_error(
                "combined snapshot byte size",
                MAXIMUM_SQLITE_SNAPSHOT_TOTAL_BYTES,
            )
        sources.append((source, metadata))
    return sources


def _copy_sqlite_snapshot_file(
    source: Path,
    source_before: os.stat_result,
    destination: Path,
    *,
    remaining_total_bytes: int,
    require_private_source: bool,
) -> int:
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    destination_flags |= getattr(os, "O_BINARY", 0)
    destination_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    destination_descriptor = -1
    total = 0
    try:
        with regular_binary_reader(
            source,
            require_private=require_private_source,
        ) as (source_handle, opened_source):
            if not _same_sqlite_source(source_before, opened_source):
                raise TVTimeError("A recovered SQLite database changed while it was opened.")
            destination_descriptor = os.open(destination, destination_flags, 0o600)
            if os.name != "nt":
                os.fchmod(destination_descriptor, 0o600)
            require_private_descriptor(destination_descriptor, expected_type=stat.S_IFREG)
            while True:
                chunk = source_handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAXIMUM_SQLITE_SNAPSHOT_FILE_BYTES:
                    raise _sqlite_limit_error(
                        "snapshot-file byte size",
                        MAXIMUM_SQLITE_SNAPSHOT_FILE_BYTES,
                    )
                if total > remaining_total_bytes:
                    raise _sqlite_limit_error(
                        "combined snapshot byte size",
                        MAXIMUM_SQLITE_SNAPSHOT_TOTAL_BYTES,
                    )
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_descriptor, view)
                    if written <= 0:
                        raise TVTimeError("A private SQLite snapshot could not be written safely.")
                    view = view[written:]
            after_destination = os.fstat(destination_descriptor)
            if after_destination.st_size != total:
                raise TVTimeError("A private SQLite snapshot could not be verified safely.")
    except OSError as exc:
        raise TVTimeError("A recovered SQLite database could not be copied safely.") from exc
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
    secure_file(destination)
    return total


@contextmanager
def readonly_sqlite(
    path: Path,
    *,
    expected_main_metadata: os.stat_result | None = None,
    require_private_source: bool = False,
) -> Iterator[sqlite3.Connection]:
    with tempfile.TemporaryDirectory(prefix=".tvtime-sqlite-", dir=path.parent) as temporary:
        snapshot_directory = secure_directory(Path(temporary))
        snapshot = snapshot_directory / path.name

        def copy_snapshot(held_metadata: os.stat_result) -> None:
            sources = _sqlite_snapshot_sources(
                path,
                expected_main_metadata=held_metadata,
                require_private_source=require_private_source,
            )
            copied_bytes = 0
            for source, source_before in sources:
                destination = snapshot_directory / source.name
                copied_bytes += _copy_sqlite_snapshot_file(
                    source,
                    source_before,
                    destination,
                    remaining_total_bytes=MAXIMUM_SQLITE_SNAPSHOT_TOTAL_BYTES - copied_bytes,
                    require_private_source=require_private_source,
                )

        if expected_main_metadata is None:
            with regular_binary_reader(
                path,
                require_private=require_private_source,
            ) as (_held_main, held_metadata):
                copy_snapshot(held_metadata)
        else:
            copy_snapshot(expected_main_metadata)

        connection = sqlite3.connect(snapshot, timeout=0)
        try:
            # Some Apple-provided Python builds omit extension loading entirely.
            # When the API exists, explicitly keep it disabled; when it does not,
            # SQLite extensions cannot be enabled through this connection.
            if hasattr(connection, "enable_load_extension"):
                connection.enable_load_extension(False)
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            if hasattr(connection, "setlimit"):
                connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAXIMUM_CACHE_PAYLOAD_BYTES)
                connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 256)
                connection.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 128)
                connection.setlimit(sqlite3.SQLITE_LIMIT_COMPOUND_SELECT, 16)
            yield connection
        finally:
            connection.close()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sorting_value(item: dict[str, Any], *names: str) -> str:
    wanted = set(names)
    sorting = item.get("sorting")
    if not isinstance(sorting, list):
        return ""
    for entry in sorting:
        if isinstance(entry, dict) and entry.get("id") in wanted:
            return str(entry.get("value") or "")
    return ""


def latest_by_uuid(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for item in items:
        identity = str(item.get("uuid") or json.dumps(item, sort_keys=True))
        previous = selected.get(identity)
        if previous is None or str(item.get("updated_at") or "") >= str(
            previous.get("updated_at") or ""
        ):
            selected[identity] = item
    return list(selected.values())


def latest_watch_events(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate cached page repeats without collapsing genuine rewatches."""

    selected: dict[tuple[str, ...], dict[str, Any]] = {}
    for item in items:
        event_id = str(item.get("id") or "")
        if event_id:
            identity = ("event-id", event_id)
        else:
            identity = (
                "compound",
                str(item.get("uuid") or ""),
                str(item.get("watched_at") or ""),
                str(item.get("entity_type") or ""),
                str(item.get("type") or ""),
            )
            if not any(identity[1:]):
                identity = ("payload", json.dumps(item, sort_keys=True, ensure_ascii=False))
        previous = selected.get(identity)
        if previous is None or str(item.get("updated_at") or "") >= str(
            previous.get("updated_at") or ""
        ):
            selected[identity] = item
    return list(selected.values())


def _is_supported_payload(payload: object) -> bool:
    data = _payload_data(payload)
    if isinstance(data, dict):
        if data.get("type") in {"watch", "list"}:
            return isinstance(data.get("objects"), list)
        return "objects" not in data and {"id", "created_at"} <= data.keys()
    if isinstance(data, list):
        return not data or any(
            isinstance(item, dict) and {"air_date", "show", "number"} <= item.keys()
            for item in data
        )
    return False


def _integer(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def unique_favorites(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: dict[tuple[str, ...], dict[str, Any]] = {}
    for item in items:
        item_type = str(item.get("type") or "")
        stable_id = str(item.get("id") or item.get("uuid") or "")
        if stable_id:
            identity = ("stable-id", item_type, stable_id)
        else:
            identity = (
                "fallback",
                item_type,
                str(item.get("name") or ""),
                str(item.get("created_at") or ""),
            )
        previous = selected.get(identity)
        status = item.get("watch_status") if isinstance(item.get("watch_status"), dict) else {}
        previous_status = (
            previous.get("watch_status")
            if previous is not None and isinstance(previous.get("watch_status"), dict)
            else {}
        )
        score = (
            _integer(status.get("aired_episode_count")),
            _integer(status.get("watched_episode_count")),
            str(item.get("updated_at") or item.get("created_at") or ""),
        )
        previous_score = (
            _integer(previous_status.get("aired_episode_count")),
            _integer(previous_status.get("watched_episode_count")),
            str((previous or {}).get("updated_at") or (previous or {}).get("created_at") or ""),
        )
        if previous is None or score >= previous_score:
            selected[identity] = item
    return list(selected.values())


def episode_identity(row: dict[str, Any]) -> tuple[str, ...]:
    """Identify cached episodes without collapsing distinct records that lack IDs."""

    def identity_text(value: object) -> str:
        return "" if value is None else str(value)

    show_id = identity_text(row.get("show_id"))
    episode_id = identity_text(row.get("episode_id"))
    if episode_id:
        return ("stable-id", show_id, episode_id)

    show_name = identity_text(row.get("show_name"))
    show_key = show_id or show_name
    season = identity_text(row.get("season"))
    episode = identity_text(row.get("episode"))
    if show_key and (season or episode):
        return ("position", show_key, season, episode)

    air_date = identity_text(row.get("air_date"))
    if show_key and air_date:
        return ("air-date", show_key, air_date)

    metadata = (
        show_key,
        season,
        episode,
        identity_text(row.get("episode_name")),
        air_date,
        identity_text(row.get("runtime")),
    )
    if any(metadata):
        return ("metadata", *metadata)
    return ("source", identity_text(row.get("source_id")))


def _payload_data(payload: object) -> object:
    if isinstance(payload, dict) and "data" in payload:
        return payload.get("data")
    return payload


def _filters(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str) and value:
        return [value]
    return []


def _favorite_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in items:
        status = item.get("watch_status") if isinstance(item.get("watch_status"), dict) else {}
        rows.append(
            {
                "uuid": item.get("uuid", ""),
                "id": item.get("id", ""),
                "name": item.get("name", ""),
                "type": item.get("type", ""),
                "status": item.get("status", ""),
                "created_at": item.get("created_at", ""),
                "watched_episode_count": status.get("watched_episode_count", ""),
                "aired_episode_count": status.get("aired_episode_count", ""),
                "is_followed": status.get("is_followed", ""),
                "is_up_to_date": status.get("is_up_to_date", ""),
            }
        )
    return sorted(rows, key=lambda row: str(row["name"]).casefold())


def _preflight_derived_rows(
    payload_records: list[tuple[str, object]],
    *,
    cancellation_check: Callable[[], None] | None,
) -> None:
    """Measure cache fan-out before creating the private analysis staging tree."""

    budget = _DerivedRowBudget()
    for _source_id, payload in payload_records:
        if cancellation_check is not None:
            cancellation_check()
        data = _payload_data(payload)
        if isinstance(data, dict) and data.get("type") in {"watch", "list"}:
            objects = data.get("objects")
            if isinstance(objects, list):
                object_count = sum(isinstance(item, dict) for item in objects)
                if data.get("type") == "watch":
                    category = "watch-event"
                elif data.get("id") == "favorite-movies":
                    category = "favorite-movie"
                elif data.get("id") == "favorite-series":
                    category = "favorite-show"
                else:
                    category = "library"
                budget.reserve(category, object_count)
        if isinstance(data, list):
            episode_count = sum(
                isinstance(item, dict) and {"air_date", "show", "number"} <= item.keys()
                for item in data
            )
            budget.reserve("episode-cache", episode_count)


def _analyze_extraction(
    *,
    extraction_directory: Path,
    include_raw_cache: bool = False,
    cancellation_check: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Create normalized private tables from an extracted TV Time container."""

    if cancellation_check is not None:
        cancellation_check()
    extraction = validate_extraction_directory(extraction_directory)
    run_state = read_json_regular(
        safe_join(extraction, "metadata", "run_state.json"),
        maximum_bytes=MAXIMUM_COMPLETION_MARKER_BYTES,
        require_private=True,
    )
    if not isinstance(run_state, dict):
        raise TVTimeError("The private extraction completion marker had an unsupported format.")
    expected_source_snapshot = source_snapshot_from_mapping(run_state.get("source_snapshot"))
    source_snapshot = reconcile_raw_tree(
        extraction,
        expected=expected_source_snapshot,
        cancellation_check=cancellation_check,
    )
    raw = safe_join(extraction, "raw")
    regular_files = sorted(iter_regular_files(raw), key=lambda path: str(path.relative_to(raw)))
    if cancellation_check is not None:
        cancellation_check()
    app_root = safe_join(raw, PRIMARY_DOMAIN)
    cache_db = safe_join(app_root, "Documents", "DioCache.db")
    if not cache_db.is_file():
        raise AppDataMissingError(
            "The selected TV Time app data did not contain the required cache database."
        )

    cache_index: list[dict[str, Any]] = []
    unique_hashes: dict[str, str] = {}
    payload_records: list[tuple[str, object]] = []
    cache_exports: list[tuple[str, object, bool]] = []
    with readonly_sqlite(cache_db, require_private_source=True) as connection:
        try:
            quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            if quick_check != "ok":
                raise TVTimeError(
                    "DioCache.db did not pass SQLite quick_check; refusing incomplete analysis."
                )
            available_columns = {
                str(row[1]).casefold() for row in connection.execute("PRAGMA table_info(cache_dio)")
            }
            required_columns = {"key", "subkey", "content", "statuscode"}
            missing_columns = sorted(required_columns - available_columns)
            if missing_columns:
                raise UnsupportedSchemaError(
                    "DioCache.db uses an unsupported cache_dio schema; missing required columns: "
                    + ", ".join(missing_columns)
                )
            _validate_cache_table_limits(connection)
            with closing(
                connection.execute(
                    "SELECT key, subKey, content, statusCode FROM cache_dio ORDER BY key, subKey"
                )
            ) as cache_rows:
                total_json_nodes = 0
                for key, subkey, content, status_code in cache_rows:
                    if cancellation_check is not None:
                        cancellation_check()
                    raw_content = _cache_content_bytes(content)
                    source_id = private_source_id(key, subkey)
                    digest = sha256_bytes(raw_content)
                    duplicate_of = unique_hashes.get(digest, "")
                    unique_hashes.setdefault(digest, source_id)
                    exported_file = ""
                    payload, json_valid, node_count = _parse_cache_json(
                        raw_content,
                        cancellation_check=cancellation_check,
                    )
                    total_json_nodes += node_count
                    if total_json_nodes > MAXIMUM_TOTAL_CACHE_JSON_NODES:
                        raise _cache_limit_error(
                            "combined JSON node count",
                            MAXIMUM_TOTAL_CACHE_JSON_NODES,
                        )
                    if json_valid:
                        payload_records.append((source_id, payload))
                        if include_raw_cache:
                            exported_file = f"{source_id}.json"
                            cache_exports.append((exported_file, payload, True))
                    elif include_raw_cache:
                        exported_file = f"{source_id}.bin"
                        cache_exports.append((exported_file, raw_content, False))

                    data = _payload_data(payload)
                    if isinstance(data, dict):
                        shape = "object"
                        data_type = str(data.get("type") or "")
                        objects = data.get("objects")
                        object_count: int | str = len(objects) if isinstance(objects, list) else ""
                    elif isinstance(data, list):
                        shape = "array"
                        data_type = ""
                        object_count = len(data)
                    else:
                        shape = type(data).__name__
                        data_type = ""
                        object_count = ""
                    cache_index.append(
                        {
                            "source_id": source_id,
                            "status_code": status_code,
                            "bytes": len(raw_content),
                            "sha256": digest,
                            "duplicate_of": duplicate_of,
                            "json_valid": json_valid,
                            "shape": shape,
                            "data_type": data_type,
                            "object_count": object_count,
                            "exported_file": exported_file,
                        }
                    )
        except sqlite3.Error as exc:
            raise TVTimeError("DioCache.db could not be read safely.") from exc

    recognized_payloads = sum(_is_supported_payload(payload) for _, payload in payload_records)
    if cache_index and not recognized_payloads:
        raise UnsupportedSchemaError(
            "The cache contains data, but no supported TV Time payloads were recognized. "
            "Keep the extraction and check for an app-schema update."
        )
    parser_status = "empty" if not cache_index else "recognized"
    _preflight_derived_rows(
        payload_records,
        cancellation_check=cancellation_check,
    )

    layout = prepare_analysis_layout(extraction)
    analysis = layout.staging_root
    responses = safe_join(analysis, "cache_responses")
    csv_escape_metadata: dict[str, list[dict[str, int | str]]] = {}

    def write_analysis_csv(
        filename: str,
        rows: Sequence[Mapping[str, object]],
        fields: list[str],
    ) -> None:
        _validate_analysis_csv_output(rows, fields)
        escaped = write_csv_private(analysis / filename, rows, fields)
        if escaped:
            csv_escape_metadata[filename] = escaped
            _validate_csv_escape_metadata(csv_escape_metadata)

    if include_raw_cache:
        secure_directory(responses)
        for filename, value, is_json in cache_exports:
            response_path = safe_join(responses, filename)
            if is_json:
                write_json_private(response_path, value)
            else:
                write_bytes_private(response_path, value)

    write_analysis_csv(
        "cache_index.csv",
        cache_index,
        [
            "source_id",
            "status_code",
            "bytes",
            "sha256",
            "duplicate_of",
            "json_valid",
            "shape",
            "data_type",
            "object_count",
            "exported_file",
        ],
    )

    watch_events: list[dict[str, Any]] = []
    list_objects: list[dict[str, Any]] = []
    favorite_movies: list[dict[str, Any]] = []
    favorite_shows: list[dict[str, Any]] = []
    episode_rows: list[dict[str, Any]] = []
    profile_payloads_detected = 0
    derived_rows = _DerivedRowBudget()

    for source_id, payload in payload_records:
        if cancellation_check is not None:
            cancellation_check()
        data = _payload_data(payload)
        if isinstance(data, dict) and data.get("type") == "watch":
            objects = data.get("objects")
            if isinstance(objects, list):
                object_dicts = [item for item in objects if isinstance(item, dict)]
                derived_rows.reserve("watch-event", len(object_dicts))
                watch_events.extend(object_dicts)
        if isinstance(data, dict) and data.get("type") == "list":
            objects = data.get("objects")
            if isinstance(objects, list):
                object_dicts = [item for item in objects if isinstance(item, dict)]
                if data.get("id") == "favorite-movies":
                    derived_rows.reserve("favorite-movie", len(object_dicts))
                    favorite_movies.extend(object_dicts)
                elif data.get("id") == "favorite-series":
                    derived_rows.reserve("favorite-show", len(object_dicts))
                    favorite_shows.extend(object_dicts)
                else:
                    derived_rows.reserve("library", len(object_dicts))
                    list_objects.extend(object_dicts)
        if isinstance(data, dict) and "objects" not in data and {"id", "created_at"} <= data.keys():
            profile_payloads_detected += 1
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict) or not {"air_date", "show", "number"} <= item.keys():
                    continue
                derived_rows.reserve("episode-cache", 1)
                show = item.get("show") if isinstance(item.get("show"), dict) else {}
                episode_rows.append(
                    {
                        "source_id": source_id,
                        "episode_id": item.get("id", ""),
                        "show_id": show.get("id", ""),
                        "show_name": show.get("name", ""),
                        "season": item.get("season_number", ""),
                        "episode": item.get("number", ""),
                        "episode_name": item.get("name", ""),
                        "air_date": item.get("air_date", ""),
                        "seen": item.get("seen", ""),
                        "seen_date": item.get("seen_date", ""),
                        "is_watched": item.get("is_watched", ""),
                        "runtime": item.get("runtime", ""),
                    }
                )

    watch_events = latest_watch_events(watch_events)
    list_objects = latest_by_uuid(list_objects)
    favorite_movies = unique_favorites(favorite_movies)
    favorite_shows = unique_favorites(favorite_shows)

    unique_episode_rows: dict[tuple[str, ...], dict[str, Any]] = {}
    for row in episode_rows:
        identity = episode_identity(row)
        previous = unique_episode_rows.get(identity)
        score = (bool(row["seen"]), str(row["seen_date"] or ""))
        previous_score = (
            bool((previous or {}).get("seen")),
            str((previous or {}).get("seen_date") or ""),
        )
        if previous is None or score >= previous_score:
            unique_episode_rows[identity] = row
    episodes_unique = list(unique_episode_rows.values())

    movie_library: list[dict[str, Any]] = []
    series_library: list[dict[str, Any]] = []
    for item in list_objects:
        meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
        extended = item.get("extended") if isinstance(item.get("extended"), dict) else {}
        filters = _filters(item.get("filter"))
        if item.get("entity_type") == "movie":
            watched_at = item.get("watched_at") or sorting_value(item, "watched_date", "watch_date")
            movie_library.append(
                {
                    "uuid": item.get("uuid", ""),
                    "name": meta.get("name", ""),
                    "imdb_id": meta.get("imdb_id", ""),
                    "first_release_date": meta.get("first_release_date", ""),
                    "library_status": "watched"
                    if watched_at
                    else (filters[0] if filters else "saved"),
                    "watched_at": watched_at,
                    "followed_at": sorting_value(item, "follow_date"),
                    "runtime_seconds": meta.get("runtime", ""),
                    "genres": " | ".join(str(value) for value in meta.get("genres") or []),
                    "filters": " | ".join(filters),
                    "is_watched": extended.get("is_watched", ""),
                    "created_at": item.get("created_at", ""),
                    "updated_at": item.get("updated_at", ""),
                }
            )
        elif item.get("entity_type") == "series":
            series_library.append(
                {
                    "uuid": item.get("uuid", ""),
                    "series_id": meta.get("id", ""),
                    "name": meta.get("name", ""),
                    "country": meta.get("country", ""),
                    "is_ended": meta.get("is_ended", ""),
                    "followed_at": sorting_value(item, "follow_date"),
                    "last_watch_date": sorting_value(item, "watch_date", "watched_date"),
                    "filters": " | ".join(filters),
                    "created_at": item.get("created_at", ""),
                    "updated_at": item.get("updated_at", ""),
                }
            )

    watched_movies = [row for row in movie_library if row["watched_at"]]
    movie_watchlist = [row for row in movie_library if not row["watched_at"]]
    movie_by_uuid = {str(row["uuid"]): row for row in movie_library}
    named_watch_events = [
        {**event, "movie_name": movie_by_uuid.get(str(event.get("uuid")), {}).get("name", "")}
        for event in watch_events
    ]

    watch_fields = [
        "uuid",
        "entity_type",
        "type",
        "watched_at",
        "runtime",
        "created_at",
        "updated_at",
    ]
    write_analysis_csv("watch_events.csv", watch_events, watch_fields)
    write_analysis_csv(
        "watch_events_named.csv",
        named_watch_events,
        ["uuid", "movie_name", *watch_fields[1:]],
    )
    movie_fields = [
        "uuid",
        "name",
        "imdb_id",
        "first_release_date",
        "library_status",
        "watched_at",
        "followed_at",
        "runtime_seconds",
        "genres",
        "filters",
        "is_watched",
        "created_at",
        "updated_at",
    ]
    write_analysis_csv(
        "movie_library.csv",
        sorted(movie_library, key=lambda row: str(row["name"]).casefold()),
        movie_fields,
    )
    write_analysis_csv(
        "watched_movies.csv",
        sorted(watched_movies, key=lambda row: str(row["watched_at"])),
        movie_fields,
    )
    write_analysis_csv(
        "movie_watchlist.csv",
        sorted(movie_watchlist, key=lambda row: str(row["name"]).casefold()),
        movie_fields,
    )
    write_analysis_csv(
        "series_library.csv",
        sorted(series_library, key=lambda row: str(row["name"]).casefold()),
        [
            "uuid",
            "series_id",
            "name",
            "country",
            "is_ended",
            "followed_at",
            "last_watch_date",
            "filters",
            "created_at",
            "updated_at",
        ],
    )
    favorite_fields = [
        "uuid",
        "id",
        "name",
        "type",
        "status",
        "created_at",
        "watched_episode_count",
        "aired_episode_count",
        "is_followed",
        "is_up_to_date",
    ]
    write_analysis_csv("favorite_movies.csv", _favorite_rows(favorite_movies), favorite_fields)
    write_analysis_csv("favorite_shows.csv", _favorite_rows(favorite_shows), favorite_fields)
    episode_fields = [
        "source_id",
        "episode_id",
        "show_id",
        "show_name",
        "season",
        "episode",
        "episode_name",
        "air_date",
        "seen",
        "seen_date",
        "is_watched",
        "runtime",
    ]
    write_analysis_csv("episode_cache.csv", episode_rows, episode_fields)
    write_analysis_csv(
        "episode_cache_unique.csv",
        sorted(
            episodes_unique,
            key=lambda row: (
                str(row["show_name"]).casefold(),
                _integer(row["season"]),
                _integer(row["episode"]),
            ),
        ),
        episode_fields,
    )

    sqlite_rows: list[dict[str, Any]] = []
    for path in regular_files:
        if cancellation_check is not None:
            cancellation_check()
        try:
            with regular_binary_reader(
                path,
                require_private=True,
            ) as (handle, database_metadata):
                magic = bytearray()
                while len(magic) < 16:
                    chunk = handle.read(16 - len(magic))
                    if not chunk:
                        break
                    magic.extend(chunk)
                if bytes(magic) != b"SQLite format 3\x00":
                    continue
                with readonly_sqlite(
                    path,
                    expected_main_metadata=database_metadata,
                    require_private_source=True,
                ) as connection:
                    integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
                    _validate_sqlite_schema_limits(connection)
                    objects = [
                        str(row[0])
                        for row in connection.execute(
                            "SELECT name FROM sqlite_master "
                            "WHERE type IN ('table','view') ORDER BY name"
                        )
                    ]
        except (UnsafePathError, UnsupportedSchemaError):
            raise
        except (sqlite3.Error, TVTimeError) as exc:
            message = str(exc)
            integrity = (
                "not_checked_custom_IDBKEY"
                if "no such collation sequence: IDBKEY" in message
                else "ERROR: database inspection failed"
            )
            objects = []
        sqlite_rows.append(
            {
                "relative_path": str(path.relative_to(raw)),
                "bytes": database_metadata.st_size,
                "quick_check": integrity,
                "schema_objects": " | ".join(objects),
            }
        )
    write_analysis_csv(
        "sqlite_integrity.csv",
        sqlite_rows,
        ["relative_path", "bytes", "quick_check", "schema_objects"],
    )

    plist_rows: list[dict[str, Any]] = []
    for path in (path for path in regular_files if path.suffix.casefold() == ".plist"):
        if cancellation_check is not None:
            cancellation_check()
        try:
            with regular_binary_reader(
                path,
                require_private=True,
            ) as (handle, plist_metadata):
                if plist_metadata.st_size > MAXIMUM_PLIST_BYTES:
                    raise _cache_limit_error("property-list byte size", MAXIMUM_PLIST_BYTES)
                plist_payload = bytearray()
                while len(plist_payload) < plist_metadata.st_size:
                    chunk = handle.read(
                        min(1024 * 1024, plist_metadata.st_size - len(plist_payload))
                    )
                    if not chunk:
                        break
                    plist_payload.extend(chunk)
                if len(plist_payload) != plist_metadata.st_size:
                    raise UnsafePathError("A recovered property list changed while it was read.")
                value = plistlib.loads(bytes(plist_payload))
            keys = sorted(map(str, value.keys())) if isinstance(value, dict) else []
            for key in keys:
                _bounded_utf8_length(
                    key,
                    subject="property-list key byte size",
                    maximum_bytes=MAXIMUM_ANALYSIS_CSV_CELL_BYTES,
                )
            plist_rows.append(
                {
                    "relative_path": str(path.relative_to(raw)),
                    "format": type(value).__name__,
                    "top_level_keys": " | ".join(keys),
                }
            )
        except (UnsafePathError, UnsupportedSchemaError):
            raise
        except Exception as exc:
            plist_rows.append(
                {
                    "relative_path": str(path.relative_to(raw)),
                    "format": f"ERROR: {type(exc).__name__}",
                    "top_level_keys": "",
                }
            )
    write_analysis_csv(
        "plist_key_inventory.csv",
        plist_rows,
        ["relative_path", "format", "top_level_keys"],
    )

    summary: dict[str, Any] = {
        "dio_cache_quick_check": quick_check,
        "parser_status": parser_status,
        "recognized_payloads": recognized_payloads,
        "cache_rows": len(cache_index),
        "unique_cache_payloads": len(unique_hashes),
        "raw_cache_exported": include_raw_cache,
        "profile_payloads_detected_not_exported": profile_payloads_detected,
        "watch_events": len(watch_events),
        "movie_library": len(movie_library),
        "watched_movies": len(watched_movies),
        "movie_watchlist": len(movie_watchlist),
        "watch_events_with_titles": sum(
            has_display_text(row["movie_name"]) for row in named_watch_events
        ),
        "series_library": len(series_library),
        "favorite_movies": len(favorite_movies),
        "favorite_shows": len(favorite_shows),
        "episode_cache_rows": len(episode_rows),
        "episode_cache_unique": len(episodes_unique),
        "sqlite_databases": len(sqlite_rows),
        "sqlite_integrity": dict(Counter(row["quick_check"] for row in sqlite_rows)),
        "plist_files": len(plist_rows),
        "csv_spreadsheet_escaped_cells": csv_escape_metadata,
    }
    _validate_csv_escape_metadata(csv_escape_metadata)
    _validate_analysis_summary_output(summary)
    write_json_private(analysis / "analysis_summary.json", summary)
    if cancellation_check is not None:
        cancellation_check()
    reconcile_raw_tree(
        extraction,
        expected=source_snapshot,
        cancellation_check=cancellation_check,
    )
    promote_directory_no_replace_atomic(analysis, layout.final_root, durable=True)
    secure_directory(layout.final_root)
    return summary


def analyze_extraction(
    *,
    extraction_directory: Path,
    include_raw_cache: bool = False,
    cancellation_check: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Analyze a complete extraction and classify destination exhaustion consistently."""

    try:
        with anchored_existing_extraction_root(extraction_directory) as anchored_extraction:
            return _analyze_extraction(
                extraction_directory=anchored_extraction,
                include_raw_cache=include_raw_cache,
                cancellation_check=cancellation_check,
            )
    except OSError as exc:
        if is_insufficient_space_error(exc):
            raise insufficient_space_error() from exc
        raise
