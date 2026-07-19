from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import json
import os
import sqlite3
import stat
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from .analyze import (
    MAXIMUM_ANALYSIS_CSV_BYTES,
    MAXIMUM_ANALYSIS_CSV_CELL_BYTES,
    MAXIMUM_ANALYSIS_CSV_ROW_BYTES,
    MAXIMUM_ANALYSIS_CSV_ROWS,
    MAXIMUM_ANALYSIS_SUMMARY_BYTES,
    MAXIMUM_CSV_ESCAPE_ENTRIES,
    MAXIMUM_TOTAL_CACHE_JSON_NODES,
    _bounded_utf8_length,
    _cache_content_bytes,
    _cache_limit_error,
    _parse_cache_json,
    _validate_analysis_csv_output,
    _validate_analysis_summary_output,
    _validate_cache_json_complexity,
    _validate_cache_table_limits,
    _validate_csv_escape_metadata,
    readonly_sqlite,
)
from .errors import (
    OutputExistsError,
    RecoveryCancelled,
    TVTimeError,
    UnsafePathError,
    UnsupportedSchemaError,
    insufficient_space_error,
    is_insufficient_space_error,
)
from .extract import (
    EXTRACTION_RUN_STATE_CONTRACT,
    EXTRACTION_RUN_STATE_SCHEMA_VERSION,
    PRIMARY_DOMAIN,
    RELATED_PLUGIN_DOMAIN_PREFIX,
    TVTIME_BUNDLE_ID,
)
from .integrity import (
    INVENTORY_FIELDS,
    MAXIMUM_CONTRACT_INTEGER,
    MAXIMUM_INVENTORY_BYTES,
    SourceSnapshot,
    reconcile_raw_tree,
    source_snapshot_from_mapping,
)
from .safety import (
    MAXIMUM_COMPLETION_MARKER_BYTES,
    anchored_existing_extraction_root,
    no_link_absolute_path,
    promote_directory_no_replace_atomic,
    read_regular_bytes,
    regular_binary_reader,
    regular_text_reader,
    require_private_descriptor,
    require_private_path,
    safe_domain_component,
    safe_join,
    safe_manifest_relative_path,
    sanitize_public_url,
    secure_directory,
    validate_extraction_directory,
    validate_file_id,
    write_csv_private,
    write_json_private_atomic,
    write_text_private,
)
from .visual_report import (
    HTML_REPORT_FILENAME,
    PDF_REPORT_FILENAME,
    build_visual_report_model,
    has_display_text,
    render_markdown_report,
    write_visual_reports,
)

RECOVERY_STATE_SCHEMA_VERSION = 2
RECOVERY_STATE_CONTRACT = "tvtime-recovery-state-v0.2"
ANALYSIS_SUMMARY_CONTRACT = "tvtime-analysis-summary-v0.2"

ANALYSIS_SUMMARY_FIELDS = frozenset(
    {
        "dio_cache_quick_check",
        "parser_status",
        "recognized_payloads",
        "cache_rows",
        "unique_cache_payloads",
        "raw_cache_exported",
        "profile_payloads_detected_not_exported",
        "watch_events",
        "movie_library",
        "watched_movies",
        "movie_watchlist",
        "watch_events_with_titles",
        "series_library",
        "favorite_movies",
        "favorite_shows",
        "episode_cache_rows",
        "episode_cache_unique",
        "sqlite_databases",
        "sqlite_integrity",
        "plist_files",
        "csv_spreadsheet_escaped_cells",
        "schema_version",
        "contract",
        "status",
    }
)
PRE_REPORT_ANALYSIS_SUMMARY_FIELDS = ANALYSIS_SUMMARY_FIELDS - {
    "schema_version",
    "contract",
    "status",
}
ANALYSIS_COUNT_FIELDS = (
    "recognized_payloads",
    "cache_rows",
    "unique_cache_payloads",
    "profile_payloads_detected_not_exported",
    "watch_events",
    "movie_library",
    "watched_movies",
    "movie_watchlist",
    "watch_events_with_titles",
    "series_library",
    "favorite_movies",
    "favorite_shows",
    "episode_cache_rows",
    "episode_cache_unique",
    "sqlite_databases",
    "plist_files",
)
EXTRACTION_SUMMARY_FIELDS = frozenset(
    {
        "bundle_id",
        "domains",
        "files_expected",
        "files_extracted",
        "failures",
        "bytes_extracted",
        "selected_declared_bytes",
        "size_discrepancies",
        "decrypted_manifest_included",
        "completed_utc",
    }
)
RUN_STATE_FIELDS = frozenset(
    {
        "schema_version",
        "contract",
        "status",
        "completed_utc",
        "files_expected",
        "files_extracted",
        "bytes_extracted",
        "selected_declared_bytes",
        "size_discrepancy_count",
        "source_snapshot",
    }
)

# Human-readable output has a tighter envelope than normalized CSV analysis:
# rendering tens of thousands of table rows remains useful, while allowing an
# untrusted cache to request an effectively unbounded HTML/PDF is not. Recovery
# analysis is preserved when this ceiling is reached.
MAXIMUM_REPORT_TABLE_ROWS = 25_000
MAXIMUM_TOTAL_REPORT_TABLE_ROWS = 50_000
MAXIMUM_REPORT_INVENTORY_ROWS = 100_000
MAXIMUM_REPORT_DERIVED_ROWS = 100_000
MAXIMUM_IMAGE_CACHE_ROWS = 25_000
MAXIMUM_IMAGE_CACHE_CELL_BYTES = 256 * 1024
MAXIMUM_IMAGE_CACHE_TOTAL_BYTES = 16 * 1024 * 1024
MAXIMUM_IMAGE_TOKEN_BYTES = 64 * 1024
MAXIMUM_REPORT_RENDER_INPUT_BYTES = 8 * 1024 * 1024
MAXIMUM_REPORT_ARTIFACT_BYTES = 64 * 1024 * 1024
MAXIMUM_DOMAINS_BYTES = 32 * 1024

_IMAGE_CACHE_COLUMNS = ("_id", "url", "relativePath", "validTill", "touched", "length")

_BOUND_ARTIFACTS: tuple[tuple[str, str], ...] = (
    ("extraction_run_state", "metadata/run_state.json"),
    ("extraction_inventory", "metadata/inventory.csv"),
    ("extraction_summary", "metadata/summary.json"),
    ("extraction_domains", "metadata/domains.txt"),
    ("analysis_summary", "analysis/analysis_summary.json"),
    ("cache_index", "analysis/cache_index.csv"),
    ("movie_library", "analysis/movie_library.csv"),
    ("watch_events", "analysis/watch_events.csv"),
    ("episode_cache", "analysis/episode_cache.csv"),
    ("sqlite_integrity", "analysis/sqlite_integrity.csv"),
    ("plist_key_inventory", "analysis/plist_key_inventory.csv"),
    ("series_library", "analysis/series_library.csv"),
    ("watched_movies", "analysis/watched_movies.csv"),
    ("movie_watchlist", "analysis/movie_watchlist.csv"),
    ("favorite_shows", "analysis/favorite_shows.csv"),
    ("favorite_movies", "analysis/favorite_movies.csv"),
    ("episode_cache_unique", "analysis/episode_cache_unique.csv"),
    ("watch_events_named", "analysis/watch_events_named.csv"),
    ("trailer_references", "analysis/trailer_references.csv"),
    ("media_url_inventory", "analysis/media_url_inventory.csv"),
    ("image_cache_references", "analysis/image_cache_references.csv"),
    ("markdown_report", "analysis/TVTime-Recovered-Data.md"),
    ("html_report", f"analysis/{HTML_REPORT_FILENAME}"),
)

_SEALED_METADATA_FILENAMES = frozenset(
    {
        "domains.txt",
        "inventory.csv",
        "run_state.json",
        "summary.json",
    }
)

_PRE_REPORT_ANALYSIS_FILENAMES = frozenset(
    {
        "analysis_summary.json",
        "cache_index.csv",
        "episode_cache.csv",
        "episode_cache_unique.csv",
        "favorite_movies.csv",
        "favorite_shows.csv",
        "movie_library.csv",
        "movie_watchlist.csv",
        "plist_key_inventory.csv",
        "series_library.csv",
        "sqlite_integrity.csv",
        "watch_events.csv",
        "watch_events_named.csv",
        "watched_movies.csv",
    }
)

_PRE_REPORT_CSV_FIELDS: dict[str, tuple[str, ...]] = {
    "cache_index.csv": (
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
    ),
    "movie_library.csv": (
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
    ),
    "watch_events.csv": (
        "uuid",
        "entity_type",
        "type",
        "watched_at",
        "runtime",
        "created_at",
        "updated_at",
    ),
    "episode_cache.csv": (
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
    ),
    "sqlite_integrity.csv": ("relative_path", "bytes", "quick_check", "schema_objects"),
    "plist_key_inventory.csv": ("relative_path", "format", "top_level_keys"),
    "series_library.csv": (
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
    ),
    "watched_movies.csv": (
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
    ),
    "movie_watchlist.csv": (
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
    ),
    "favorite_shows.csv": (
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
    ),
    "favorite_movies.csv": (
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
    ),
    "episode_cache_unique.csv": (
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
    ),
    "watch_events_named.csv": (
        "uuid",
        "movie_name",
        "entity_type",
        "type",
        "watched_at",
        "runtime",
        "created_at",
        "updated_at",
    ),
}

_VISUAL_REPORT_INPUT_FILENAMES = frozenset(
    {
        "series_library.csv",
        "watched_movies.csv",
        "movie_watchlist.csv",
        "favorite_shows.csv",
        "favorite_movies.csv",
        "episode_cache_unique.csv",
        "watch_events_named.csv",
    }
)


def _sealed_analysis_filenames(pdf_status: str) -> frozenset[str]:
    if pdf_status not in {"generated", "omitted"}:
        raise TVTimeError("The private PDF report had an unsupported completion status.")
    names = {
        PurePosixPath(relative_path).name
        for _artifact_id, relative_path in _BOUND_ARTIFACTS
        if PurePosixPath(relative_path).parts[0] == "analysis"
    }
    # recovery_state.json authenticates the other artifacts and therefore cannot
    # bind its own bytes. Exact directory membership handles this one intentional
    # self-marker exception explicitly.
    names.add("recovery_state.json")
    if pdf_status == "generated":
        names.add(PDF_REPORT_FILENAME)
    return frozenset(names)


def _exact_private_directory_membership(
    directory: Path,
    *,
    expected_names: frozenset[str],
    label: str,
    cancellation_check: Callable[[], None] | None = None,
) -> None:
    """Fail closed unless one private directory contains exactly regular approved files."""

    if any(not name or "/" in name or "\\" in name for name in expected_names):
        raise RuntimeError("The sealed recovery membership allowlist was invalid.")
    if cancellation_check is not None:
        cancellation_check()
    directory_before = require_private_path(directory, expected_type=stat.S_IFDIR)
    observed: set[str] = set()

    if os.name == "nt":
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if cancellation_check is not None:
                        cancellation_check()
                    metadata = entry.stat(follow_symlinks=False)
                    if entry.name not in expected_names:
                        raise TVTimeError(
                            f"The private {label} directory did not have exact sealed membership."
                        )
                    if not stat.S_ISREG(metadata.st_mode):
                        raise UnsafePathError(
                            f"The private {label} directory contained an unsafe artifact type."
                        )
                    require_private_path(directory / entry.name, expected_type=stat.S_IFREG)
                    observed.add(entry.name)
        except TVTimeError:
            raise
        except OSError as exc:
            raise UnsafePathError(
                f"The private {label} directory could not be enumerated safely."
            ) from exc
        directory_after = require_private_path(directory, expected_type=stat.S_IFDIR)
        if (directory_before.st_dev, directory_before.st_ino) != (
            directory_after.st_dev,
            directory_after.st_ino,
        ):
            raise UnsafePathError(
                f"The private {label} directory changed during membership validation."
            )
    else:
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        file_flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        directory_descriptor = -1
        try:
            directory_descriptor = os.open(directory, directory_flags)
            opened_directory = os.fstat(directory_descriptor)
            if (directory_before.st_dev, directory_before.st_ino) != (
                opened_directory.st_dev,
                opened_directory.st_ino,
            ):
                raise UnsafePathError(f"The private {label} directory changed while it was opened.")
            require_private_descriptor(directory_descriptor, expected_type=stat.S_IFDIR)
            with os.scandir(directory_descriptor) as entries:
                for entry in entries:
                    if cancellation_check is not None:
                        cancellation_check()
                    metadata = entry.stat(follow_symlinks=False)
                    if entry.name not in expected_names:
                        raise TVTimeError(
                            f"The private {label} directory did not have exact sealed membership."
                        )
                    if not stat.S_ISREG(metadata.st_mode):
                        raise UnsafePathError(
                            f"The private {label} directory contained an unsafe artifact type."
                        )
                    child_descriptor = -1
                    try:
                        child_descriptor = os.open(
                            entry.name,
                            file_flags,
                            dir_fd=directory_descriptor,
                        )
                        opened_child = os.fstat(child_descriptor)
                        if (
                            metadata.st_dev,
                            metadata.st_ino,
                        ) != (opened_child.st_dev, opened_child.st_ino):
                            raise UnsafePathError(
                                "A private recovery artifact changed during membership validation."
                            )
                        require_private_descriptor(
                            child_descriptor,
                            expected_type=stat.S_IFREG,
                        )
                        path_after = os.stat(
                            entry.name,
                            dir_fd=directory_descriptor,
                            follow_symlinks=False,
                        )
                        if (opened_child.st_dev, opened_child.st_ino) != (
                            path_after.st_dev,
                            path_after.st_ino,
                        ):
                            raise UnsafePathError(
                                "A private recovery artifact changed during membership validation."
                            )
                    finally:
                        if child_descriptor >= 0:
                            os.close(child_descriptor)
                    observed.add(entry.name)
            directory_after = os.fstat(directory_descriptor)
            stable_fields = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_uid",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if any(
                getattr(opened_directory, field) != getattr(directory_after, field)
                for field in stable_fields
            ):
                raise UnsafePathError(
                    f"The private {label} directory changed during membership validation."
                )
            path_after = directory.lstat()
            if (directory_after.st_dev, directory_after.st_ino) != (
                path_after.st_dev,
                path_after.st_ino,
            ):
                raise UnsafePathError(
                    f"The private {label} directory was replaced during membership validation."
                )
        except (TVTimeError, UnsafePathError):
            raise
        except OSError as exc:
            raise UnsafePathError(
                f"The private {label} directory could not be enumerated safely."
            ) from exc
        finally:
            if directory_descriptor >= 0:
                os.close(directory_descriptor)

    if observed != expected_names:
        raise TVTimeError(f"The private {label} directory did not have exact sealed membership.")


def _required_nonnegative_int(value: dict[str, Any], key: str, *, label: str) -> int:
    item = value.get(key)
    if (
        not isinstance(item, int)
        or isinstance(item, bool)
        or item < 0
        or item > MAXIMUM_CONTRACT_INTEGER
    ):
        raise TVTimeError(f"The private {label} had an unsupported format.")
    return item


def _private_artifact_binding(
    path: Path,
    *,
    artifact_id: str,
    relative_path: str,
    cancellation_check: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Bind one already-written private regular file without following a link."""

    digest = hashlib.sha256()
    byte_count = 0
    with regular_binary_reader(path, require_private=True) as (handle, opened):
        if opened.st_size <= 0:
            raise TVTimeError("A required private recovery artifact was empty.")
        if cancellation_check is not None:
            cancellation_check()
        while True:
            if cancellation_check is not None:
                cancellation_check()
            chunk = os.read(handle.fileno(), 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            byte_count += len(chunk)
    if byte_count != opened.st_size or byte_count <= 0:
        raise TVTimeError("A required private recovery artifact had an invalid byte size.")
    return {
        "id": artifact_id,
        "relative_path": relative_path,
        "bytes": byte_count,
        "sha256": digest.hexdigest(),
    }


def _canonical_inventory_decimal(value: object) -> int:
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdecimal():
        raise TVTimeError("The private extraction inventory had an unsupported numeric value.")
    parsed = int(value)
    if str(parsed) != value or parsed > MAXIMUM_CONTRACT_INTEGER:
        raise TVTimeError("The private extraction inventory had an unsupported numeric value.")
    return parsed


def _inventory_aggregate(
    rows: Sequence[Mapping[str, str]],
    *,
    source_snapshot: SourceSnapshot,
) -> tuple[dict[str, int], list[dict[str, Any]]]:
    previous_key: tuple[str, str] | None = None
    actual_bytes = 0
    declared_bytes = 0
    discrepancies: list[dict[str, Any]] = []
    for row in rows:
        try:
            if row["file_id"] != validate_file_id(row["file_id"]):
                raise ValueError("noncanonical file identifier")
            if row["domain"] != safe_domain_component(row["domain"]):
                raise ValueError("noncanonical domain")
            relative = safe_manifest_relative_path(row["relative_path"])
            if relative.as_posix() != row["relative_path"]:
                raise ValueError("noncanonical relative path")
        except (KeyError, ValueError) as exc:
            raise TVTimeError(
                "The private extraction inventory had an unsupported format."
            ) from exc
        current_key = (row["domain"], row["relative_path"])
        if previous_key is not None and current_key < previous_key:
            raise TVTimeError("The private extraction inventory had an unsupported order.")
        previous_key = current_key
        declared = _canonical_inventory_decimal(row.get("declared_size"))
        actual = _canonical_inventory_decimal(row.get("actual_size"))
        expected_match = "True" if declared == actual else "False"
        digest = row.get("sha256")
        if (
            row.get("size_match") != expected_match
            or not isinstance(digest, str)
            or len(digest) != 64
            or digest != digest.lower()
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise TVTimeError("The private extraction inventory had an unsupported format.")
        actual_bytes += actual
        declared_bytes += declared
        if actual_bytes > MAXIMUM_CONTRACT_INTEGER or declared_bytes > MAXIMUM_CONTRACT_INTEGER:
            raise TVTimeError("The private extraction inventory byte totals were unsupported.")
        if declared != actual:
            discrepancies.append(
                {
                    "domain": row["domain"],
                    "relative_path": row["relative_path"],
                    "declared_size": declared,
                    "actual_size": actual,
                }
            )
    if (
        source_snapshot.raw_tree_files != len(rows)
        or source_snapshot.raw_tree_bytes != actual_bytes
    ):
        raise TVTimeError("The private extraction inventory did not match the sealed raw tree.")
    return (
        {
            "files_expected": len(rows),
            "files_extracted": len(rows),
            "bytes_extracted": actual_bytes,
            "selected_declared_bytes": declared_bytes,
            "size_discrepancy_count": len(discrepancies),
        },
        discrepancies,
    )


def _validate_inventory_summary_contract(
    *,
    extraction: Path,
    inventory_rows: Sequence[Mapping[str, str]],
    extraction_summary: dict[str, Any],
    run_state: dict[str, Any],
    source_snapshot: SourceSnapshot,
) -> tuple[dict[str, int], list[dict[str, Any]]]:
    aggregate, discrepancies = _inventory_aggregate(
        inventory_rows,
        source_snapshot=source_snapshot,
    )
    if extraction_summary.get("size_discrepancies") != discrepancies or any(
        extraction_summary.get(key) != value
        for key, value in aggregate.items()
        if key != "size_discrepancy_count"
    ):
        raise TVTimeError("The private extraction summary did not match its inventory.")
    if any(run_state.get(key) != value for key, value in aggregate.items()):
        raise TVTimeError("The private extraction completion marker did not match its inventory.")
    domains = extraction_summary["domains"]
    expected_domains = ("\n".join(domains) + "\n").encode("utf-8")
    domains_bytes = read_regular_bytes(
        safe_join(extraction, "metadata", "domains.txt"),
        maximum_bytes=MAXIMUM_DOMAINS_BYTES,
        require_private=True,
    )
    if domains_bytes != expected_domains:
        raise TVTimeError("The private extraction domains file did not match its summary.")
    return aggregate, discrepancies


def _analysis_aggregate(summary: dict[str, Any]) -> dict[str, int | str]:
    aggregate: dict[str, int | str] = {
        key: _required_nonnegative_int(summary, key, label="analysis summary")
        for key in (
            "series_library",
            "watched_movies",
            "movie_watchlist",
            "favorite_shows",
            "favorite_movies",
            "watch_events",
            "watch_events_with_titles",
            "episode_cache_unique",
        )
    }
    parser_status = summary.get("parser_status")
    if parser_status not in {"recognized", "empty"}:
        raise TVTimeError("The private analysis summary had an unsupported parser status.")
    if int(aggregate["watch_events_with_titles"]) > int(aggregate["watch_events"]):
        raise TVTimeError("The private analysis summary had invalid watch-event counts.")
    aggregate["parser_status"] = parser_status
    return aggregate


def _preflight_report_table_counts(
    summary: dict[str, Any],
    *,
    additional_rows: int = 0,
) -> None:
    """Reject an impractical visual report before analysis staging is renamed."""

    if additional_rows < 0 or additional_rows > MAXIMUM_REPORT_TABLE_ROWS:
        raise _report_limit_error(
            "copy-size-difference row count",
            MAXIMUM_REPORT_TABLE_ROWS,
        )
    total = additional_rows
    for key in (
        "series_library",
        "watched_movies",
        "movie_watchlist",
        "favorite_shows",
        "favorite_movies",
        "episode_cache_unique",
        "watch_events",
    ):
        count = _required_nonnegative_int(summary, key, label="analysis summary")
        if count > MAXIMUM_REPORT_TABLE_ROWS:
            raise _report_limit_error(
                f"{key.replace('_', '-')} visual-report row count",
                MAXIMUM_REPORT_TABLE_ROWS,
            )
        total += count
    if total > MAXIMUM_TOTAL_REPORT_TABLE_ROWS:
        raise _report_limit_error(
            "combined visual-report row count",
            MAXIMUM_TOTAL_REPORT_TABLE_ROWS,
        )


def _validated_size_discrepancies(summary: dict[str, Any]) -> list[dict[str, Any]]:
    value = summary.get("size_discrepancies")
    if not isinstance(value, list):
        raise TVTimeError("The private extraction summary had an unsupported format.")
    result: list[dict[str, Any]] = []
    for item in value:
        if len(result) >= MAXIMUM_REPORT_TABLE_ROWS:
            raise _report_limit_error(
                "copy-size-difference row count",
                MAXIMUM_REPORT_TABLE_ROWS,
            )
        if not isinstance(item, dict) or set(item) != {
            "domain",
            "relative_path",
            "declared_size",
            "actual_size",
        }:
            raise TVTimeError("The private extraction size warnings had an unsupported format.")
        domain = item.get("domain")
        relative_path = item.get("relative_path")
        declared_size = item.get("declared_size")
        actual_size = item.get("actual_size")
        if (
            not isinstance(domain, str)
            or not domain
            or not isinstance(relative_path, str)
            or not relative_path
            or not isinstance(declared_size, int)
            or isinstance(declared_size, bool)
            or declared_size < 0
            or declared_size > MAXIMUM_CONTRACT_INTEGER
            or not isinstance(actual_size, int)
            or isinstance(actual_size, bool)
            or actual_size < 0
            or actual_size > MAXIMUM_CONTRACT_INTEGER
            or declared_size == actual_size
        ):
            raise TVTimeError("The private extraction size warnings had an unsupported format.")
        try:
            canonical_domain = safe_domain_component(domain)
            canonical_path = safe_manifest_relative_path(relative_path).as_posix()
        except ValueError as exc:
            raise TVTimeError(
                "The private extraction size warnings had an unsupported format."
            ) from exc
        if canonical_domain != domain or canonical_path != relative_path:
            raise TVTimeError("The private extraction size warnings had an unsupported format.")
        _bounded_utf8_length(
            domain,
            subject="copy-size-difference domain byte size",
            maximum_bytes=MAXIMUM_ANALYSIS_CSV_CELL_BYTES,
        )
        _bounded_utf8_length(
            relative_path,
            subject="copy-size-difference path byte size",
            maximum_bytes=MAXIMUM_ANALYSIS_CSV_CELL_BYTES,
        )
        result.append(
            {
                "domain": domain,
                "relative_path": relative_path,
                "declared_size": declared_size,
                "actual_size": actual_size,
            }
        )
    return result


def _report_limit_error(subject: str, limit: int) -> UnsupportedSchemaError:
    return UnsupportedSchemaError(
        f"The recovered data exceeded this release's safe {subject} limit ({limit:,}). "
        "The normalized recovery tables remain the authoritative result; preserve them and "
        "retry report generation with an updated extractor."
    )


class _ReportRowBudget:
    def __init__(self, *, maximum_total: int) -> None:
        self.maximum_total = maximum_total
        self.total = 0

    def reserve(self, category: str, count: int) -> None:
        if count <= 0:
            return
        total = self.total + count
        if total > self.maximum_total:
            raise _report_limit_error(category, self.maximum_total)
        self.total = total


class _ReportByteBudget:
    def __init__(self, *, maximum_total: int) -> None:
        self.maximum_total = maximum_total
        self.total = 0

    def reserve_rows(self, category: str, rows: Sequence[Mapping[str, object]]) -> None:
        for row in rows:
            for value in row.values():
                text = "" if value is None else str(value)
                self.total += _bounded_utf8_length(
                    text,
                    subject=f"{category} cell byte size",
                    maximum_bytes=MAXIMUM_ANALYSIS_CSV_CELL_BYTES,
                )
                if self.total > self.maximum_total:
                    raise _report_limit_error(category, self.maximum_total)


def _validate_json_mapping(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TVTimeError(f"The private {label} had an unsupported format.")
    try:
        _validate_cache_json_complexity(value)
    except UnsupportedSchemaError as exc:
        raise TVTimeError(f"The private {label} exceeded its safe data envelope.") from exc
    return value


def _read_strict_json_mapping(
    path: Path,
    *,
    maximum_bytes: int,
    label: str,
) -> dict[str, Any]:
    """Read one bounded private JSON object while rejecting duplicate keys at every depth."""

    payload = read_regular_bytes(
        path,
        maximum_bytes=maximum_bytes,
        require_private=True,
    )

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object field")
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise TVTimeError(f"The private {label} had an unsupported format.") from exc
    return _validate_json_mapping(value, label=label)


def _require_exact_fields(
    value: Mapping[str, object],
    fields: frozenset[str],
    *,
    label: str,
) -> None:
    if set(value) != fields:
        raise TVTimeError(f"The private {label} had an unsupported exact schema.")


def _require_utc_timestamp(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("+00:00"):
        raise TVTimeError(f"The private {label} had an unsupported timestamp.")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise TVTimeError(f"The private {label} had an unsupported timestamp.") from exc
    if parsed.utcoffset() != timedelta(0):
        raise TVTimeError(f"The private {label} had an unsupported timestamp.")
    return value


def _validate_pre_report_analysis_summary(summary: dict[str, Any]) -> None:
    _require_exact_fields(
        summary,
        PRE_REPORT_ANALYSIS_SUMMARY_FIELDS,
        label="analysis summary",
    )
    if summary.get("dio_cache_quick_check") != "ok" or summary.get("parser_status") not in {
        "recognized",
        "empty",
    }:
        raise TVTimeError("The private analysis summary had an unsupported completion state.")
    if summary.get("raw_cache_exported") is not False:
        raise TVTimeError(
            "A sealed report cannot include raw cache-response exports. Preserve this analysis "
            "and run a fresh recovery without --include-raw-cache for native validation."
        )
    for name in ANALYSIS_COUNT_FIELDS:
        _required_nonnegative_int(summary, name, label="analysis summary")
    if summary["episode_cache_unique"] > summary["episode_cache_rows"]:
        raise TVTimeError("The private analysis summary had invalid episode-cache counts.")
    sqlite_integrity = summary.get("sqlite_integrity")
    if not isinstance(sqlite_integrity, dict) or any(
        not isinstance(key, str)
        or not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > MAXIMUM_CONTRACT_INTEGER
        for key, value in sqlite_integrity.items()
    ):
        raise TVTimeError("The private analysis summary had an unsupported format.")
    escape_metadata = summary.get("csv_spreadsheet_escaped_cells")
    if not isinstance(escape_metadata, dict):
        raise TVTimeError("The private analysis summary had an unsupported format.")
    try:
        _validate_csv_escape_metadata(escape_metadata)
    except UnsupportedSchemaError as exc:
        raise TVTimeError("The private analysis summary had an unsupported format.") from exc


def _validate_extraction_summary_contract(summary: dict[str, Any]) -> None:
    _require_exact_fields(summary, EXTRACTION_SUMMARY_FIELDS, label="extraction summary")
    if (
        summary.get("bundle_id") != TVTIME_BUNDLE_ID
        or summary.get("failures") != []
        or summary.get("decrypted_manifest_included") is not False
    ):
        raise TVTimeError("The private extraction summary was not a sealed default extraction.")
    _require_utc_timestamp(summary.get("completed_utc"), label="extraction summary")
    domains = summary.get("domains")
    try:
        domains_are_safe = (
            isinstance(domains, list)
            and bool(domains)
            and all(isinstance(item, str) for item in domains)
            and domains == sorted(set(domains))
            and PRIMARY_DOMAIN in domains
            and all(
                item == PRIMARY_DOMAIN or item.startswith(RELATED_PLUGIN_DOMAIN_PREFIX)
                for item in domains
            )
            and all(item == safe_domain_component(item) for item in domains)
        )
    except ValueError:
        domains_are_safe = False
    if not domains_are_safe:
        raise TVTimeError("The private extraction summary had unsupported domains.")
    for name in (
        "files_expected",
        "files_extracted",
        "bytes_extracted",
        "selected_declared_bytes",
    ):
        _required_nonnegative_int(summary, name, label="extraction summary")
    _validated_size_discrepancies(summary)


def _validate_run_state_contract(run_state: dict[str, Any]) -> None:
    _require_exact_fields(run_state, RUN_STATE_FIELDS, label="extraction completion marker")
    if (
        run_state.get("schema_version") != EXTRACTION_RUN_STATE_SCHEMA_VERSION
        or run_state.get("contract") != EXTRACTION_RUN_STATE_CONTRACT
        or run_state.get("status") != "complete"
    ):
        raise TVTimeError("The private extraction completion marker was not complete.")
    _require_utc_timestamp(run_state.get("completed_utc"), label="extraction completion marker")
    for name in (
        "files_expected",
        "files_extracted",
        "bytes_extracted",
        "selected_declared_bytes",
        "size_discrepancy_count",
    ):
        _required_nonnegative_int(run_state, name, label="extraction completion marker")
    if (
        run_state["files_expected"] != run_state["files_extracted"]
        or run_state["size_discrepancy_count"] > run_state["files_expected"]
    ):
        raise TVTimeError("The private extraction completion marker had invalid counts.")
    source_snapshot_from_mapping(run_state.get("source_snapshot"))


def _validate_report_artifact(path: Path, *, label: str) -> None:
    metadata = require_private_path(path, expected_type=stat.S_IFREG)
    if metadata.st_size <= 0 or metadata.st_size > MAXIMUM_REPORT_ARTIFACT_BYTES:
        raise _report_limit_error(
            f"{label} byte size",
            MAXIMUM_REPORT_ARTIFACT_BYTES,
        )


def read_csv(
    path: Path,
    *,
    escaped_cells: object = None,
    maximum_rows: int | None = None,
    maximum_bytes: int = MAXIMUM_ANALYSIS_CSV_BYTES,
    expected_fields: tuple[str, ...] | None = None,
) -> list[dict[str, str]]:
    """Read an analysis CSV without following links and reverse recorded safe-cell escapes."""

    row_limit = MAXIMUM_REPORT_TABLE_ROWS if maximum_rows is None else maximum_rows
    if row_limit < 0:
        raise ValueError("maximum_rows must be nonnegative")
    if maximum_bytes <= 0:
        raise ValueError("maximum_bytes must be positive")
    metadata = require_private_path(path, expected_type=stat.S_IFREG)
    if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
        raise _report_limit_error("CSV file byte size", maximum_bytes)
    rows: list[dict[str, str]] = []
    previous_field_limit = csv.field_size_limit()
    total_read_bytes = 0
    try:
        csv.field_size_limit(MAXIMUM_ANALYSIS_CSV_CELL_BYTES + 1)
        with regular_text_reader(path, newline="", require_private=True) as handle:
            opened_metadata = os.fstat(handle.fileno())

            def bounded_lines() -> Iterator[str]:
                nonlocal total_read_bytes
                while True:
                    line = handle.readline(MAXIMUM_ANALYSIS_CSV_ROW_BYTES + 2)
                    if not line:
                        return
                    try:
                        line_bytes = len(line.encode("utf-8"))
                    except UnicodeEncodeError as exc:
                        raise TVTimeError(
                            "A private recovery table contained invalid Unicode text."
                        ) from exc
                    if line_bytes > MAXIMUM_ANALYSIS_CSV_ROW_BYTES:
                        raise _report_limit_error(
                            "CSV physical-line byte size",
                            MAXIMUM_ANALYSIS_CSV_ROW_BYTES,
                        )
                    total_read_bytes += line_bytes
                    if total_read_bytes > maximum_bytes:
                        raise _report_limit_error("CSV file byte size", maximum_bytes)
                    yield line

            reader = csv.DictReader(bounded_lines())
            fieldnames = tuple(reader.fieldnames or ())
            if (
                not fieldnames
                or len(fieldnames) > 256
                or len(set(fieldnames)) != len(fieldnames)
                or (expected_fields is not None and fieldnames != expected_fields)
            ):
                raise TVTimeError("A private recovery table had an unsupported header.")
            for field in fieldnames:
                if not field:
                    raise TVTimeError("A private recovery table had an unsupported header.")
                _bounded_utf8_length(
                    field,
                    subject="analysis CSV header byte size",
                    maximum_bytes=1_024,
                )
            for row in reader:
                if len(rows) >= row_limit:
                    raise _report_limit_error("CSV row count", row_limit)
                if None in row or any(value is None for value in row.values()):
                    raise TVTimeError("A private recovery table had an unsupported row shape.")
                row_bytes = 0
                for value in row.values():
                    assert value is not None
                    row_bytes += _bounded_utf8_length(
                        value,
                        subject="analysis CSV cell byte size",
                        maximum_bytes=MAXIMUM_ANALYSIS_CSV_CELL_BYTES + 1,
                    )
                if row_bytes > MAXIMUM_ANALYSIS_CSV_ROW_BYTES:
                    raise _report_limit_error(
                        "CSV row byte size",
                        MAXIMUM_ANALYSIS_CSV_ROW_BYTES,
                    )
                rows.append(row)
            after_metadata = os.fstat(handle.fileno())
    except csv.Error as exc:
        raise TVTimeError(
            "A private recovery table could not be read safely. Preserve the extraction "
            "and retry with an updated extractor."
        ) from exc
    finally:
        csv.field_size_limit(previous_field_limit)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        any(
            getattr(opened_metadata, field) != getattr(after_metadata, field)
            for field in stable_fields
        )
        or total_read_bytes != after_metadata.st_size
    ):
        raise UnsafePathError("A private recovery table changed while it was read.")
    if escaped_cells is None:
        for row in rows:
            for value in row.values():
                _bounded_utf8_length(
                    value,
                    subject="analysis CSV cell byte size",
                    maximum_bytes=MAXIMUM_ANALYSIS_CSV_CELL_BYTES,
                )
        return rows
    if not isinstance(escaped_cells, list):
        raise TVTimeError("Analysis CSV escape metadata had an unsupported format.")
    if len(escaped_cells) > MAXIMUM_CSV_ESCAPE_ENTRIES:
        raise _report_limit_error(
            "analysis CSV escape-coordinate count",
            MAXIMUM_CSV_ESCAPE_ENTRIES,
        )
    seen: set[tuple[int, str]] = set()
    for item in escaped_cells:
        if not isinstance(item, dict):
            raise TVTimeError("Analysis CSV escape metadata had an unsupported format.")
        row_number = item.get("row")
        field = item.get("field")
        if (
            not isinstance(row_number, int)
            or isinstance(row_number, bool)
            or row_number < 1
            or not isinstance(field, str)
            or not field
        ):
            raise TVTimeError("Analysis CSV escape metadata had an unsupported format.")
        coordinate = (row_number, field)
        if coordinate in seen or row_number > len(rows) or field not in rows[row_number - 1]:
            raise TVTimeError("Analysis CSV escape metadata did not match the recovered table.")
        value = rows[row_number - 1][field]
        if not isinstance(value, str) or not value.startswith("'") or len(value) < 2:
            raise TVTimeError("Analysis CSV escape metadata did not match the recovered table.")
        if not value[1:].startswith(("=", "+", "-", "@", "\t", "\r")):
            raise TVTimeError("Analysis CSV escape metadata did not match the recovered table.")
        rows[row_number - 1][field] = value[1:]
        seen.add(coordinate)
    for row in rows:
        for value in row.values():
            _bounded_utf8_length(
                value,
                subject="analysis CSV cell byte size",
                maximum_bytes=MAXIMUM_ANALYSIS_CSV_CELL_BYTES,
            )
    return rows


def collect_trailers(
    value: object,
    inherited_name: str = "",
    *,
    row_budget: _ReportRowBudget | None = None,
    cancellation_check: Callable[[], None] | None = None,
) -> list[dict[str, str]]:
    """Collect trailer rows iteratively within the report-derived-row envelope."""

    budget = row_budget or _ReportRowBudget(maximum_total=MAXIMUM_REPORT_DERIVED_ROWS)
    rows: list[dict[str, str]] = []
    visited = 0

    def children(item: object, parent_name: str) -> Iterator[tuple[object, str]]:
        if isinstance(item, dict):
            for child in item.values():
                yield child, parent_name
        elif isinstance(item, list):
            for child in item:
                yield child, parent_name

    stack: list[Iterator[tuple[object, str]]] = [iter(((value, inherited_name),))]
    while stack:
        try:
            item, parent_name = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        visited += 1
        if cancellation_check is not None and visited % 4_096 == 0:
            cancellation_check()
        if isinstance(item, dict):
            own_name = str(item.get("name") or parent_name or "")
            meta = item.get("meta")
            if isinstance(meta, dict):
                meta_name = str(meta.get("name") or own_name)
                meta_trailers = meta.get("trailers")
                for trailer in meta_trailers if isinstance(meta_trailers, list) else ():
                    if not isinstance(trailer, dict):
                        continue
                    url = sanitize_public_url(str(trailer.get("url") or ""))
                    if not url:
                        continue
                    budget.reserve("derived media-reference row count", 1)
                    rows.append(
                        {
                            "title": meta_name,
                            "trailer_name": str(trailer.get("name") or ""),
                            "runtime_seconds": str(trailer.get("runtime") or ""),
                            "url": url,
                            "thumbnail_url": sanitize_public_url(
                                str(trailer.get("thumb_url") or "")
                            ),
                        }
                    )
            direct_trailers = item.get("trailers")
            for trailer in direct_trailers if isinstance(direct_trailers, list) else ():
                if isinstance(trailer, dict):
                    url = sanitize_public_url(str(trailer.get("url") or ""))
                    if url:
                        budget.reserve("derived media-reference row count", 1)
                        rows.append(
                            {
                                "title": own_name,
                                "trailer_name": str(trailer.get("name") or ""),
                                "runtime_seconds": str(trailer.get("runtime") or ""),
                                "url": url,
                                "thumbnail_url": sanitize_public_url(
                                    str(trailer.get("thumb_url") or "")
                                ),
                            }
                        )
            stack.append(children(item, own_name))
        elif isinstance(item, list):
            stack.append(children(item, parent_name))
    return rows


def collect_urls(
    value: object,
    path: str = "",
    *,
    row_budget: _ReportRowBudget | None = None,
    cancellation_check: Callable[[], None] | None = None,
) -> list[tuple[str, str]]:
    """Collect sanitized URLs iteratively without recursive-stack failure."""

    budget = row_budget or _ReportRowBudget(maximum_total=MAXIMUM_REPORT_DERIVED_ROWS)
    rows: list[tuple[str, str]] = []
    visited = 0

    def children(item: object, parent_path: str) -> Iterator[tuple[object, str]]:
        if isinstance(item, dict):
            for key, child in item.items():
                child_path = f"{parent_path}.{key}" if parent_path else str(key)
                yield child, child_path
        elif isinstance(item, list):
            child_path = f"{parent_path}[]"
            for child in item:
                yield child, child_path

    stack: list[Iterator[tuple[object, str]]] = [iter(((value, path),))]
    while stack:
        try:
            item, item_path = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        visited += 1
        if cancellation_check is not None and visited % 4_096 == 0:
            cancellation_check()
        if isinstance(item, (dict, list)):
            stack.append(children(item, item_path))
        elif isinstance(item, str):
            url = sanitize_public_url(item)
            if url:
                budget.reserve("derived media-reference row count", 1)
                rows.append((item_path, url))
    return rows


def decode_tvtime_image_url(url: str) -> tuple[str, str, str]:
    if not isinstance(url, str):
        raise _report_limit_error("image-cache URL value type", 1)
    if len(url.encode("utf-8")) > MAXIMUM_IMAGE_CACHE_CELL_BYTES:
        raise _report_limit_error("image-cache URL byte size", MAXIMUM_IMAGE_CACHE_CELL_BYTES)
    sanitized = sanitize_public_url(url)
    marker = "/image/raw/"
    if marker not in sanitized:
        return sanitized, "", ""
    token = sanitized.split(marker, 1)[1].split("?", 1)[0]
    if len(token.encode("ascii", errors="ignore")) != len(token):
        return sanitized, "", ""
    if len(token) > MAXIMUM_IMAGE_TOKEN_BYTES:
        raise _report_limit_error("image-cache token byte size", MAXIMUM_IMAGE_TOKEN_BYTES)
    try:
        token += "=" * (-len(token) % 4)
        decoded = base64.b64decode(token, altchars=b"-_", validate=True)
        payload, json_valid, _node_count = _parse_cache_json(decoded)
        if not json_valid or not isinstance(payload, dict):
            return sanitized, "", ""
        key = payload.get("key")
        source = (sanitize_image_source_reference(key) if isinstance(key, str) else "") or sanitized
        edits = payload.get("edits")
        resize = edits.get("resize") if isinstance(edits, dict) else None
        if not isinstance(resize, dict):
            resize = {}

        def dimension(name: str) -> str:
            value = resize.get(name)
            if value is None or isinstance(value, bool) or not isinstance(value, (str, int, float)):
                return ""
            text = str(value)
            return text if len(text.encode("utf-8")) <= 64 else ""

        return source, dimension("width"), dimension("height")
    except (binascii.Error, ValueError, TypeError, json.JSONDecodeError):
        return sanitized, "", ""


def sanitize_image_source_reference(value: str) -> str:
    absolute_url = sanitize_public_url(value)
    if absolute_url:
        return absolute_url
    if not isinstance(value, str) or not value or "\\" in value:
        return ""
    if any(ord(character) < 32 for character in value):
        return ""
    parsed = urlsplit(value)
    path = parsed.path
    decoded_path = unquote(path)
    if (
        parsed.scheme
        or parsed.netloc
        or not path
        or path.startswith("/")
        or path[0] in "=+-@"
        or "\\" in decoded_path
        or decoded_path.startswith("/")
    ):
        return ""
    relative = PurePosixPath(path)
    decoded_relative = PurePosixPath(decoded_path)
    if (
        relative.as_posix() != path
        or any(part in {".", ".."} for part in relative.parts)
        or any(part in {".", ".."} for part in decoded_relative.parts)
    ):
        return ""
    return path


def image_category(source: str) -> str:
    lowered = source.lower()
    for category, markers in (
        ("episode screen", ("/episode/", "/screencap/")),
        ("poster", ("/posters/", "/poster/")),
        ("background / fanart", ("/backgrounds/", "/fanart/")),
        ("thumbnail", ("ytimg.com", "thumb")),
        ("logo", ("logo",)),
    ):
        if any(marker in lowered for marker in markers):
            return category
    return "other image"


def _bounded_image_cache_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray, memoryview)):
        try:
            text = bytes(value).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UnsupportedSchemaError(
                "The optional image cache contained non-text metadata."
            ) from exc
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        text = str(value)
    else:
        raise UnsupportedSchemaError(
            "The optional image cache contained an unsupported metadata value."
        )
    if "\x00" in text or len(text.encode("utf-8")) > MAXIMUM_IMAGE_CACHE_CELL_BYTES:
        raise _report_limit_error(
            "image-cache metadata cell byte size",
            MAXIMUM_IMAGE_CACHE_CELL_BYTES,
        )
    return text


def _validate_image_cache_table_limits(connection: sqlite3.Connection) -> int:
    byte_expressions = [
        f"COALESCE(length(CAST({column} AS BLOB)), 0)" for column in _IMAGE_CACHE_COLUMNS
    ]
    maximum_expressions = [f"MAX({expression})" for expression in byte_expressions]
    query = (
        "SELECT COUNT(*), "
        + ", ".join(maximum_expressions)
        + ", COALESCE(SUM("
        + " + ".join(byte_expressions)
        + "), 0) FROM cacheObject"
    )
    values = connection.execute(query).fetchone()
    if values is None or len(values) != len(_IMAGE_CACHE_COLUMNS) + 2:
        raise UnsupportedSchemaError("The optional image cache could not be bounded safely.")
    row_count = values[0]
    maximums = values[1:-1]
    total_bytes = values[-1]
    if not isinstance(row_count, int) or isinstance(row_count, bool) or row_count < 0:
        raise UnsupportedSchemaError("The optional image cache row count was invalid.")
    if row_count > MAXIMUM_IMAGE_CACHE_ROWS:
        raise _report_limit_error("image-cache reference row count", MAXIMUM_IMAGE_CACHE_ROWS)
    if any(
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > MAXIMUM_IMAGE_CACHE_CELL_BYTES
        for value in maximums
    ):
        raise _report_limit_error(
            "image-cache metadata cell byte size",
            MAXIMUM_IMAGE_CACHE_CELL_BYTES,
        )
    if (
        not isinstance(total_bytes, int)
        or isinstance(total_bytes, bool)
        or total_bytes < 0
        or total_bytes > MAXIMUM_IMAGE_CACHE_TOTAL_BYTES
    ):
        raise _report_limit_error(
            "combined image-cache metadata byte size",
            MAXIMUM_IMAGE_CACHE_TOTAL_BYTES,
        )
    return row_count


def _cache_payloads(
    cache_db: Path,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> Iterator[object]:
    """Yield validated cache payloads without retaining the full cache twice."""

    with readonly_sqlite(cache_db) as connection:
        try:
            _validate_cache_table_limits(connection)
            with closing(
                connection.execute("SELECT content FROM cache_dio ORDER BY key, subKey")
            ) as rows:
                total_json_nodes = 0
                for (content,) in rows:
                    if cancellation_check is not None:
                        cancellation_check()
                    payload, json_valid, node_count = _parse_cache_json(
                        _cache_content_bytes(content),
                        cancellation_check=cancellation_check,
                    )
                    total_json_nodes += node_count
                    if total_json_nodes > MAXIMUM_TOTAL_CACHE_JSON_NODES:
                        raise _cache_limit_error(
                            "combined JSON node count",
                            MAXIMUM_TOTAL_CACHE_JSON_NODES,
                        )
                    if not json_valid:
                        continue
                    yield payload
        except sqlite3.Error as exc:
            raise TVTimeError(
                "Media references could not be read safely from DioCache.db."
            ) from exc


def _image_cache_rows(image_db: Path) -> tuple[list[dict[str, Any]], str]:
    if not image_db.is_file():
        return [], "not present"
    rows: list[dict[str, Any]] = []
    try:
        with readonly_sqlite(image_db) as connection:
            _validate_image_cache_table_limits(connection)
            with closing(
                connection.execute(
                    "SELECT _id, url, relativePath, validTill, touched, length "
                    "FROM cacheObject ORDER BY _id"
                )
            ) as records:
                for record in records:
                    cache_id, url, relative_path, valid_till, touched, length = record
                    url_text = _bounded_image_cache_text(url)
                    source, width, height = decode_tvtime_image_url(url_text)
                    rows.append(
                        {
                            "cache_id": _bounded_image_cache_text(cache_id),
                            "category": image_category(source),
                            "intended_filename": _bounded_image_cache_text(relative_path),
                            "declared_bytes": (_bounded_image_cache_text(length) if length else ""),
                            "width": width,
                            "height": height,
                            "source_url": source,
                            "cached_request_url": sanitize_public_url(url_text),
                            "valid_till": (
                                _bounded_image_cache_text(valid_till) if valid_till else ""
                            ),
                            "touched": (_bounded_image_cache_text(touched) if touched else ""),
                        }
                    )
    except (sqlite3.Error, TVTimeError):
        # Keep local paths and dependency diagnostics out of the human-readable
        # reports. The catalogue remains useful even when this optional cache is
        # unavailable, and "unreadable" is the complete public status contract.
        return [], "unreadable"
    return rows, "ok"


def _build_report(
    *,
    extraction_directory: Path,
    cancellation_check: Callable[[], None] | None = None,
    commit_seal: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Build a readable private catalogue and sanitized media-reference tables."""

    if cancellation_check is not None:
        cancellation_check()
    extraction = validate_extraction_directory(extraction_directory)
    initial_run_state = _read_strict_json_mapping(
        safe_join(extraction, "metadata", "run_state.json"),
        maximum_bytes=MAXIMUM_COMPLETION_MARKER_BYTES,
        label="extraction completion marker",
    )
    _validate_run_state_contract(initial_run_state)
    expected_source_snapshot = source_snapshot_from_mapping(
        initial_run_state.get("source_snapshot")
    )
    source_snapshot = reconcile_raw_tree(
        extraction,
        expected=expected_source_snapshot,
        cancellation_check=cancellation_check,
    )
    final_analysis = safe_join(extraction, "analysis")
    if not final_analysis.is_dir() or final_analysis.is_symlink():
        raise TVTimeError("The complete analysis directory was not found. Run analyze first.")
    metadata_directory = safe_join(extraction, "metadata")
    pre_report_summary = _read_strict_json_mapping(
        final_analysis / "analysis_summary.json",
        maximum_bytes=MAXIMUM_ANALYSIS_SUMMARY_BYTES,
        label="analysis summary",
    )
    _validate_pre_report_analysis_summary(pre_report_summary)
    pre_extraction_summary = _read_strict_json_mapping(
        safe_join(extraction, "metadata", "summary.json"),
        maximum_bytes=MAXIMUM_ANALYSIS_SUMMARY_BYTES,
        label="extraction summary",
    )
    _validate_extraction_summary_contract(pre_extraction_summary)
    if pre_extraction_summary["completed_utc"] != initial_run_state["completed_utc"]:
        raise TVTimeError(
            "The private extraction summary timestamp did not match its completion marker."
        )
    preflight_inventory = read_csv(
        safe_join(extraction, "metadata", "inventory.csv"),
        maximum_rows=MAXIMUM_REPORT_INVENTORY_ROWS,
        maximum_bytes=MAXIMUM_INVENTORY_BYTES,
        expected_fields=tuple(INVENTORY_FIELDS),
    )
    _preflight_aggregate, preflight_size_discrepancies = _validate_inventory_summary_contract(
        extraction=extraction,
        inventory_rows=preflight_inventory,
        extraction_summary=pre_extraction_summary,
        run_state=initial_run_state,
        source_snapshot=source_snapshot,
    )
    _preflight_report_table_counts(
        pre_report_summary,
        additional_rows=len(preflight_size_discrepancies),
    )
    preflight_escape_metadata = pre_report_summary.get("csv_spreadsheet_escaped_cells", {})
    _validate_csv_escape_metadata(preflight_escape_metadata)
    if any(
        name not in _PRE_REPORT_CSV_FIELDS or not items
        for name, items in preflight_escape_metadata.items()
    ):
        raise TVTimeError("Analysis CSV escape metadata had an unsupported format.")
    for filename in _PRE_REPORT_CSV_FIELDS:
        csv_metadata = require_private_path(
            final_analysis / filename,
            expected_type=stat.S_IFREG,
        )
        if csv_metadata.st_size <= 0 or csv_metadata.st_size > MAXIMUM_ANALYSIS_CSV_BYTES:
            raise _report_limit_error(
                "CSV file byte size",
                MAXIMUM_ANALYSIS_CSV_BYTES,
            )
    if pre_report_summary.get("raw_cache_exported") is not False:
        raise TVTimeError(
            "A sealed report cannot include raw cache-response exports. Preserve this analysis "
            "and run a fresh recovery without --include-raw-cache for native validation."
        )
    cache_responses = final_analysis / "cache_responses"
    if cache_responses.exists() or cache_responses.is_symlink():
        raise TVTimeError(
            "Unexpected raw cache-response exports were present. Preserve this analysis and run "
            "a fresh recovery without --include-raw-cache for native validation."
        )
    manifest_directory = safe_join(extraction, "manifest")
    try:
        require_private_path(manifest_directory, expected_type=stat.S_IFDIR)
        invalid_manifest_directory = (
            not manifest_directory.is_dir()
            or manifest_directory.is_symlink()
            or next(manifest_directory.iterdir(), None) is not None
        )
    except OSError as exc:
        raise TVTimeError("The private manifest directory could not be validated safely.") from exc
    if invalid_manifest_directory:
        raise TVTimeError(
            "A sealed report cannot include a retained decrypted device manifest. Preserve this "
            "extraction for advanced private analysis and run a fresh default recovery for "
            "native validation."
        )
    report_staging = safe_join(extraction, ".report-incomplete")
    if report_staging.exists() or report_staging.is_symlink():
        raise OutputExistsError(
            "An incomplete report staging directory already exists. Preserve it for diagnosis and "
            "retry recovery into a fresh destination."
        )

    artifact_names = (
        "trailer_references.csv",
        "media_url_inventory.csv",
        "image_cache_references.csv",
        "TVTime-Recovered-Data.md",
        HTML_REPORT_FILENAME,
        PDF_REPORT_FILENAME,
        "recovery_state.json",
    )
    if any(
        (final_analysis / name).exists() or (final_analysis / name).is_symlink()
        for name in artifact_names
    ):
        raise OutputExistsError(
            "Report output already exists. Refusing to overwrite or mix recovery artifacts."
        )

    promote_directory_no_replace_atomic(final_analysis, report_staging, durable=True)
    analysis = report_staging
    secure_directory(analysis)
    _exact_private_directory_membership(
        analysis,
        expected_names=_PRE_REPORT_ANALYSIS_FILENAMES,
        label="analysis",
        cancellation_check=cancellation_check,
    )

    analysis_summary = _read_strict_json_mapping(
        analysis / "analysis_summary.json",
        maximum_bytes=MAXIMUM_ANALYSIS_SUMMARY_BYTES,
        label="analysis summary",
    )
    _validate_pre_report_analysis_summary(analysis_summary)
    escape_metadata = analysis_summary.get("csv_spreadsheet_escaped_cells", {})
    _validate_csv_escape_metadata(escape_metadata)
    if any(
        name not in _PRE_REPORT_CSV_FIELDS or not items for name, items in escape_metadata.items()
    ):
        raise TVTimeError("Analysis CSV escape metadata had an unsupported format.")

    report_table_budget = _ReportRowBudget(maximum_total=MAXIMUM_TOTAL_REPORT_TABLE_ROWS)
    report_byte_budget = _ReportByteBudget(maximum_total=MAXIMUM_REPORT_RENDER_INPUT_BYTES)

    validated_nonvisual_tables = set(_PRE_REPORT_CSV_FIELDS) - _VISUAL_REPORT_INPUT_FILENAMES
    for filename in sorted(validated_nonvisual_tables):
        read_csv(
            analysis / filename,
            escaped_cells=escape_metadata.get(filename, []),
            maximum_rows=MAXIMUM_ANALYSIS_CSV_ROWS,
            expected_fields=_PRE_REPORT_CSV_FIELDS[filename],
        )

    def read_analysis_csv(filename: str) -> list[dict[str, str]]:
        rows = read_csv(
            analysis / filename,
            escaped_cells=escape_metadata.get(filename, []),
            expected_fields=_PRE_REPORT_CSV_FIELDS[filename],
        )
        report_table_budget.reserve("combined visual-report row count", len(rows))
        report_byte_budget.reserve_rows("combined visual-report input byte size", rows)
        return rows

    series = read_analysis_csv("series_library.csv")
    watched_movies = read_analysis_csv("watched_movies.csv")
    movie_watchlist = read_analysis_csv("movie_watchlist.csv")
    favorite_shows = read_analysis_csv("favorite_shows.csv")
    favorite_movies = read_analysis_csv("favorite_movies.csv")
    episodes = read_analysis_csv("episode_cache_unique.csv")
    watch_events = read_analysis_csv("watch_events_named.csv")
    try:
        inventory_path = safe_join(extraction, "metadata", "inventory.csv")
    except ValueError as exc:
        raise UnsafePathError("The private extraction inventory path was unsafe.") from exc
    inventory_rows = read_csv(
        inventory_path,
        maximum_rows=MAXIMUM_REPORT_INVENTORY_ROWS,
        maximum_bytes=MAXIMUM_INVENTORY_BYTES,
        expected_fields=tuple(INVENTORY_FIELDS),
    )
    extracted_file_count = len(inventory_rows)
    extraction_summary = _read_strict_json_mapping(
        safe_join(extraction, "metadata", "summary.json"),
        maximum_bytes=MAXIMUM_ANALYSIS_SUMMARY_BYTES,
        label="extraction summary",
    )
    _validate_extraction_summary_contract(extraction_summary)
    extraction_run_state = _read_strict_json_mapping(
        safe_join(extraction, "metadata", "run_state.json"),
        maximum_bytes=MAXIMUM_COMPLETION_MARKER_BYTES,
        label="extraction completion marker",
    )
    _validate_run_state_contract(extraction_run_state)
    extraction_aggregate, size_discrepancies = _validate_inventory_summary_contract(
        extraction=extraction,
        inventory_rows=inventory_rows,
        extraction_summary=extraction_summary,
        run_state=extraction_run_state,
        source_snapshot=source_snapshot,
    )
    expected_run_state = {
        "schema_version": EXTRACTION_RUN_STATE_SCHEMA_VERSION,
        "contract": EXTRACTION_RUN_STATE_CONTRACT,
        "status": "complete",
        "completed_utc": extraction_summary["completed_utc"],
        **extraction_aggregate,
        "source_snapshot": source_snapshot.as_dict(),
    }
    if any(extraction_run_state.get(key) != value for key, value in expected_run_state.items()):
        raise TVTimeError(
            "The private extraction completion marker did not match the extraction summary."
        )
    report_table_budget.reserve(
        "combined visual-report row count",
        len(size_discrepancies),
    )
    report_byte_budget.reserve_rows(
        "combined visual-report input byte size",
        size_discrepancies,
    )
    _exact_private_directory_membership(
        metadata_directory,
        expected_names=_SEALED_METADATA_FILENAMES,
        label="metadata",
        cancellation_check=cancellation_check,
    )

    app_root = safe_join(extraction, "raw", PRIMARY_DOMAIN)
    all_urls: dict[str, str] = {}
    trailers_by_url: dict[str, dict[str, str]] = {}
    media_row_budget = _ReportRowBudget(maximum_total=MAXIMUM_REPORT_DERIVED_ROWS)
    with closing(
        _cache_payloads(
            safe_join(app_root, "Documents", "DioCache.db"),
            cancellation_check=cancellation_check,
        )
    ) as payloads:
        for payload in payloads:
            if cancellation_check is not None:
                cancellation_check()
            for field_path, url in collect_urls(
                payload,
                row_budget=media_row_budget,
                cancellation_check=cancellation_check,
            ):
                all_urls.setdefault(url, field_path)
            for trailer in collect_trailers(
                payload,
                row_budget=media_row_budget,
                cancellation_check=cancellation_check,
            ):
                trailers_by_url.setdefault(trailer["url"], trailer)

    trailer_rows = sorted(
        trailers_by_url.values(),
        key=lambda row: (row["title"].casefold(), row["url"]),
    )
    trailer_fields = ("title", "trailer_name", "runtime_seconds", "url", "thumbnail_url")
    _validate_analysis_csv_output(trailer_rows, trailer_fields)
    write_csv_private(
        analysis / "trailer_references.csv",
        trailer_rows,
        trailer_fields,
    )

    media_url_rows: list[dict[str, str]] = []
    for url, field_path in sorted(all_urls.items()):
        host = urlsplit(url).netloc
        lowered = f"{field_path} {url}".lower()
        if "youtube.com/watch" in lowered or "youtu.be/" in lowered:
            kind = "trailer video link"
        elif any(
            marker in lowered
            for marker in ("image", "poster", "fanart", "banner", "screen", "thumb", ".jpg", ".png")
        ):
            kind = "image link"
        else:
            kind = "other link"
        media_url_rows.append({"kind": kind, "host": host, "field_path": field_path, "url": url})
    media_url_fields = ("kind", "host", "field_path", "url")
    _validate_analysis_csv_output(media_url_rows, media_url_fields)
    write_csv_private(
        analysis / "media_url_inventory.csv",
        media_url_rows,
        media_url_fields,
    )

    image_rows, image_cache_status = _image_cache_rows(
        safe_join(app_root, "Library", "Application Support", "libCachedImageData.db")
    )
    image_fields = (
        "cache_id",
        "category",
        "intended_filename",
        "declared_bytes",
        "width",
        "height",
        "source_url",
        "cached_request_url",
        "valid_till",
        "touched",
    )
    _validate_analysis_csv_output(image_rows, image_fields)
    write_csv_private(
        analysis / "image_cache_references.csv",
        image_rows,
        image_fields,
    )

    named_events = sum(has_display_text(row["movie_name"]) for row in watch_events)
    media_counts = Counter(row["kind"] for row in media_url_rows)
    image_category_counts = Counter(str(row["category"]) for row in image_rows)
    visual_model = build_visual_report_model(
        series=series,
        watched_movies=watched_movies,
        movie_watchlist=movie_watchlist,
        favorite_shows=favorite_shows,
        favorite_movies=favorite_movies,
        episodes=episodes,
        watch_events=watch_events,
        extracted_file_count=extracted_file_count,
        image_cache_status=image_cache_status,
        trailer_count=len(trailer_rows),
        media_url_counts=media_counts,
        image_category_counts=image_category_counts,
        size_discrepancies=size_discrepancies,
    )
    staged_report_path = analysis / "TVTime-Recovered-Data.md"
    markdown_report = render_markdown_report(
        visual_model,
        cancellation_check=cancellation_check,
    )
    if len(markdown_report.encode("utf-8")) > MAXIMUM_REPORT_ARTIFACT_BYTES:
        raise _report_limit_error(
            "Markdown report byte size",
            MAXIMUM_REPORT_ARTIFACT_BYTES,
        )
    write_text_private(
        staged_report_path,
        markdown_report,
    )
    _validate_report_artifact(staged_report_path, label="Markdown report")
    visual_artifacts = write_visual_reports(
        visual_model,
        analysis_directory=analysis,
        cancellation_check=cancellation_check,
    )
    pdf_status = visual_artifacts.get("pdf_status", "generated")
    pdf_warning = visual_artifacts.get("pdf_warning", "")
    if pdf_status not in {"generated", "omitted"}:
        raise TVTimeError("The private PDF report had an unsupported completion status.")
    _validate_report_artifact(analysis / HTML_REPORT_FILENAME, label="HTML report")
    if pdf_status == "generated":
        _validate_report_artifact(analysis / PDF_REPORT_FILENAME, label="PDF report")

    analysis_aggregate = _analysis_aggregate(analysis_summary)
    expected_analysis_counts = {
        "series_library": len(series),
        "watched_movies": len(watched_movies),
        "movie_watchlist": len(movie_watchlist),
        "favorite_shows": len(favorite_shows),
        "favorite_movies": len(favorite_movies),
        "watch_events": len(watch_events),
        "watch_events_with_titles": named_events,
        "episode_cache_unique": len(episodes),
    }
    if any(analysis_aggregate[key] != count for key, count in expected_analysis_counts.items()):
        raise TVTimeError("The private analysis summary did not match the canonical report tables.")

    report_aggregate: dict[str, Any] = {
        "image_cache_references": len(image_rows),
        "trailer_references": len(trailer_rows),
        "media_urls": len(media_url_rows),
        "pdf_status": pdf_status,
    }
    if pdf_status == "omitted":
        report_aggregate["pdf_omission_reason"] = pdf_warning

    completed_utc = datetime.now(timezone.utc).isoformat()
    versioned_analysis_summary = dict(analysis_summary)
    versioned_analysis_summary.update(
        {
            "schema_version": RECOVERY_STATE_SCHEMA_VERSION,
            "contract": ANALYSIS_SUMMARY_CONTRACT,
            "status": "complete",
        }
    )
    _require_exact_fields(
        versioned_analysis_summary,
        ANALYSIS_SUMMARY_FIELDS,
        label="analysis summary",
    )
    _validate_analysis_summary_output(versioned_analysis_summary)
    write_json_private_atomic(analysis / "analysis_summary.json", versioned_analysis_summary)

    reconcile_raw_tree(
        extraction,
        expected=source_snapshot,
        cancellation_check=cancellation_check,
    )

    artifact_bindings: list[dict[str, Any]] = []
    for artifact_id, relative_path in _BOUND_ARTIFACTS:
        relative = PurePosixPath(relative_path)
        if relative.parts[0] == "metadata":
            artifact_path = safe_join(extraction, *relative.parts)
        else:
            artifact_path = safe_join(analysis, *relative.parts[1:])
        artifact_bindings.append(
            _private_artifact_binding(
                artifact_path,
                artifact_id=artifact_id,
                relative_path=relative_path,
                cancellation_check=cancellation_check,
            )
        )
    if pdf_status == "generated":
        artifact_bindings.append(
            _private_artifact_binding(
                analysis / PDF_REPORT_FILENAME,
                artifact_id="pdf_report",
                relative_path=f"analysis/{PDF_REPORT_FILENAME}",
                cancellation_check=cancellation_check,
            )
        )
    elif (analysis / PDF_REPORT_FILENAME).exists() or (analysis / PDF_REPORT_FILENAME).is_symlink():
        raise TVTimeError("The omitted private PDF report unexpectedly existed.")

    recovery_state = {
        "schema_version": RECOVERY_STATE_SCHEMA_VERSION,
        "contract": RECOVERY_STATE_CONTRACT,
        "status": "complete",
        "completed_utc": completed_utc,
        "pdf": {
            "status": pdf_status,
            "artifact_id": "pdf_report" if pdf_status == "generated" else None,
        },
        "source_snapshot": source_snapshot.as_dict(),
        "aggregates": {
            "extraction": extraction_aggregate,
            "analysis": analysis_aggregate,
            "report": report_aggregate,
        },
        "artifacts": artifact_bindings,
    }
    _validate_cache_json_complexity(recovery_state)
    recovery_state_bytes = (json.dumps(recovery_state, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    if len(recovery_state_bytes) > MAXIMUM_COMPLETION_MARKER_BYTES:
        raise _report_limit_error(
            "recovery completion-marker byte size",
            MAXIMUM_COMPLETION_MARKER_BYTES,
        )
    write_json_private_atomic(analysis / "recovery_state.json", recovery_state)
    if (
        read_regular_bytes(
            analysis / "recovery_state.json",
            maximum_bytes=MAXIMUM_COMPLETION_MARKER_BYTES,
            require_private=True,
        )
        != recovery_state_bytes
    ):
        raise TVTimeError(
            "The private recovery completion marker did not match its exact serialized bytes."
        )
    recovery_state_binding = _private_artifact_binding(
        analysis / "recovery_state.json",
        artifact_id="recovery_state",
        relative_path="analysis/recovery_state.json",
        cancellation_check=cancellation_check,
    )
    if (
        recovery_state_binding["bytes"] != len(recovery_state_bytes)
        or recovery_state_binding["sha256"] != hashlib.sha256(recovery_state_bytes).hexdigest()
    ):
        raise TVTimeError(
            "The private recovery completion marker did not match its exact serialized bytes."
        )
    sealed_analysis_filenames = _sealed_analysis_filenames(pdf_status)
    _exact_private_directory_membership(
        metadata_directory,
        expected_names=_SEALED_METADATA_FILENAMES,
        label="metadata",
        cancellation_check=cancellation_check,
    )
    _exact_private_directory_membership(
        analysis,
        expected_names=sealed_analysis_filenames,
        label="analysis",
        cancellation_check=cancellation_check,
    )
    reconcile_raw_tree(
        extraction,
        expected=source_snapshot,
        cancellation_check=cancellation_check,
    )
    for expected_binding in artifact_bindings:
        relative = PurePosixPath(expected_binding["relative_path"])
        if relative.parts[0] == "metadata":
            artifact_path = safe_join(extraction, *relative.parts)
        else:
            artifact_path = safe_join(analysis, *relative.parts[1:])
        observed_binding = _private_artifact_binding(
            artifact_path,
            artifact_id=expected_binding["id"],
            relative_path=expected_binding["relative_path"],
            cancellation_check=cancellation_check,
        )
        if observed_binding != expected_binding:
            raise TVTimeError(
                "A private recovery artifact changed before final report promotion. Preserve this "
                "incomplete output and retry into a fresh destination."
            )
    _exact_private_directory_membership(
        metadata_directory,
        expected_names=_SEALED_METADATA_FILENAMES,
        label="metadata",
        cancellation_check=cancellation_check,
    )
    _exact_private_directory_membership(
        analysis,
        expected_names=sealed_analysis_filenames,
        label="analysis",
        cancellation_check=cancellation_check,
    )
    if (
        read_regular_bytes(
            analysis / "recovery_state.json",
            maximum_bytes=MAXIMUM_COMPLETION_MARKER_BYTES,
            require_private=True,
        )
        != recovery_state_bytes
        or _private_artifact_binding(
            analysis / "recovery_state.json",
            artifact_id="recovery_state",
            relative_path="analysis/recovery_state.json",
            cancellation_check=cancellation_check,
        )
        != recovery_state_binding
    ):
        raise TVTimeError(
            "The private recovery completion marker changed before final report promotion."
        )
    if cancellation_check is not None:
        cancellation_check()
    if final_analysis.exists() or final_analysis.is_symlink():
        raise OutputExistsError(
            "The final analysis path appeared during report generation; refusing to overwrite it."
        )
    if commit_seal is not None:
        if not commit_seal():
            if cancellation_check is not None:
                cancellation_check()
            raise RecoveryCancelled(
                "Recovery was cancelled before the final private report was committed."
            )
    elif cancellation_check is not None:
        # Standalone report generation has no service token to seal. Keep its
        # final cooperative checkpoint immediately adjacent to the atomic rename.
        cancellation_check()
    promote_directory_no_replace_atomic(analysis, final_analysis, durable=True)
    secure_directory(final_analysis)
    report_path = final_analysis / "TVTime-Recovered-Data.md"
    visual_report_path = final_analysis / HTML_REPORT_FILENAME
    pdf_report_path = final_analysis / PDF_REPORT_FILENAME
    result: dict[str, Any] = {
        "report": str(report_path),
        "visual_report": str(visual_report_path),
        "pdf_status": pdf_status,
        "pdf_warning": pdf_warning,
        "series": len(series),
        "watched_movies": len(watched_movies),
        "movie_watchlist": len(movie_watchlist),
        "favorite_shows": len(favorite_shows),
        "favorite_movies": len(favorite_movies),
        "episodes": len(episodes),
        "watch_events": len(watch_events),
        "named_watch_events": named_events,
        "image_cache_references": len(image_rows),
        "trailer_references": len(trailer_rows),
        "media_urls": len(media_url_rows),
    }
    if pdf_status == "generated":
        result["pdf_report"] = str(pdf_report_path)
    return result


def build_report(
    *,
    extraction_directory: Path,
    cancellation_check: Callable[[], None] | None = None,
    commit_seal: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Build and atomically promote a report with stable storage-full classification."""

    try:
        visible_extraction = no_link_absolute_path(extraction_directory)
        with anchored_existing_extraction_root(visible_extraction) as anchored_extraction:
            result = _build_report(
                extraction_directory=anchored_extraction,
                cancellation_check=cancellation_check,
                commit_seal=commit_seal,
            )
        rebased = dict(result)
        for key in ("report", "visual_report", "pdf_report"):
            value = rebased.get(key)
            if value is None:
                continue
            path = Path(str(value))
            if path.is_absolute():
                try:
                    path.relative_to(visible_extraction)
                except ValueError as exc:
                    raise UnsafePathError(
                        "A private report path escaped its held extraction root."
                    ) from exc
            else:
                if ".." in path.parts:
                    raise UnsafePathError("A private report path escaped its held extraction root.")
                path = visible_extraction / path
            rebased[key] = str(path)
        return rebased
    except OSError as exc:
        if is_insufficient_space_error(exc):
            raise insufficient_space_error() from exc
        raise
