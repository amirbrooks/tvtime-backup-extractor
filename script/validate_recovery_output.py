from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import closing, contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tvtime_extractor.analyze import (  # noqa: E402
    MAXIMUM_ANALYSIS_CSV_BYTES,
    MAXIMUM_ANALYSIS_CSV_CELL_BYTES,
    MAXIMUM_ANALYSIS_CSV_ROW_BYTES,
    MAXIMUM_ANALYSIS_SUMMARY_BYTES,
    MAXIMUM_CACHE_JSON_DEPTH,
    MAXIMUM_CACHE_JSON_NODES,
    MAXIMUM_CACHE_JSON_STRING_BYTES,
    MAXIMUM_CACHE_PAYLOAD_BYTES,
    MAXIMUM_CACHE_ROWS,
    MAXIMUM_DERIVED_ROWS_PER_TABLE,
    MAXIMUM_SQLITE_SNAPSHOT_FILE_BYTES,
    MAXIMUM_SQLITE_SNAPSHOT_TOTAL_BYTES,
    MAXIMUM_TOTAL_CACHE_JSON_NODES,
    MAXIMUM_TOTAL_CACHE_PAYLOAD_BYTES,
    _bounded_utf8_length,
    _cache_content_bytes,
    _favorite_rows,
    _filters,
    _integer,
    _is_supported_payload,
    _parse_cache_json,
    _payload_data,
    _preflight_derived_rows,
    _validate_cache_table_limits,
    _validate_csv_escape_metadata,
    episode_identity,
    latest_by_uuid,
    latest_watch_events,
    sorting_value,
    unique_favorites,
)
from tvtime_extractor.display_text import has_display_text  # noqa: E402
from tvtime_extractor.errors import UnsupportedSchemaError  # noqa: E402
from tvtime_extractor.extract import (  # noqa: E402
    PRIMARY_DOMAIN,
    RELATED_PLUGIN_DOMAIN_PREFIX,
    TVTIME_BUNDLE_ID,
)
from tvtime_extractor.integrity import (  # noqa: E402
    INVENTORY_FIELDS,
    MAXIMUM_INVENTORY_BYTES,
    SourceSnapshot,
    reconcile_raw_tree,
    source_snapshot_from_mapping,
)
from tvtime_extractor.report import (  # noqa: E402
    _BOUND_ARTIFACTS,
    _SEALED_METADATA_FILENAMES,
    ANALYSIS_COUNT_FIELDS,
    ANALYSIS_SUMMARY_CONTRACT,
    ANALYSIS_SUMMARY_FIELDS,
    EXTRACTION_SUMMARY_FIELDS,
    MAXIMUM_CONTRACT_INTEGER,
    MAXIMUM_IMAGE_CACHE_ROWS,
    MAXIMUM_REPORT_ARTIFACT_BYTES,
    MAXIMUM_REPORT_DERIVED_ROWS,
    MAXIMUM_REPORT_INVENTORY_ROWS,
    MAXIMUM_REPORT_RENDER_INPUT_BYTES,
    MAXIMUM_REPORT_TABLE_ROWS,
    MAXIMUM_TOTAL_REPORT_TABLE_ROWS,
    RECOVERY_STATE_CONTRACT,
    RECOVERY_STATE_SCHEMA_VERSION,
    RUN_STATE_FIELDS,
    _bounded_image_cache_text,
    _private_artifact_binding,
    _ReportByteBudget,
    _ReportRowBudget,
    _sealed_analysis_filenames,
    _validate_image_cache_table_limits,
    collect_trailers,
    collect_urls,
    decode_tvtime_image_url,
    image_category,
)
from tvtime_extractor.safety import (  # noqa: E402
    EXTRACTION_DIRECTORY_NAME,
    EXTRACTION_RUN_STATE_CONTRACT,
    EXTRACTION_RUN_STATE_SCHEMA_VERSION,
    MAXIMUM_COMPLETION_MARKER_BYTES,
    _windows_close_handle,
    _windows_directory_identity,
    _windows_open_locked_directory,
    no_link_absolute_path,
    private_source_id,
    require_private_descriptor,
    require_private_path,
    safe_domain_component,
    safe_manifest_relative_path,
    sanitize_public_url,
    validate_file_id,
)
from tvtime_extractor.visual_report import (  # noqa: E402
    HTML_REPORT_FILENAME,
    PDF_FIDELITY_WARNING,
    PDF_REPORT_FILENAME,
    PDFCapabilityError,
    VisualReportModel,
    build_visual_report_model,
    render_html_report,
    render_markdown_report,
    write_pdf_report,
)

MAXIMUM_INPUT_BYTES = 32 * 1024
MAXIMUM_JSON_BYTES = MAXIMUM_ANALYSIS_SUMMARY_BYTES
MAXIMUM_CSV_BYTES = MAXIMUM_ANALYSIS_CSV_BYTES
MAXIMUM_CSV_ROWS = MAXIMUM_DERIVED_ROWS_PER_TABLE
MAXIMUM_JSON_DEPTH = MAXIMUM_CACHE_JSON_DEPTH
MAXIMUM_JSON_NODES = MAXIMUM_CACHE_JSON_NODES
MAXIMUM_JSON_STRING_BYTES = MAXIMUM_CACHE_JSON_STRING_BYTES
MAXIMUM_PDF_BYTES = 64 * 1024 * 1024
MAXIMUM_PDF_DECOMPRESSED_BYTES = 32 * 1024 * 1024
MAXIMUM_PDF_PAGES = 2_048
MAXIMUM_PDF_OBJECTS = 100_000
MAXIMUM_PDF_OBJECT_DEPTH = 256
MAXIMUM_PDF_PAGE_TEXT_BYTES = 8 * 1024 * 1024
MAXIMUM_PDF_TOTAL_TEXT_BYTES = 64 * 1024 * 1024
MAXIMUM_REPORT_BYTES = MAXIMUM_REPORT_ARTIFACT_BYTES
MAXIMUM_SQLITE_FILE_BYTES = MAXIMUM_SQLITE_SNAPSHOT_FILE_BYTES
MAXIMUM_SQLITE_ROWS = MAXIMUM_CACHE_ROWS
EXPECTED_DIRECTORY_MODE = 0o700
EXPECTED_FILE_MODE = 0o600
PRIVATE_STAGING_PREFIX = ".tvtime-validator-"

RECOVERY_STATE_FIELDS = frozenset(
    {
        "schema_version",
        "contract",
        "status",
        "completed_utc",
        "pdf",
        "source_snapshot",
        "aggregates",
        "artifacts",
    }
)

CSV_FIELDS: dict[str, tuple[str, ...]] = {
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
    "watched_movies.csv": (),
    "movie_watchlist.csv": (),
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
    "favorite_movies.csv": (),
    "episode_cache_unique.csv": (),
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
    "trailer_references.csv": (
        "title",
        "trailer_name",
        "runtime_seconds",
        "url",
        "thumbnail_url",
    ),
    "media_url_inventory.csv": ("kind", "host", "field_path", "url"),
    "image_cache_references.csv": (
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
    ),
}
CSV_FIELDS["watched_movies.csv"] = CSV_FIELDS["movie_library.csv"]
CSV_FIELDS["movie_watchlist.csv"] = CSV_FIELDS["movie_library.csv"]
CSV_FIELDS["favorite_movies.csv"] = CSV_FIELDS["favorite_shows.csv"]
CSV_FIELDS["episode_cache_unique.csv"] = CSV_FIELDS["episode_cache.csv"]

PRE_REPORT_CSV_NAMES = frozenset(
    name
    for name in CSV_FIELDS
    if name
    not in {
        "trailer_references.csv",
        "media_url_inventory.csv",
        "image_cache_references.csv",
    }
)


class ValidationFailure(Exception):
    def __init__(self, gate: str, passed_gates: Sequence[str] = ()) -> None:
        super().__init__("recovery output validation failed")
        self.gate = gate
        self.passed_gates = tuple(passed_gates)


@dataclass(frozen=True)
class ValidationResult:
    gates: tuple[str, ...]
    counts: tuple[tuple[str, int], ...]


@dataclass
class _State:
    output_root: Path
    extraction: Path = Path()
    raw: Path = Path()
    metadata: Path = Path()
    manifest: Path = Path()
    analysis: Path = Path()
    run_state: dict[str, Any] = field(default_factory=dict)
    extraction_summary: dict[str, Any] = field(default_factory=dict)
    analysis_summary: dict[str, Any] = field(default_factory=dict)
    recovery_state: dict[str, Any] = field(default_factory=dict)
    source_snapshot: SourceSnapshot | None = None
    inventory: list[dict[str, str]] = field(default_factory=list)
    size_discrepancies: list[dict[str, object]] = field(default_factory=list)
    tables: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    payloads: list[object] = field(default_factory=list)
    image_cache_status: str = ""
    model: VisualReportModel | None = None
    recovery_state_bytes: bytes = b""
    domains_bytes: bytes = b""
    artifact_bindings: list[dict[str, Any]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    passed_gates: list[str] = field(default_factory=list)


def _fail() -> None:
    raise ValueError("invalid recovery output")


def _exact_keys(value: Mapping[str, object], expected: frozenset[str] | set[str]) -> None:
    if set(value) != set(expected):
        _fail()


def _nonnegative_int(value: object) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > MAXIMUM_CONTRACT_INTEGER
    ):
        _fail()
    return value


def _positive_int(value: object) -> int:
    result = _nonnegative_int(value)
    if result == 0:
        _fail()
    return result


def _canonical_decimal(value: object) -> int:
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdecimal():
        _fail()
    parsed = int(value)
    if str(parsed) != value:
        _fail()
    return parsed


def _sha256(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail()
    return value


def _utc_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value.endswith("+00:00"):
        _fail()
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        _fail()
    if parsed.utcoffset() != timedelta(0):
        _fail()
    return value


def _identity(value: os.stat_result) -> tuple[int, int]:
    return (getattr(value, "st_dev", 0), getattr(value, "st_ino", 0))


def _read_bytes(path: Path, *, maximum_bytes: int | None = None) -> bytes:
    before = require_private_path(
        path,
        expected_type=stat.S_IFREG,
        expected_mode=EXPECTED_FILE_MODE,
    )
    if maximum_bytes is not None and (before.st_size <= 0 or before.st_size > maximum_bytes):
        _fail()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _identity(before) != _identity(opened) or not stat.S_ISREG(opened.st_mode):
            _fail()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if maximum_bytes is not None and total > maximum_bytes:
                _fail()
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(opened, name, 0) != getattr(after, name, 0) for name in stable_fields):
        _fail()
    path_after = require_private_path(
        path,
        expected_type=stat.S_IFREG,
        expected_mode=EXPECTED_FILE_MODE,
    )
    if _identity(after) != _identity(path_after) or total != after.st_size:
        _fail()
    return b"".join(chunks)


def _strict_json(path: Path, *, maximum_bytes: int = MAXIMUM_JSON_BYTES) -> dict[str, Any]:
    payload = _read_bytes(path, maximum_bytes=maximum_bytes)

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                _fail()
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        _fail()
    if not isinstance(value, dict):
        _fail()
    _validate_json_complexity(value)
    return value


def _validate_json_complexity(value: object) -> None:
    """Bound already byte-limited JSON before recursive consumers inspect it."""

    pending: list[tuple[object, int]] = [(value, 0)]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > MAXIMUM_JSON_NODES or depth > MAXIMUM_JSON_DEPTH:
            _fail()
        if isinstance(item, str):
            try:
                _bounded_utf8_length(
                    item,
                    subject="JSON string byte size",
                    maximum_bytes=MAXIMUM_JSON_STRING_BYTES,
                )
            except UnsupportedSchemaError:
                _fail()
        elif isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    _fail()
                pending.append((key, depth + 1))
                pending.append((child, depth + 1))
        elif isinstance(item, (list, tuple)):
            pending.extend((child, depth + 1) for child in item)


def _require_directory(path: Path) -> None:
    require_private_path(
        path,
        expected_type=stat.S_IFDIR,
        expected_mode=EXPECTED_DIRECTORY_MODE,
    )


def _require_file(path: Path) -> None:
    require_private_path(
        path,
        expected_type=stat.S_IFREG,
        expected_mode=EXPECTED_FILE_MODE,
    )


def _exact_directory(
    directory: Path,
    expected: Mapping[str, int],
) -> None:
    _require_directory(directory)
    observed: dict[str, int] = {}
    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.name in observed:
                _fail()
            metadata = entry.stat(follow_symlinks=False)
            file_type = stat.S_IFMT(metadata.st_mode)
            observed[entry.name] = file_type
            expected_type = expected.get(entry.name)
            if expected_type is None or expected_type != file_type:
                _fail()
            if expected_type == stat.S_IFDIR:
                _require_directory(directory / entry.name)
            else:
                _require_file(directory / entry.name)
    if observed != dict(expected):
        _fail()


def _validate_private_tree(root: Path) -> None:
    _require_directory(root)
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                metadata = entry.stat(follow_symlinks=False)
                child = directory / entry.name
                if stat.S_ISDIR(metadata.st_mode):
                    _require_directory(child)
                    pending.append(child)
                elif stat.S_ISREG(metadata.st_mode):
                    _require_file(child)
                else:
                    _fail()


def _root_layout(state: _State) -> None:
    _exact_directory(state.output_root, {EXTRACTION_DIRECTORY_NAME: stat.S_IFDIR})
    state.extraction = state.output_root / EXTRACTION_DIRECTORY_NAME
    state.raw = state.extraction / "raw"
    state.metadata = state.extraction / "metadata"
    state.manifest = state.extraction / "manifest"
    state.analysis = state.extraction / "analysis"
    _exact_directory(
        state.extraction,
        {
            "raw": stat.S_IFDIR,
            "metadata": stat.S_IFDIR,
            "manifest": stat.S_IFDIR,
            "analysis": stat.S_IFDIR,
        },
    )
    _validate_private_tree(state.raw)
    _exact_directory(
        state.metadata,
        {name: stat.S_IFREG for name in _SEALED_METADATA_FILENAMES},
    )
    _exact_directory(state.manifest, {})
    _require_directory(state.analysis)
    allowed_analysis = _sealed_analysis_filenames("generated") | _sealed_analysis_filenames(
        "omitted"
    )
    observed: dict[str, int] = {}
    with os.scandir(state.analysis) as entries:
        for entry in entries:
            metadata = entry.stat(follow_symlinks=False)
            if entry.name not in allowed_analysis or not stat.S_ISREG(metadata.st_mode):
                _fail()
            _require_file(state.analysis / entry.name)
            observed[entry.name] = stat.S_IFREG
    if "recovery_state.json" not in observed:
        _fail()


def _validate_source_snapshot_shape(value: object) -> SourceSnapshot:
    if not isinstance(value, dict):
        _fail()
    _exact_keys(value, {"contract", "inventory", "raw_tree"})
    inventory = value.get("inventory")
    raw_tree = value.get("raw_tree")
    if not isinstance(inventory, dict) or not isinstance(raw_tree, dict):
        _fail()
    _exact_keys(inventory, {"bytes", "sha256"})
    _exact_keys(raw_tree, {"files", "bytes", "sha256"})
    _positive_int(inventory.get("bytes"))
    _sha256(inventory.get("sha256"))
    _nonnegative_int(raw_tree.get("files"))
    _nonnegative_int(raw_tree.get("bytes"))
    _sha256(raw_tree.get("sha256"))
    return source_snapshot_from_mapping(value)


def _completion_contracts(state: _State) -> None:
    state.run_state = _strict_json(
        state.metadata / "run_state.json",
        maximum_bytes=MAXIMUM_COMPLETION_MARKER_BYTES,
    )
    state.extraction_summary = _strict_json(state.metadata / "summary.json")
    state.analysis_summary = _strict_json(state.analysis / "analysis_summary.json")
    recovery_path = state.analysis / "recovery_state.json"
    state.recovery_state_bytes = _read_bytes(
        recovery_path,
        maximum_bytes=MAXIMUM_COMPLETION_MARKER_BYTES,
    )
    state.recovery_state = _strict_json(
        recovery_path,
        maximum_bytes=MAXIMUM_COMPLETION_MARKER_BYTES,
    )

    _exact_keys(state.run_state, RUN_STATE_FIELDS)
    if (
        state.run_state.get("schema_version") != EXTRACTION_RUN_STATE_SCHEMA_VERSION
        or state.run_state.get("contract") != EXTRACTION_RUN_STATE_CONTRACT
        or state.run_state.get("status") != "complete"
    ):
        _fail()
    _utc_timestamp(state.run_state.get("completed_utc"))
    for name in (
        "files_expected",
        "files_extracted",
        "bytes_extracted",
        "selected_declared_bytes",
        "size_discrepancy_count",
    ):
        _nonnegative_int(state.run_state.get(name))
    if (
        state.run_state["files_expected"] != state.run_state["files_extracted"]
        or state.run_state["size_discrepancy_count"] > state.run_state["files_expected"]
    ):
        _fail()
    run_snapshot = _validate_source_snapshot_shape(state.run_state.get("source_snapshot"))

    _exact_keys(state.extraction_summary, EXTRACTION_SUMMARY_FIELDS)
    if (
        state.extraction_summary.get("bundle_id") != TVTIME_BUNDLE_ID
        or state.extraction_summary.get("failures") != []
        or state.extraction_summary.get("decrypted_manifest_included") is not False
    ):
        _fail()
    _utc_timestamp(state.extraction_summary.get("completed_utc"))
    if state.extraction_summary["completed_utc"] != state.run_state["completed_utc"]:
        _fail()
    domains = state.extraction_summary.get("domains")
    if (
        not isinstance(domains, list)
        or not domains
        or any(not isinstance(item, str) for item in domains)
        or domains != sorted(set(domains))
        or PRIMARY_DOMAIN not in domains
        or any(
            item != PRIMARY_DOMAIN and not item.startswith(RELATED_PLUGIN_DOMAIN_PREFIX)
            for item in domains
        )
        or any(item != safe_domain_component(item) for item in domains)
    ):
        _fail()
    for name in (
        "files_expected",
        "files_extracted",
        "bytes_extracted",
        "selected_declared_bytes",
    ):
        _nonnegative_int(state.extraction_summary.get(name))
    if not isinstance(state.extraction_summary.get("size_discrepancies"), list):
        _fail()

    _exact_keys(state.analysis_summary, ANALYSIS_SUMMARY_FIELDS)
    if (
        state.analysis_summary.get("schema_version") != RECOVERY_STATE_SCHEMA_VERSION
        or state.analysis_summary.get("contract") != ANALYSIS_SUMMARY_CONTRACT
        or state.analysis_summary.get("status") != "complete"
        or state.analysis_summary.get("dio_cache_quick_check") != "ok"
        or state.analysis_summary.get("parser_status") not in {"recognized", "empty"}
        or state.analysis_summary.get("raw_cache_exported") is not False
    ):
        _fail()
    for name in ANALYSIS_COUNT_FIELDS:
        _nonnegative_int(state.analysis_summary.get(name))
    if (
        state.analysis_summary["episode_cache_unique"]
        > state.analysis_summary["episode_cache_rows"]
    ):
        _fail()
    if not isinstance(state.analysis_summary.get("sqlite_integrity"), dict):
        _fail()
    for key, value in state.analysis_summary["sqlite_integrity"].items():
        if not isinstance(key, str):
            _fail()
        _nonnegative_int(value)
    if not isinstance(state.analysis_summary.get("csv_spreadsheet_escaped_cells"), dict):
        _fail()
    try:
        _validate_csv_escape_metadata(state.analysis_summary["csv_spreadsheet_escaped_cells"])
    except UnsupportedSchemaError:
        _fail()

    _exact_keys(state.recovery_state, RECOVERY_STATE_FIELDS)
    if (
        state.recovery_state.get("schema_version") != RECOVERY_STATE_SCHEMA_VERSION
        or state.recovery_state.get("contract") != RECOVERY_STATE_CONTRACT
        or state.recovery_state.get("status") != "complete"
    ):
        _fail()
    _utc_timestamp(state.recovery_state.get("completed_utc"))
    recovery_snapshot = _validate_source_snapshot_shape(state.recovery_state.get("source_snapshot"))
    if recovery_snapshot != run_snapshot:
        _fail()
    state.source_snapshot = run_snapshot

    pdf = state.recovery_state.get("pdf")
    aggregates = state.recovery_state.get("aggregates")
    artifacts = state.recovery_state.get("artifacts")
    if (
        not isinstance(pdf, dict)
        or not isinstance(aggregates, dict)
        or not isinstance(artifacts, list)
    ):
        _fail()
    _exact_keys(pdf, {"status", "artifact_id"})
    pdf_status = pdf.get("status")
    if pdf_status not in {"generated", "omitted"}:
        _fail()
    expected_pdf_id = "pdf_report" if pdf_status == "generated" else None
    if pdf.get("artifact_id") != expected_pdf_id:
        _fail()
    _exact_keys(aggregates, {"extraction", "analysis", "report"})
    extraction_aggregate = aggregates.get("extraction")
    analysis_aggregate = aggregates.get("analysis")
    report_aggregate = aggregates.get("report")
    if not all(
        isinstance(item, dict)
        for item in (extraction_aggregate, analysis_aggregate, report_aggregate)
    ):
        _fail()
    _exact_keys(
        extraction_aggregate,
        {
            "files_expected",
            "files_extracted",
            "bytes_extracted",
            "selected_declared_bytes",
            "size_discrepancy_count",
        },
    )
    _exact_keys(
        analysis_aggregate,
        {
            "series_library",
            "watched_movies",
            "movie_watchlist",
            "favorite_shows",
            "favorite_movies",
            "watch_events",
            "watch_events_with_titles",
            "episode_cache_unique",
            "parser_status",
        },
    )
    report_fields = {
        "image_cache_references",
        "trailer_references",
        "media_urls",
        "pdf_status",
    }
    if pdf_status == "omitted":
        report_fields.add("pdf_omission_reason")
    _exact_keys(report_aggregate, report_fields)
    for name in (
        "image_cache_references",
        "trailer_references",
        "media_urls",
    ):
        _nonnegative_int(report_aggregate.get(name))
    if report_aggregate.get("pdf_status") != pdf_status:
        _fail()
    if (
        pdf_status == "omitted"
        and report_aggregate.get("pdf_omission_reason") != PDF_FIDELITY_WARNING
    ):
        _fail()
    _exact_directory(
        state.analysis,
        {name: stat.S_IFREG for name in _sealed_analysis_filenames(pdf_status)},
    )


def _read_csv_rows(
    path: Path,
    fields: Sequence[str],
    *,
    escaped_cells: object = None,
) -> list[dict[str, str]]:
    filename = path.name
    maximum_bytes = MAXIMUM_INVENTORY_BYTES if filename == "inventory.csv" else MAXIMUM_CSV_BYTES
    if filename == "inventory.csv":
        maximum_rows = MAXIMUM_REPORT_INVENTORY_ROWS
    elif filename == "image_cache_references.csv":
        maximum_rows = MAXIMUM_IMAGE_CACHE_ROWS
    elif filename in {
        "trailer_references.csv",
        "media_url_inventory.csv",
    }:
        maximum_rows = MAXIMUM_REPORT_DERIVED_ROWS
    elif filename in {
        "series_library.csv",
        "watched_movies.csv",
        "movie_watchlist.csv",
        "favorite_shows.csv",
        "favorite_movies.csv",
        "episode_cache_unique.csv",
        "watch_events_named.csv",
    }:
        maximum_rows = MAXIMUM_REPORT_TABLE_ROWS
    else:
        maximum_rows = MAXIMUM_CSV_ROWS
    try:
        text = _read_bytes(path, maximum_bytes=maximum_bytes).decode("utf-8")
        previous_field_limit = csv.field_size_limit()
        try:
            csv.field_size_limit(MAXIMUM_ANALYSIS_CSV_CELL_BYTES + 1)
            reader = csv.DictReader(io.StringIO(text, newline=""))
            if tuple(reader.fieldnames or ()) != tuple(fields):
                _fail()
            rows: list[dict[str, str]] = []
            for row_number, row in enumerate(reader, 1):
                if row_number > maximum_rows:
                    _fail()
                if None in row or any(row.get(field) is None for field in fields):
                    _fail()
                row_bytes = 0
                for value in row.values():
                    if value is None:
                        _fail()
                    try:
                        cell_bytes = _bounded_utf8_length(
                            value,
                            subject="analysis CSV cell byte size",
                            maximum_bytes=MAXIMUM_ANALYSIS_CSV_CELL_BYTES + 1,
                        )
                    except UnsupportedSchemaError:
                        _fail()
                    row_bytes += cell_bytes
                if row_bytes > MAXIMUM_ANALYSIS_CSV_ROW_BYTES:
                    _fail()
                rows.append(row)
        finally:
            csv.field_size_limit(previous_field_limit)
    except (UnicodeDecodeError, csv.Error, RecursionError):
        _fail()
    if escaped_cells is None:
        derived_escaped = filename in {
            "trailer_references.csv",
            "media_url_inventory.csv",
            "image_cache_references.csv",
        }
        for row in rows:
            for value in row.values():
                semantic = value[1:] if derived_escaped and value.startswith("'") else value
                try:
                    _bounded_utf8_length(
                        semantic,
                        subject="analysis CSV cell byte size",
                        maximum_bytes=MAXIMUM_ANALYSIS_CSV_CELL_BYTES,
                    )
                except UnsupportedSchemaError:
                    _fail()
        return rows
    if not isinstance(escaped_cells, list) or not escaped_cells:
        _fail()
    seen: set[tuple[int, str]] = set()
    for item in escaped_cells:
        if not isinstance(item, dict):
            _fail()
        _exact_keys(item, {"row", "field"})
        row_number = item.get("row")
        field_name = item.get("field")
        if (
            not isinstance(row_number, int)
            or isinstance(row_number, bool)
            or row_number < 1
            or not isinstance(field_name, str)
            or not field_name
        ):
            _fail()
        coordinate = (row_number, field_name)
        if coordinate in seen or row_number > len(rows) or field_name not in rows[row_number - 1]:
            _fail()
        value = rows[row_number - 1][field_name]
        if not value.startswith("'") or not value[1:].startswith(("=", "+", "-", "@", "\t", "\r")):
            _fail()
        rows[row_number - 1][field_name] = value[1:]
        seen.add(coordinate)
    for row in rows:
        for value in row.values():
            try:
                _bounded_utf8_length(
                    value,
                    subject="analysis CSV cell byte size",
                    maximum_bytes=MAXIMUM_ANALYSIS_CSV_CELL_BYTES,
                )
            except UnsupportedSchemaError:
                _fail()
    return rows


def _source_integrity(state: _State) -> None:
    if state.source_snapshot is None:
        _fail()
    observed_snapshot = reconcile_raw_tree(state.extraction, expected=state.source_snapshot)
    if observed_snapshot != state.source_snapshot:
        _fail()
    state.inventory = _read_csv_rows(
        state.metadata / "inventory.csv",
        INVENTORY_FIELDS,
    )
    previous_key: tuple[str, str] | None = None
    discrepancies: list[dict[str, object]] = []
    actual_bytes = 0
    declared_bytes = 0
    for row in state.inventory:
        if row["file_id"] != validate_file_id(row["file_id"]):
            _fail()
        if row["domain"] != safe_domain_component(row["domain"]):
            _fail()
        relative = safe_manifest_relative_path(row["relative_path"])
        if relative.as_posix() != row["relative_path"]:
            _fail()
        current_key = (row["domain"], row["relative_path"])
        if previous_key is not None and current_key < previous_key:
            _fail()
        previous_key = current_key
        declared = _canonical_decimal(row["declared_size"])
        actual = _canonical_decimal(row["actual_size"])
        expected_match = "True" if declared == actual else "False"
        if row["size_match"] != expected_match:
            _fail()
        _sha256(row["sha256"])
        actual_bytes += actual
        declared_bytes += declared
        if declared != actual:
            discrepancies.append(
                {
                    "domain": row["domain"],
                    "relative_path": row["relative_path"],
                    "declared_size": declared,
                    "actual_size": actual,
                }
            )
    state.size_discrepancies = discrepancies
    summary_discrepancies = state.extraction_summary["size_discrepancies"]
    if summary_discrepancies != discrepancies:
        _fail()
    expected_counts = {
        "files_expected": len(state.inventory),
        "files_extracted": len(state.inventory),
        "bytes_extracted": actual_bytes,
        "selected_declared_bytes": declared_bytes,
    }
    if any(state.extraction_summary.get(key) != value for key, value in expected_counts.items()):
        _fail()
    expected_run = {
        **expected_counts,
        "size_discrepancy_count": len(discrepancies),
    }
    if any(state.run_state.get(key) != value for key, value in expected_run.items()):
        _fail()
    if (
        observed_snapshot.raw_tree_files != len(state.inventory)
        or observed_snapshot.raw_tree_bytes != actual_bytes
    ):
        _fail()
    domains = state.extraction_summary["domains"]
    expected_domains = "\n".join(domains) + "\n"
    state.domains_bytes = _read_bytes(
        state.metadata / "domains.txt",
        maximum_bytes=MAXIMUM_INPUT_BYTES,
    )
    try:
        domains_text = state.domains_bytes.decode("utf-8")
    except UnicodeDecodeError:
        _fail()
    if domains_text != expected_domains:
        _fail()


def _artifact_bindings(state: _State) -> None:
    pdf_status = state.recovery_state["pdf"]["status"]
    expected = list(_BOUND_ARTIFACTS)
    if pdf_status == "generated":
        expected.append(("pdf_report", f"analysis/{PDF_REPORT_FILENAME}"))
    bindings = state.recovery_state["artifacts"]
    if len(bindings) != len(expected):
        _fail()
    for binding, (artifact_id, relative_path) in zip(bindings, expected, strict=True):
        if not isinstance(binding, dict):
            _fail()
        _exact_keys(binding, {"id", "relative_path", "bytes", "sha256"})
        if binding.get("id") != artifact_id or binding.get("relative_path") != relative_path:
            _fail()
        _positive_int(binding.get("bytes"))
        _sha256(binding.get("sha256"))
        observed = _private_artifact_binding(
            state.extraction / Path(relative_path),
            artifact_id=artifact_id,
            relative_path=relative_path,
        )
        if observed != binding:
            _fail()
    state.artifact_bindings = list(bindings)


def _row_counter(rows: Sequence[Mapping[str, str]]) -> Counter[str]:
    return Counter(json.dumps(row, separators=(",", ":"), sort_keys=True) for row in rows)


def _safe_remove_private_staging(
    path: Path,
    *,
    output_root: Path,
    expected_identity: tuple[int, int],
) -> None:
    if (
        path.parent != output_root
        or not path.name.startswith(PRIVATE_STAGING_PREFIX)
        or path.name in {PRIVATE_STAGING_PREFIX, ".", ".."}
    ):
        _fail()
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_IFMT(metadata.st_mode) != stat.S_IFDIR or _identity(metadata) != expected_identity:
        _fail()
    if os.name != "nt" and not shutil.rmtree.avoids_symlink_attacks:
        _fail()
    shutil.rmtree(path)
    if path.exists() or path.is_symlink():
        _fail()


@contextmanager
def _private_staging_directory(state: _State) -> Iterator[Path]:
    """Create ephemeral private workspace only on the validated output volume."""

    root_before = require_private_path(
        state.output_root,
        expected_type=stat.S_IFDIR,
        expected_mode=EXPECTED_DIRECTORY_MODE,
    )
    windows_root_handle = -1
    windows_root_identity: tuple[int, int] | None = None
    if os.name == "nt":
        windows_root_handle, windows_root_identity = _windows_open_locked_directory(
            state.output_root
        )
    try:
        path = Path(tempfile.mkdtemp(prefix=PRIVATE_STAGING_PREFIX, dir=state.output_root))
        stage_identity = _identity(path.lstat())
        try:
            if path.parent != state.output_root or not path.name.startswith(PRIVATE_STAGING_PREFIX):
                _fail()
            _require_directory(path)
            root_after = require_private_path(
                state.output_root,
                expected_type=stat.S_IFDIR,
                expected_mode=EXPECTED_DIRECTORY_MODE,
            )
            if _identity(root_before) != _identity(root_after):
                _fail()
            yield path
        finally:
            _safe_remove_private_staging(
                path,
                output_root=state.output_root,
                expected_identity=stage_identity,
            )
            if os.name == "nt":
                if (
                    windows_root_identity is None
                    or _windows_directory_identity(windows_root_handle) != windows_root_identity
                ):
                    _fail()
                os.utime(
                    state.output_root,
                    ns=(root_before.st_atime_ns, root_before.st_mtime_ns),
                )
                if _windows_directory_identity(windows_root_handle) != windows_root_identity:
                    _fail()
            else:
                os.utime(
                    state.output_root,
                    ns=(root_before.st_atime_ns, root_before.st_mtime_ns),
                    follow_symlinks=False,
                )
            root_after_cleanup = require_private_path(
                state.output_root,
                expected_type=stat.S_IFDIR,
                expected_mode=EXPECTED_DIRECTORY_MODE,
            )
            if (
                _identity(root_before) != _identity(root_after_cleanup)
                or root_after_cleanup.st_mtime_ns != root_before.st_mtime_ns
            ):
                _fail()
    finally:
        if windows_root_handle >= 0:
            _windows_close_handle(windows_root_handle)


def _copy_private_file(source: Path, destination: Path, *, maximum_bytes: int) -> int:
    before = _require_bounded_file(source, maximum_bytes)
    _require_directory(destination.parent)
    source_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    source_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    destination_flags |= getattr(os, "O_BINARY", 0)
    destination_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_descriptor = -1
    destination_descriptor = -1
    total = 0
    try:
        source_descriptor = os.open(source, source_flags)
        opened_source = require_private_descriptor(
            source_descriptor,
            expected_type=stat.S_IFREG,
            expected_mode=EXPECTED_FILE_MODE,
        )
        if _identity(before) != _identity(opened_source):
            _fail()
        destination_descriptor = os.open(
            destination,
            destination_flags,
            EXPECTED_FILE_MODE,
        )
        if os.name != "nt":
            os.fchmod(destination_descriptor, EXPECTED_FILE_MODE)
        require_private_descriptor(
            destination_descriptor,
            expected_type=stat.S_IFREG,
            expected_mode=EXPECTED_FILE_MODE,
        )
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                _fail()
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    _fail()
                view = view[written:]
        after_source = os.fstat(source_descriptor)
        after_destination = os.fstat(destination_descriptor)
        if (
            _identity(opened_source) != _identity(after_source)
            or total != opened_source.st_size
            or after_destination.st_size != total
        ):
            _fail()
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if source_descriptor >= 0:
            os.close(source_descriptor)
    _require_file(destination)
    return total


def _require_bounded_file(path: Path, maximum_bytes: int) -> os.stat_result:
    metadata = require_private_path(
        path,
        expected_type=stat.S_IFREG,
        expected_mode=EXPECTED_FILE_MODE,
    )
    if metadata.st_size < 0 or metadata.st_size > maximum_bytes:
        _fail()
    return metadata


@contextmanager
def _sqlite_snapshot(state: _State, source: Path) -> Iterator[sqlite3.Connection]:
    candidates: list[tuple[Path, os.stat_result]] = []
    total_bytes = 0
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = source.with_name(source.name + suffix)
        try:
            candidate.lstat()
        except FileNotFoundError:
            if not suffix:
                _fail()
            continue
        metadata = _require_bounded_file(candidate, MAXIMUM_SQLITE_FILE_BYTES)
        total_bytes += metadata.st_size
        if total_bytes > MAXIMUM_SQLITE_SNAPSHOT_TOTAL_BYTES:
            _fail()
        candidates.append((candidate, metadata))
    with _private_staging_directory(state) as temporary:
        target = temporary / source.name
        copied_bytes = 0
        for candidate, _metadata in candidates:
            destination = temporary / candidate.name
            copied_bytes += _copy_private_file(
                candidate,
                destination,
                maximum_bytes=min(
                    MAXIMUM_SQLITE_FILE_BYTES,
                    MAXIMUM_SQLITE_SNAPSHOT_TOTAL_BYTES - copied_bytes,
                ),
            )
        connection = sqlite3.connect(target, timeout=0)
        try:
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


def _raw_cache_index(
    state: _State,
) -> tuple[list[dict[str, str]], list[tuple[str, object]]]:
    database = state.raw / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
    rows: list[dict[str, str]] = []
    payload_records: list[tuple[str, object]] = []
    unique_hashes: dict[str, str] = {}
    with _sqlite_snapshot(state, database) as connection:
        if str(connection.execute("PRAGMA quick_check").fetchone()[0]) != "ok":
            _fail()
        available_columns = {
            str(row[1]).casefold() for row in connection.execute("PRAGMA table_info(cache_dio)")
        }
        if not {"key", "subkey", "content", "statuscode"} <= available_columns:
            _fail()
        try:
            _validate_cache_table_limits(connection)
        except (UnsupportedSchemaError, sqlite3.Error):
            _fail()
        with closing(
            connection.execute(
                "SELECT key, subKey, content, statusCode FROM cache_dio ORDER BY key, subKey"
            )
        ) as records:
            total_payload_bytes = 0
            total_json_nodes = 0
            for row_number, (key, subkey, content, status_code) in enumerate(records, 1):
                if row_number > MAXIMUM_SQLITE_ROWS:
                    _fail()
                try:
                    raw_content = _cache_content_bytes(content)
                except UnsupportedSchemaError:
                    _fail()
                if len(raw_content) > MAXIMUM_CACHE_PAYLOAD_BYTES:
                    _fail()
                total_payload_bytes += len(raw_content)
                if total_payload_bytes > MAXIMUM_TOTAL_CACHE_PAYLOAD_BYTES:
                    _fail()
                source_id = private_source_id(key, subkey)
                digest = hashlib.sha256(raw_content).hexdigest()
                duplicate_of = unique_hashes.get(digest, "")
                unique_hashes.setdefault(digest, source_id)
                try:
                    payload, json_valid, node_count = _parse_cache_json(raw_content)
                except UnsupportedSchemaError:
                    _fail()
                total_json_nodes += node_count
                if total_json_nodes > MAXIMUM_TOTAL_CACHE_JSON_NODES:
                    _fail()
                if json_valid:
                    payload_records.append((source_id, payload))
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
                rows.append(
                    {
                        "source_id": source_id,
                        "status_code": "" if status_code is None else str(status_code),
                        "bytes": str(len(raw_content)),
                        "sha256": digest,
                        "duplicate_of": duplicate_of,
                        "json_valid": str(json_valid),
                        "shape": shape,
                        "data_type": data_type,
                        "object_count": str(object_count),
                        "exported_file": "",
                    }
                )
    return rows, payload_records


def _spreadsheet_value(value: object) -> str:
    text = "" if value is None else str(value)
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return text


def _serialized_rows(
    rows: Sequence[Mapping[str, object]],
    fields: Sequence[str],
) -> list[dict[str, str]]:
    return [
        {field_name: _spreadsheet_value(row.get(field_name, "")) for field_name in fields}
        for row in rows
    ]


def _plain_serialized_rows(
    rows: Sequence[Mapping[str, object]],
    fields: Sequence[str],
) -> list[dict[str, str]]:
    return [
        {
            field_name: "" if row.get(field_name, "") is None else str(row.get(field_name, ""))
            for field_name in fields
        }
        for row in rows
    ]


def _expected_core_tables(
    payload_records: Sequence[tuple[str, object]],
) -> dict[str, list[dict[str, str]]]:
    """Derive title-bearing tables directly from the immutable raw cache payloads."""

    try:
        _preflight_derived_rows(
            list(payload_records),
            cancellation_check=None,
        )
    except UnsupportedSchemaError:
        _fail()
    watch_events: list[dict[str, Any]] = []
    list_objects: list[dict[str, Any]] = []
    favorite_movies: list[dict[str, Any]] = []
    favorite_shows: list[dict[str, Any]] = []
    episode_rows: list[dict[str, Any]] = []
    for source_id, payload in payload_records:
        data = _payload_data(payload)
        if isinstance(data, dict) and data.get("type") == "watch":
            objects = data.get("objects")
            if isinstance(objects, list):
                watch_events.extend(item for item in objects if isinstance(item, dict))
        if isinstance(data, dict) and data.get("type") == "list":
            objects = data.get("objects")
            if isinstance(objects, list):
                object_dicts = [item for item in objects if isinstance(item, dict)]
                if data.get("id") == "favorite-movies":
                    favorite_movies.extend(object_dicts)
                elif data.get("id") == "favorite-series":
                    favorite_shows.extend(object_dicts)
                else:
                    list_objects.extend(object_dicts)
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict) or not {"air_date", "show", "number"} <= item.keys():
                    continue
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
    ordered: dict[str, Sequence[Mapping[str, object]]] = {
        "watch_events.csv": watch_events,
        "watch_events_named.csv": named_watch_events,
        "movie_library.csv": sorted(movie_library, key=lambda row: str(row["name"]).casefold()),
        "watched_movies.csv": sorted(watched_movies, key=lambda row: str(row["watched_at"])),
        "movie_watchlist.csv": sorted(movie_watchlist, key=lambda row: str(row["name"]).casefold()),
        "series_library.csv": sorted(series_library, key=lambda row: str(row["name"]).casefold()),
        "favorite_movies.csv": _favorite_rows(favorite_movies),
        "favorite_shows.csv": _favorite_rows(favorite_shows),
        "episode_cache.csv": episode_rows,
        "episode_cache_unique.csv": sorted(
            episodes_unique,
            key=lambda row: (
                str(row["show_name"]).casefold(),
                _integer(row["season"]),
                _integer(row["episode"]),
            ),
        ),
    }
    return {name: _plain_serialized_rows(rows, CSV_FIELDS[name]) for name, rows in ordered.items()}


def _media_rows(payloads: Sequence[object]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    all_urls: dict[str, str] = {}
    trailers_by_url: dict[str, dict[str, str]] = {}
    media_budget = _ReportRowBudget(maximum_total=MAXIMUM_REPORT_DERIVED_ROWS)
    for payload in payloads:
        try:
            for field_path, url in collect_urls(payload, row_budget=media_budget):
                all_urls.setdefault(url, field_path)
            for trailer in collect_trailers(payload, row_budget=media_budget):
                trailers_by_url.setdefault(trailer["url"], trailer)
        except UnsupportedSchemaError:
            _fail()
    trailers = sorted(
        trailers_by_url.values(),
        key=lambda row: (row["title"].casefold(), row["url"]),
    )
    media: list[dict[str, str]] = []
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
        media.append({"kind": kind, "host": host, "field_path": field_path, "url": url})
    return trailers, media


def _image_rows(state: _State) -> tuple[list[dict[str, object]], str]:
    database = (
        state.raw / PRIMARY_DOMAIN / "Library" / "Application Support" / "libCachedImageData.db"
    )
    try:
        database.lstat()
    except FileNotFoundError:
        return [], "not present"
    rows: list[dict[str, object]] = []
    try:
        with _sqlite_snapshot(state, database) as connection:
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
    except (sqlite3.Error, UnsupportedSchemaError, ValueError):
        return [], "unreadable"
    return rows, "ok"


def _data_parity(state: _State) -> None:
    escape_metadata = state.analysis_summary["csv_spreadsheet_escaped_cells"]
    if any(
        not isinstance(name, str)
        or name not in PRE_REPORT_CSV_NAMES
        or not isinstance(items, list)
        or not items
        for name, items in escape_metadata.items()
    ):
        _fail()
    for name, fields in CSV_FIELDS.items():
        escaped = escape_metadata.get(name)
        state.tables[name] = _read_csv_rows(
            state.analysis / name,
            fields,
            escaped_cells=escaped,
        )
    visual_row_names = (
        "series_library.csv",
        "watched_movies.csv",
        "movie_watchlist.csv",
        "favorite_shows.csv",
        "favorite_movies.csv",
        "episode_cache_unique.csv",
        "watch_events_named.csv",
    )
    if len(state.size_discrepancies) > MAXIMUM_REPORT_TABLE_ROWS or (
        len(state.size_discrepancies) + sum(len(state.tables[name]) for name in visual_row_names)
        > MAXIMUM_TOTAL_REPORT_TABLE_ROWS
    ):
        _fail()
    visual_byte_budget = _ReportByteBudget(maximum_total=MAXIMUM_REPORT_RENDER_INPUT_BYTES)
    try:
        for name in visual_row_names:
            visual_byte_budget.reserve_rows(
                "combined visual-report input byte size",
                state.tables[name],
            )
        visual_byte_budget.reserve_rows(
            "combined visual-report input byte size",
            state.size_discrepancies,
        )
    except UnsupportedSchemaError:
        _fail()

    raw_cache_index, payload_records = _raw_cache_index(state)
    if state.tables["cache_index.csv"] != raw_cache_index:
        _fail()
    expected_core_tables = _expected_core_tables(payload_records)
    if any(state.tables[name] != rows for name, rows in expected_core_tables.items()):
        _fail()
    payloads = [payload for _source_id, payload in payload_records]
    state.payloads = payloads
    recognized_payloads = sum(_is_supported_payload(payload) for payload in payloads)
    profile_payloads = sum(
        isinstance(data := _payload_data(payload), dict)
        and "objects" not in data
        and {"id", "created_at"} <= data.keys()
        for payload in payloads
    )
    cache_rows = state.tables["cache_index.csv"]
    if cache_rows and recognized_payloads == 0:
        _fail()
    unique_cache_payloads = len({row["sha256"] for row in cache_rows})
    parser_status = "empty" if not cache_rows else "recognized"
    if (
        state.analysis_summary["recognized_payloads"] != recognized_payloads
        or state.analysis_summary["profile_payloads_detected_not_exported"] != profile_payloads
        or state.analysis_summary["cache_rows"] != len(cache_rows)
        or state.analysis_summary["unique_cache_payloads"] != unique_cache_payloads
        or state.analysis_summary["parser_status"] != parser_status
        or any(row["exported_file"] for row in cache_rows)
    ):
        _fail()

    tables = state.tables
    watch_projection = [
        {field_name: row[field_name] for field_name in CSV_FIELDS["watch_events.csv"]}
        for row in tables["watch_events_named.csv"]
    ]
    if watch_projection != tables["watch_events.csv"]:
        _fail()
    combined_movies = _row_counter([*tables["watched_movies.csv"], *tables["movie_watchlist.csv"]])
    if combined_movies != _row_counter(tables["movie_library.csv"]):
        _fail()
    if not _row_counter(tables["episode_cache_unique.csv"]) <= _row_counter(
        tables["episode_cache.csv"]
    ):
        _fail()
    if len(_row_counter(tables["episode_cache_unique.csv"])) != len(
        tables["episode_cache_unique.csv"]
    ):
        _fail()
    sqlite_counts = dict(Counter(row["quick_check"] for row in tables["sqlite_integrity.csv"]))
    if state.analysis_summary["sqlite_integrity"] != sqlite_counts:
        _fail()

    named_watch_events = sum(
        has_display_text(row["movie_name"]) for row in tables["watch_events_named.csv"]
    )
    summary_counts = {
        "cache_rows": len(cache_rows),
        "watch_events": len(tables["watch_events.csv"]),
        "movie_library": len(tables["movie_library.csv"]),
        "watched_movies": len(tables["watched_movies.csv"]),
        "movie_watchlist": len(tables["movie_watchlist.csv"]),
        "watch_events_with_titles": named_watch_events,
        "series_library": len(tables["series_library.csv"]),
        "favorite_movies": len(tables["favorite_movies.csv"]),
        "favorite_shows": len(tables["favorite_shows.csv"]),
        "episode_cache_rows": len(tables["episode_cache.csv"]),
        "episode_cache_unique": len(tables["episode_cache_unique.csv"]),
        "sqlite_databases": len(tables["sqlite_integrity.csv"]),
        "plist_files": len(tables["plist_key_inventory.csv"]),
    }
    if any(state.analysis_summary.get(name) != value for name, value in summary_counts.items()):
        _fail()

    trailers, media = _media_rows(payloads)
    image_rows, image_status = _image_rows(state)
    if tables["trailer_references.csv"] != _serialized_rows(
        trailers, CSV_FIELDS["trailer_references.csv"]
    ):
        _fail()
    if tables["media_url_inventory.csv"] != _serialized_rows(
        media, CSV_FIELDS["media_url_inventory.csv"]
    ):
        _fail()
    if tables["image_cache_references.csv"] != _serialized_rows(
        image_rows, CSV_FIELDS["image_cache_references.csv"]
    ):
        _fail()
    state.image_cache_status = image_status

    extraction_aggregate = {
        "files_expected": len(state.inventory),
        "files_extracted": len(state.inventory),
        "bytes_extracted": sum(_canonical_decimal(row["actual_size"]) for row in state.inventory),
        "selected_declared_bytes": sum(
            _canonical_decimal(row["declared_size"]) for row in state.inventory
        ),
        "size_discrepancy_count": len(state.size_discrepancies),
    }
    analysis_aggregate: dict[str, int | str] = {
        name: summary_counts[name]
        for name in (
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
    analysis_aggregate["parser_status"] = parser_status
    report_aggregate: dict[str, object] = {
        "image_cache_references": len(image_rows),
        "trailer_references": len(trailers),
        "media_urls": len(media),
        "pdf_status": state.recovery_state["pdf"]["status"],
    }
    if state.recovery_state["pdf"]["status"] == "omitted":
        report_aggregate["pdf_omission_reason"] = PDF_FIDELITY_WARNING
    aggregates = state.recovery_state["aggregates"]
    if (
        aggregates["extraction"] != extraction_aggregate
        or aggregates["analysis"] != analysis_aggregate
        or aggregates["report"] != report_aggregate
    ):
        _fail()

    media_counts = Counter(row["kind"] for row in media)
    image_counts = Counter(str(row["category"]) for row in image_rows)
    state.model = build_visual_report_model(
        series=tables["series_library.csv"],
        watched_movies=tables["watched_movies.csv"],
        movie_watchlist=tables["movie_watchlist.csv"],
        favorite_shows=tables["favorite_shows.csv"],
        favorite_movies=tables["favorite_movies.csv"],
        episodes=tables["episode_cache_unique.csv"],
        watch_events=tables["watch_events_named.csv"],
        extracted_file_count=len(state.inventory),
        image_cache_status=image_status,
        trailer_count=len(trailers),
        media_url_counts=media_counts,
        image_category_counts=image_counts,
        size_discrepancies=state.size_discrepancies,
    )
    state.counts = {
        "extracted_files": len(state.inventory),
        "size_discrepancies": len(state.size_discrepancies),
        "series_library": summary_counts["series_library"],
        "watched_movies": summary_counts["watched_movies"],
        "saved_movies": summary_counts["movie_watchlist"],
        "favorite_shows": summary_counts["favorite_shows"],
        "favorite_movies": summary_counts["favorite_movies"],
        "watch_events": summary_counts["watch_events"],
        "named_watch_events": named_watch_events,
        "cached_episodes": summary_counts["episode_cache_unique"],
        "image_references": len(image_rows),
        "trailer_references": len(trailers),
        "media_urls": len(media),
    }


class _HTMLSafetyParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.html_language = ""
        self.h1_count = 0
        self.h2_count = 0
        self.table_count = 0
        self.caption_count = 0
        self.csp = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag in {"script", "iframe", "object", "embed", "form", "base", "link"}:
            _fail()
        for name, value in attrs:
            lowered_name = name.casefold()
            lowered_value = str(value or "").strip().casefold()
            if lowered_name.startswith("on") or lowered_name in {"srcdoc", "action", "formaction"}:
                _fail()
            if lowered_name in {"href", "src", "xlink:href"} and not lowered_value.startswith("#"):
                _fail()
        if tag == "html":
            self.html_language = str(attributes.get("lang") or "")
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "h2":
            self.h2_count += 1
        elif tag == "table":
            self.table_count += 1
            if not attributes.get("aria-describedby"):
                _fail()
        elif tag == "caption":
            self.caption_count += 1
        elif (
            tag == "meta"
            and str(attributes.get("http-equiv") or "").casefold() == "content-security-policy"
        ):
            self.csp = str(attributes.get("content") or "")


def _visual_reports(state: _State) -> None:
    if state.model is None:
        _fail()
    markdown = _read_bytes(
        state.analysis / "TVTime-Recovered-Data.md",
        maximum_bytes=MAXIMUM_REPORT_BYTES,
    )
    html = _read_bytes(
        state.analysis / HTML_REPORT_FILENAME,
        maximum_bytes=MAXIMUM_REPORT_BYTES,
    )
    expected_markdown = render_markdown_report(state.model).encode("utf-8")
    expected_html = render_html_report(state.model).encode("utf-8")
    if markdown != expected_markdown or html != expected_html:
        _fail()
    try:
        html_text = html.decode("utf-8")
    except UnicodeDecodeError:
        _fail()
    parser = _HTMLSafetyParser()
    parser.feed(html_text)
    parser.close()
    required_csp = (
        "default-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "script-src 'none'",
        "connect-src 'none'",
        "object-src 'none'",
    )
    if (
        parser.html_language != "en"
        or parser.h1_count != 1
        or parser.h2_count < 2
        or parser.table_count != len(state.model.sections)
        or parser.caption_count != parser.table_count
        or any(item not in parser.csp for item in required_csp)
    ):
        _fail()


def _pdf_reader(payload: bytes) -> Any:
    try:
        from pypdf import PdfReader
    except ImportError:
        return None
    return PdfReader(io.BytesIO(payload), strict=True)


@contextmanager
def _bounded_pdf_decoders() -> Iterator[None]:
    try:
        from pypdf import filters
    except ImportError:
        yield
        return
    names = (
        "FLATE_MAX_BUFFER_SIZE",
        "JBIG2_MAX_OUTPUT_LENGTH",
        "LZW_MAX_OUTPUT_LENGTH",
        "MAX_ARRAY_BASED_STREAM_OUTPUT_LENGTH",
        "MAX_DECLARED_STREAM_LENGTH",
        "RUN_LENGTH_MAX_OUTPUT_LENGTH",
        "ZLIB_MAX_OUTPUT_LENGTH",
    )
    original = {name: getattr(filters, name) for name in names if hasattr(filters, name)}
    try:
        for name, value in original.items():
            if value <= 0 or value > MAXIMUM_PDF_DECOMPRESSED_BYTES:
                setattr(filters, name, MAXIMUM_PDF_DECOMPRESSED_BYTES)
        yield
    finally:
        for name, value in original.items():
            setattr(filters, name, value)


def _semantic_pdf_text(value: str) -> str:
    """Normalize layout whitespace while retaining every token boundary."""

    return " ".join(value.split())


def _pdf_page_texts(reader: Any) -> list[str]:
    pages = reader.pages
    page_count = len(pages)
    if page_count <= 0 or page_count > MAXIMUM_PDF_PAGES:
        _fail()
    result: list[str] = []
    total_bytes = 0
    for page in pages:
        if "/Annots" in page:
            _fail()
        text = page.extract_text() or ""
        text_bytes = len(text.encode("utf-8", errors="surrogatepass"))
        if text_bytes > MAXIMUM_PDF_PAGE_TEXT_BYTES:
            _fail()
        total_bytes += text_bytes
        if total_bytes > MAXIMUM_PDF_TOTAL_TEXT_BYTES:
            _fail()
        result.append(_semantic_pdf_text(text))
    return result


def _validate_pdf_structure_bounds(reader: Any) -> None:
    trailer_size = reader.trailer.get("/Size")
    if (
        not isinstance(trailer_size, int)
        or isinstance(trailer_size, bool)
        or trailer_size <= 0
        or trailer_size > MAXIMUM_PDF_OBJECTS
    ):
        _fail()
    xref_objects = sum(
        len(entries) for entries in reader.xref.values() if isinstance(entries, Mapping)
    )
    object_streams = len(getattr(reader, "xref_objStm", {}))
    if xref_objects + object_streams <= 0 or xref_objects + object_streams > MAXIMUM_PDF_OBJECTS:
        _fail()


def _outline_titles(value: object) -> list[str]:
    titles: list[str] = []
    pending: list[tuple[object, int]] = [(value, 0)]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > MAXIMUM_PDF_OBJECTS or depth > MAXIMUM_PDF_OBJECT_DEPTH:
            _fail()
        if isinstance(item, list):
            if len(pending) + len(item) > MAXIMUM_PDF_OBJECTS:
                _fail()
            pending.extend((child, depth + 1) for child in reversed(item))
            continue
        title = getattr(item, "title", None)
        if isinstance(title, str):
            titles.append(title)
    return titles


def _validate_pdf_actions(reader: Any) -> None:
    forbidden_keys = {
        "/A",
        "/AA",
        "/AcroForm",
        "/AF",
        "/Annots",
        "/Collection",
        "/EF",
        "/EmbeddedFiles",
        "/JavaScript",
        "/JS",
        "/Launch",
        "/Names",
        "/OpenAction",
        "/Perms",
        "/RichMediaContent",
        "/RichMediaSettings",
        "/URI",
        "/XFA",
    }
    forbidden_actions = {
        "/GoTo",
        "/GoTo3DView",
        "/GoToE",
        "/GoToR",
        "/Hide",
        "/ImportData",
        "/JavaScript",
        "/Launch",
        "/Movie",
        "/Named",
        "/ResetForm",
        "/Rendition",
        "/SetOCGState",
        "/Sound",
        "/SubmitForm",
        "/Thread",
        "/Trans",
        "/URI",
    }
    forbidden_types = {"/Action", "/Annot", "/EmbeddedFile", "/Filespec"}
    forbidden_annotations = {
        "/3D",
        "/Caret",
        "/Circle",
        "/FileAttachment",
        "/FreeText",
        "/Highlight",
        "/Ink",
        "/Line",
        "/Link",
        "/Movie",
        "/Polygon",
        "/PolyLine",
        "/Popup",
        "/PrinterMark",
        "/Redact",
        "/RichMedia",
        "/Screen",
        "/Sound",
        "/Square",
        "/Squiggly",
        "/Stamp",
        "/StrikeOut",
        "/Text",
        "/TrapNet",
        "/Underline",
        "/Watermark",
        "/Widget",
    }
    seen_indirect: set[tuple[int, int]] = set()
    seen_direct: set[int] = set()
    visited = 0

    def visit(value: object, depth: int = 0) -> None:
        nonlocal visited
        if depth > MAXIMUM_PDF_OBJECT_DEPTH or visited > MAXIMUM_PDF_OBJECTS:
            _fail()
        if (
            hasattr(value, "idnum")
            and hasattr(value, "generation")
            and hasattr(value, "get_object")
        ):
            identity = (int(value.idnum), int(value.generation))
            if identity in seen_indirect:
                return
            seen_indirect.add(identity)
            visited += 1
            if visited > MAXIMUM_PDF_OBJECTS:
                _fail()
            visit(value.get_object(), depth + 1)
            return
        if isinstance(value, Mapping):
            identity = id(value)
            if identity in seen_direct:
                return
            seen_direct.add(identity)
            visited += 1
            keys = {str(key) for key in value}
            if keys & forbidden_keys:
                _fail()
            if str(value.get("/S") or "") in forbidden_actions:
                _fail()
            if str(value.get("/Type") or "") in forbidden_types:
                _fail()
            if str(value.get("/Subtype") or "") in forbidden_annotations:
                _fail()
            for child in value.values():
                visit(child, depth + 1)
            return
        if isinstance(value, (list, tuple)):
            identity = id(value)
            if identity in seen_direct:
                return
            seen_direct.add(identity)
            visited += 1
            for child in value:
                visit(child, depth + 1)

    visit(reader.trailer["/Root"])


def _rerender_pdf(state: _State) -> bytes:
    if state.model is None:
        _fail()
    with _private_staging_directory(state) as staging:
        path = staging / PDF_REPORT_FILENAME
        write_pdf_report(state.model, output_path=path)
        return _read_bytes(path, maximum_bytes=MAXIMUM_PDF_BYTES)


def _pdf_report(state: _State) -> None:
    if state.model is None:
        _fail()
    status = state.recovery_state["pdf"]["status"]
    path = state.analysis / PDF_REPORT_FILENAME
    if status == "omitted":
        if path.exists() or path.is_symlink():
            _fail()
        try:
            _rerender_pdf(state)
        except PDFCapabilityError as error:
            if str(error) != PDF_FIDELITY_WARNING:
                _fail()
        else:
            _fail()
        return

    payload = _read_bytes(path, maximum_bytes=MAXIMUM_PDF_BYTES)
    if not payload.startswith(b"%PDF-") or not payload.rstrip().endswith(b"%%EOF"):
        _fail()
    rerendered = _rerender_pdf(state)
    # The generator uses ReportLab's invariant mode, so any byte difference is
    # noncanonical. This catches visual-only mutations before pypdf parses them.
    if not hmac.compare_digest(payload, rerendered):
        _fail()
    with _bounded_pdf_decoders():
        reader = _pdf_reader(payload)
        rerendered_reader = _pdf_reader(rerendered)
        if reader is None or rerendered_reader is None:
            _fail()
        _validate_pdf_structure_bounds(reader)
        _validate_pdf_structure_bounds(rerendered_reader)
        if reader.is_encrypted or rerendered_reader.is_encrypted:
            _fail()
        root = reader.trailer["/Root"]
        rerendered_root = rerendered_reader.trailer["/Root"]
        if (
            root.get("/Lang") != "en-AU"
            or rerendered_root.get("/Lang") != "en-AU"
            or "/Outlines" not in root
            or "/Outlines" not in rerendered_root
        ):
            _fail()
        _validate_pdf_actions(reader)
        _validate_pdf_actions(rerendered_reader)
        metadata = reader.metadata
        if (
            metadata is None
            or metadata.title != "TV Time recovered-data report"
            or metadata.author != "TV Time Backup Extractor"
            or metadata.subject != "Private recovered TV Time data"
        ):
            _fail()
        expected_titles = [
            "Recovery summary",
            *(section.title for section in state.model.sections),
            "Aggregate media statistics",
        ]
        if (
            _outline_titles(reader.outline) != expected_titles
            or _outline_titles(rerendered_reader.outline) != expected_titles
        ):
            _fail()
        actual_pages = _pdf_page_texts(reader)
        rerendered_pages = _pdf_page_texts(rerendered_reader)
        accessibility_notice = _semantic_pdf_text(
            "For accessible headings, navigation, and table structure, use the complete offline "
            "HTML report."
        )
        if (
            len(actual_pages) != len(rerendered_pages)
            or actual_pages != rerendered_pages
            or accessibility_notice not in " ".join(actual_pages)
        ):
            _fail()


def _final_immutability(state: _State) -> None:
    if state.source_snapshot is None:
        _fail()
    if (
        reconcile_raw_tree(state.extraction, expected=state.source_snapshot)
        != state.source_snapshot
    ):
        _fail()
    if (
        not state.domains_bytes
        or _read_bytes(
            state.metadata / "domains.txt",
            maximum_bytes=MAXIMUM_INPUT_BYTES,
        )
        != state.domains_bytes
    ):
        _fail()
    _root_layout(state)
    pdf_status = state.recovery_state["pdf"]["status"]
    _exact_directory(
        state.analysis,
        {name: stat.S_IFREG for name in _sealed_analysis_filenames(pdf_status)},
    )
    if (
        _read_bytes(
            state.analysis / "recovery_state.json",
            maximum_bytes=MAXIMUM_COMPLETION_MARKER_BYTES,
        )
        != state.recovery_state_bytes
    ):
        _fail()
    for expected in state.artifact_bindings:
        observed = _private_artifact_binding(
            state.extraction / Path(expected["relative_path"]),
            artifact_id=expected["id"],
            relative_path=expected["relative_path"],
        )
        if observed != expected:
            _fail()


def _run_gate(state: _State, name: str, operation: Callable[[_State], None]) -> None:
    try:
        operation(state)
    except Exception as error:
        raise ValidationFailure(name, state.passed_gates) from error
    state.passed_gates.append(name)


def validate_recovery_output(output_root: Path) -> ValidationResult:
    try:
        root = no_link_absolute_path(output_root.expanduser())
    except Exception as error:
        raise ValidationFailure("input") from error
    state = _State(output_root=root)
    for name, operation in (
        ("root_layout", _root_layout),
        ("completion_contracts", _completion_contracts),
        ("source_integrity", _source_integrity),
        ("artifact_bindings", _artifact_bindings),
        ("data_parity", _data_parity),
        ("visual_reports", _visual_reports),
        ("pdf_report", _pdf_report),
        ("final_immutability", _final_immutability),
    ):
        _run_gate(state, name, operation)
    return ValidationResult(
        gates=tuple(state.passed_gates),
        counts=tuple(state.counts.items()),
    )


def _stdin_path() -> Path:
    payload = sys.stdin.buffer.read(MAXIMUM_INPUT_BYTES + 1)
    if not payload or len(payload) > MAXIMUM_INPUT_BYTES:
        raise ValidationFailure("input")
    try:
        value = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationFailure("input") from error
    lines = value.splitlines()
    if len(lines) != 1 or not lines[0].strip() or "\x00" in lines[0]:
        raise ValidationFailure("input")
    return Path(lines[0])


def main() -> int:
    if len(sys.argv) != 1:
        print("GATE input FAIL")
        print("RESULT FAIL")
        return 2
    try:
        output_root = _stdin_path()
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        with redirect_stdout(captured_stdout), redirect_stderr(captured_stderr):
            result = validate_recovery_output(output_root)
    except ValidationFailure as error:
        for gate in error.passed_gates:
            print(f"GATE {gate} PASS")
        print(f"GATE {error.gate} FAIL")
        print("RESULT FAIL")
        return 1
    except Exception:
        print("GATE input FAIL")
        print("RESULT FAIL")
        return 1
    for gate in result.gates:
        print(f"GATE {gate} PASS")
    for name, value in result.counts:
        print(f"COUNT {name} {value}")
    print("RESULT PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
