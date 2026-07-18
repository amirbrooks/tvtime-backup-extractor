from __future__ import annotations

import hashlib
import json
import plistlib
import shutil
import sqlite3
import tempfile
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .errors import TVTimeError
from .extract import PRIMARY_DOMAIN
from .safety import (
    prepare_new_analysis_directory,
    private_source_id,
    safe_join,
    secure_directory,
    secure_file,
    validate_extraction_directory,
    write_bytes_private,
    write_csv_private,
    write_json_private,
)


@contextmanager
def readonly_sqlite(path: Path) -> Iterator[sqlite3.Connection]:
    if not path.is_file() or path.is_symlink():
        raise TVTimeError(f"Required SQLite database was not found: {path}")
    with tempfile.TemporaryDirectory(prefix=".tvtime-sqlite-", dir=path.parent) as temporary:
        snapshot_directory = secure_directory(Path(temporary))
        snapshot = snapshot_directory / path.name
        for suffix in ("", "-wal", "-shm", "-journal"):
            source = path.with_name(path.name + suffix)
            if not source.exists():
                continue
            if not source.is_file() or source.is_symlink():
                raise TVTimeError(f"Refusing unsafe SQLite file or sidecar: {source}")
            destination = snapshot_directory / source.name
            shutil.copyfile(source, destination)
            secure_file(destination)

        connection = sqlite3.connect(snapshot)
        try:
            connection.execute("PRAGMA query_only = ON")
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
    selected: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        identity = (
            str(item.get("type") or ""),
            str(item.get("id") or item.get("uuid") or ""),
            str(item.get("name") or ""),
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


def analyze_extraction(
    *,
    extraction_directory: Path,
    include_raw_cache: bool = False,
) -> dict[str, Any]:
    """Create normalized private tables from an extracted TV Time container."""

    extraction = validate_extraction_directory(extraction_directory)
    raw = safe_join(extraction, "raw")
    app_root = safe_join(raw, PRIMARY_DOMAIN)
    cache_db = safe_join(app_root, "Documents", "DioCache.db")
    if not cache_db.is_file():
        raise TVTimeError(f"TV Time cache database was not found: {cache_db}")

    cache_index: list[dict[str, Any]] = []
    unique_hashes: dict[str, str] = {}
    payload_records: list[tuple[str, object]] = []
    cache_exports: list[tuple[str, object, bool]] = []
    with readonly_sqlite(cache_db) as connection:
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
                raise TVTimeError(
                    "DioCache.db uses an unsupported cache_dio schema; missing required columns: "
                    + ", ".join(missing_columns)
                )
            cache_rows = connection.execute(
                "SELECT key, subKey, content, statusCode FROM cache_dio ORDER BY key, subKey"
            )
            for key, subkey, content, status_code in cache_rows:
                if content is None:
                    raw_content = b""
                elif isinstance(content, bytes):
                    raw_content = content
                else:
                    raw_content = bytes(content)
                source_id = private_source_id(key, subkey)
                digest = sha256_bytes(raw_content)
                duplicate_of = unique_hashes.get(digest, "")
                unique_hashes.setdefault(digest, source_id)
                exported_file = ""
                try:
                    payload = json.loads(raw_content)
                    json_valid = True
                    payload_records.append((source_id, payload))
                    if include_raw_cache:
                        exported_file = f"{source_id}.json"
                        cache_exports.append((exported_file, payload, True))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    json_valid = False
                    payload = None
                    if include_raw_cache:
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
            raise TVTimeError(f"Could not read DioCache.db: {exc}") from exc

    recognized_payloads = sum(_is_supported_payload(payload) for _, payload in payload_records)
    if cache_index and not recognized_payloads:
        raise TVTimeError(
            "The cache contains data, but no supported TV Time payloads were recognized. "
            "Keep the extraction and check for an app-schema update."
        )
    parser_status = "empty" if not cache_index else "recognized"

    analysis = prepare_new_analysis_directory(extraction)
    responses = safe_join(analysis, "cache_responses")
    if include_raw_cache:
        secure_directory(responses)
        for filename, value, is_json in cache_exports:
            response_path = safe_join(responses, filename)
            if is_json:
                write_json_private(response_path, value)
            else:
                write_bytes_private(response_path, value)

    write_csv_private(
        analysis / "cache_index.csv",
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
        if isinstance(data, dict) and "objects" not in data and {"id", "created_at"} <= data.keys():
            profile_payloads_detected += 1
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

    unique_episode_rows: dict[tuple[str, str], dict[str, Any]] = {}
    for row in episode_rows:
        identity = (str(row["show_id"]), str(row["episode_id"]))
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
    write_csv_private(analysis / "watch_events.csv", watch_events, watch_fields)
    write_csv_private(
        analysis / "watch_events_named.csv",
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
    write_csv_private(
        analysis / "movie_library.csv",
        sorted(movie_library, key=lambda row: str(row["name"]).casefold()),
        movie_fields,
    )
    write_csv_private(
        analysis / "watched_movies.csv",
        sorted(watched_movies, key=lambda row: str(row["watched_at"])),
        movie_fields,
    )
    write_csv_private(
        analysis / "movie_watchlist.csv",
        sorted(movie_watchlist, key=lambda row: str(row["name"]).casefold()),
        movie_fields,
    )
    write_csv_private(
        analysis / "series_library.csv",
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
    write_csv_private(
        analysis / "favorite_movies.csv", _favorite_rows(favorite_movies), favorite_fields
    )
    write_csv_private(
        analysis / "favorite_shows.csv", _favorite_rows(favorite_shows), favorite_fields
    )
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
    write_csv_private(analysis / "episode_cache.csv", episode_rows, episode_fields)
    write_csv_private(
        analysis / "episode_cache_unique.csv",
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
    for path in sorted(raw.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open("rb") as handle:
                if handle.read(16) != b"SQLite format 3\x00":
                    continue
            with readonly_sqlite(path) as connection:
                integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
                objects = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type IN ('table','view') ORDER BY name"
                    )
                ]
        except (sqlite3.Error, TVTimeError) as exc:
            message = str(exc)
            integrity = (
                "not_checked_custom_IDBKEY"
                if "no such collation sequence: IDBKEY" in message
                else f"ERROR: {message}"
            )
            objects = []
        sqlite_rows.append(
            {
                "relative_path": str(path.relative_to(raw)),
                "bytes": path.stat().st_size,
                "quick_check": integrity,
                "schema_objects": " | ".join(objects),
            }
        )
    write_csv_private(
        analysis / "sqlite_integrity.csv",
        sqlite_rows,
        ["relative_path", "bytes", "quick_check", "schema_objects"],
    )

    plist_rows: list[dict[str, Any]] = []
    for path in sorted(raw.rglob("*.plist")):
        try:
            value = plistlib.loads(path.read_bytes())
            keys = sorted(map(str, value.keys())) if isinstance(value, dict) else []
            plist_rows.append(
                {
                    "relative_path": str(path.relative_to(raw)),
                    "format": type(value).__name__,
                    "top_level_keys": " | ".join(keys),
                }
            )
        except Exception as exc:
            plist_rows.append(
                {
                    "relative_path": str(path.relative_to(raw)),
                    "format": f"ERROR: {type(exc).__name__}",
                    "top_level_keys": "",
                }
            )
    write_csv_private(
        analysis / "plist_key_inventory.csv",
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
        "watch_events_with_titles": sum(bool(row["movie_name"]) for row in named_watch_events),
        "series_library": len(series_library),
        "favorite_movies": len(favorite_movies),
        "favorite_shows": len(favorite_shows),
        "episode_cache_rows": len(episode_rows),
        "episode_cache_unique": len(episodes_unique),
        "sqlite_databases": len(sqlite_rows),
        "sqlite_integrity": dict(Counter(row["quick_check"] for row in sqlite_rows)),
        "plist_files": len(plist_rows),
    }
    write_json_private(analysis / "analysis_summary.json", summary)
    return summary
