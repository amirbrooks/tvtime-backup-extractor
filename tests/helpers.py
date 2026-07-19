from __future__ import annotations

import csv
import hashlib
import json
import plistlib
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from tvtime_extractor.extract import (
    EXTRACTION_RUN_STATE_CONTRACT,
    EXTRACTION_RUN_STATE_SCHEMA_VERSION,
    PRIMARY_DOMAIN,
)
from tvtime_extractor.integrity import reconcile_raw_tree
from tvtime_extractor.safety import (
    secure_directory,
    secure_file,
    write_csv_private,
    write_json_private_atomic,
    write_text_private,
)

PROFILE_SENTINEL = "SYNTHETIC_PROFILE_SENTINEL"
MOVIE_UUID = "11111111-1111-4111-8111-111111111111"
SAVED_MOVIE_UUID = "22222222-2222-4222-8222-222222222222"
SERIES_UUID = "33333333-3333-4333-8333-333333333333"


def write_finished_status(backup: Path) -> None:
    with (backup / "Status.plist").open("wb") as handle:
        plistlib.dump({"SnapshotState": "finished"}, handle)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def synthetic_payloads() -> list[tuple[str, str, bytes, int]]:
    library = {
        "data": {
            "id": "library",
            "type": "list",
            "objects": [
                {
                    "uuid": MOVIE_UUID,
                    "entity_type": "movie",
                    "filter": ["watched"],
                    "watched_at": "2025-01-02T03:04:05Z",
                    "created_at": "2025-01-01T00:00:00Z",
                    "updated_at": "2025-01-03T00:00:00Z",
                    "sorting": [
                        {"id": "follow_date", "value": "2025-01-01T00:00:00Z"},
                        {"id": "watched_date", "value": "2025-01-02T03:04:05Z"},
                    ],
                    "extended": {"is_watched": True},
                    "meta": {
                        "name": "Example Movie",
                        "imdb_id": "tt0000001",
                        "first_release_date": "2024-06-01",
                        "runtime": 7200,
                        "genres": ["Drama", "Mystery"],
                        "poster_url": (
                            "https://cdn.example.invalid/posters/example.jpg"
                            "?token=SYNTHETIC_TOKEN#private"
                        ),
                        "private_url": "https://demo:secret@example.invalid/account",
                        "trailers": [
                            {
                                "name": "Example trailer",
                                "runtime": 90,
                                "url": (
                                    "https://www.youtube.com/watch?v=demo-video"
                                    "&token=SYNTHETIC_TOKEN#private"
                                ),
                                "thumb_url": (
                                    "https://img.example.invalid/thumb.jpg"
                                    "?signature=SYNTHETIC_SIGNATURE"
                                ),
                            }
                        ],
                    },
                },
                {
                    "uuid": SAVED_MOVIE_UUID,
                    "entity_type": "movie",
                    "filter": "watch_later",
                    "created_at": "2025-02-01T00:00:00Z",
                    "updated_at": "2025-02-02T00:00:00Z",
                    "sorting": [{"id": "follow_date", "value": "2025-02-01T00:00:00Z"}],
                    "meta": {
                        "name": "Example Saved Movie",
                        "imdb_id": "tt0000002",
                        "first_release_date": "2026-01-01",
                        "runtime": 6000,
                        "genres": ["Comedy"],
                    },
                },
                {
                    "uuid": SERIES_UUID,
                    "entity_type": "series",
                    "filter": ["up_to_date"],
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2025-03-04T00:00:00Z",
                    "sorting": [
                        {"id": "follow_date", "value": "2024-01-01T00:00:00Z"},
                        {"id": "watch_date", "value": "2025-03-04T05:06:07Z"},
                    ],
                    "meta": {
                        "id": "series-example-1",
                        "name": "Example Series",
                        "country": "AU",
                        "is_ended": False,
                    },
                },
            ],
        }
    }
    favorite_movies = {
        "data": {
            "id": "favorite-movies",
            "type": "list",
            "objects": [
                {
                    "uuid": "44444444-4444-4444-8444-444444444444",
                    "id": "favorite-movie-example",
                    "name": "Favorite Example Movie",
                    "type": "movie",
                    "created_at": "2025-01-10T00:00:00Z",
                }
            ],
        }
    }
    favorite_series = {
        "data": {
            "id": "favorite-series",
            "type": "list",
            "objects": [
                {
                    "uuid": "55555555-5555-4555-8555-555555555555",
                    "id": "favorite-series-example",
                    "name": "Favorite Example Series",
                    "type": "series",
                    "created_at": "2025-01-11T00:00:00Z",
                    "watch_status": {
                        "watched_episode_count": 4,
                        "aired_episode_count": 5,
                        "is_followed": True,
                        "is_up_to_date": False,
                    },
                }
            ],
        }
    }
    watches = {
        "data": {
            "type": "watch",
            "objects": [
                {
                    "uuid": MOVIE_UUID,
                    "entity_type": "movie",
                    "type": "watch",
                    "watched_at": "2025-01-02T03:04:05Z",
                    "runtime": 7200,
                    "created_at": "2025-01-02T03:04:05Z",
                    "updated_at": "2025-01-02T03:04:05Z",
                }
            ],
        }
    }
    episodes = {
        "data": [
            {
                "id": "episode-example-1",
                "show": {"id": "series-example-1", "name": "Example Series"},
                "season_number": 1,
                "number": 2,
                "name": "The Synthetic Episode",
                "air_date": "2025-03-01T00:00:00Z",
                "seen": True,
                "seen_date": "2025-03-04T05:06:07Z",
                "is_watched": True,
                "runtime": 2700,
            }
        ]
    }
    profile = {
        "data": {
            "id": "synthetic-profile",
            "created_at": "2020-01-01T00:00:00Z",
            "display_name": PROFILE_SENTINEL,
            "analytics_installation_id": "synthetic-installation-id",
        }
    }
    library_bytes = _json_bytes(library)
    return [
        ("https://api.example.invalid/library?account=synthetic", "library", library_bytes, 200),
        ("https://api.example.invalid/favorites", "movies", _json_bytes(favorite_movies), 200),
        ("https://api.example.invalid/favorites", "series", _json_bytes(favorite_series), 200),
        ("https://api.example.invalid/watches", "movie", _json_bytes(watches), 200),
        ("https://api.example.invalid/episodes", "series", _json_bytes(episodes), 200),
        ("https://api.example.invalid/profile", "settings", _json_bytes(profile), 200),
        ("duplicate-private-cache-key", "duplicate-private-subkey", library_bytes, 200),
        ("binary-private-cache-key", "binary-private-subkey", b"\xffnot-json", 500),
    ]


def create_synthetic_extraction(base: Path) -> Path:
    extraction = base / "TVTime-Extraction"
    app_root = extraction / "raw" / PRIMARY_DOMAIN
    documents = app_root / "Documents"
    support = app_root / "Library" / "Application Support"
    metadata = extraction / "metadata"
    manifest = extraction / "manifest"
    documents.mkdir(parents=True)
    support.mkdir(parents=True)
    metadata.mkdir(parents=True)
    manifest.mkdir(parents=True)

    cache_db = documents / "DioCache.db"
    with closing(sqlite3.connect(cache_db)) as connection:
        connection.execute(
            "CREATE TABLE cache_dio "
            "(key TEXT NOT NULL, subKey TEXT NOT NULL, content BLOB, statusCode INTEGER)"
        )
        connection.executemany(
            "INSERT INTO cache_dio (key, subKey, content, statusCode) VALUES (?, ?, ?, ?)",
            synthetic_payloads(),
        )
        connection.commit()

    image_db = support / "libCachedImageData.db"
    with closing(sqlite3.connect(image_db)) as connection:
        connection.execute(
            "CREATE TABLE cacheObject "
            "(_id INTEGER, url TEXT, key TEXT, relativePath TEXT, eTag TEXT, "
            "validTill INTEGER, touched INTEGER, length INTEGER)"
        )
        connection.execute(
            "INSERT INTO cacheObject VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                "https://cdn.example.invalid/posters/cache.jpg?token=SYNTHETIC_TOKEN#private",
                "synthetic-image-key",
                "posters/cache.jpg",
                "synthetic-etag",
                2_000_000_000,
                1_900_000_000,
                1234,
            ),
        )
        connection.commit()

    with (app_root / "Library" / "Preferences.plist").open("wb") as handle:
        plistlib.dump({"SyntheticFeatureEnabled": True}, handle)

    for directory in [extraction, *(path for path in extraction.rglob("*") if path.is_dir())]:
        secure_directory(directory)
    for path in (path for path in extraction.rglob("*") if path.is_file()):
        secure_file(path)

    inventory_rows = _synthetic_inventory_rows(extraction)
    write_csv_private(
        metadata / "inventory.csv",
        inventory_rows,
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
    source_snapshot = reconcile_raw_tree(extraction)
    extracted_bytes = source_snapshot.raw_tree_bytes
    extracted_files = source_snapshot.raw_tree_files
    write_json_private_atomic(
        metadata / "summary.json",
        {
            "bundle_id": "com.tozelabs.tvshowtime",
            "domains": [PRIMARY_DOMAIN],
            "files_expected": extracted_files,
            "files_extracted": extracted_files,
            "failures": [],
            "bytes_extracted": extracted_bytes,
            "selected_declared_bytes": extracted_bytes,
            "size_discrepancies": [],
            "decrypted_manifest_included": False,
            "completed_utc": "2026-07-18T10:00:00+00:00",
        },
    )
    write_json_private_atomic(
        metadata / "run_state.json",
        {
            "schema_version": EXTRACTION_RUN_STATE_SCHEMA_VERSION,
            "contract": EXTRACTION_RUN_STATE_CONTRACT,
            "status": "complete",
            "completed_utc": "2026-07-18T10:00:00+00:00",
            "files_expected": extracted_files,
            "files_extracted": extracted_files,
            "bytes_extracted": extracted_bytes,
            "selected_declared_bytes": extracted_bytes,
            "size_discrepancy_count": 0,
            "source_snapshot": source_snapshot.as_dict(),
        },
    )
    write_text_private(metadata / "domains.txt", f"{PRIMARY_DOMAIN}\n")
    return extraction


def _synthetic_inventory_rows(extraction: Path) -> list[dict[str, object]]:
    raw = extraction / "raw"
    rows: list[dict[str, object]] = []
    for index, path in enumerate(
        sorted(
            (path for path in raw.rglob("*") if path.is_file()),
            key=lambda item: item.as_posix(),
        ),
        1,
    ):
        relative = path.relative_to(raw)
        domain, *relative_parts = relative.parts
        size = path.stat().st_size
        rows.append(
            {
                "file_id": f"{index:040x}",
                "domain": domain,
                "relative_path": Path(*relative_parts).as_posix(),
                "declared_size": size,
                "actual_size": size,
                "size_match": True,
                "mtime": "2025-01-01T00:00:00Z",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return rows


def refresh_synthetic_source_snapshot(extraction: Path) -> None:
    """Reseal a fixture after an intentional semantic raw-data mutation."""

    inventory_path = extraction / "metadata" / "inventory.csv"
    write_csv_private(
        inventory_path,
        _synthetic_inventory_rows(extraction),
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
    source_snapshot = reconcile_raw_tree(extraction)
    summary_path = extraction / "metadata" / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary.update(
        {
            "files_expected": source_snapshot.raw_tree_files,
            "files_extracted": source_snapshot.raw_tree_files,
            "bytes_extracted": source_snapshot.raw_tree_bytes,
            "selected_declared_bytes": source_snapshot.raw_tree_bytes,
        }
    )
    write_json_private_atomic(summary_path, summary)
    run_state_path = extraction / "metadata" / "run_state.json"
    run_state = json.loads(run_state_path.read_text(encoding="utf-8"))
    run_state.update(
        {
            "files_expected": source_snapshot.raw_tree_files,
            "files_extracted": source_snapshot.raw_tree_files,
            "bytes_extracted": source_snapshot.raw_tree_bytes,
            "selected_declared_bytes": source_snapshot.raw_tree_bytes,
            "source_snapshot": source_snapshot.as_dict(),
        }
    )
    write_json_private_atomic(run_state_path, run_state)


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
