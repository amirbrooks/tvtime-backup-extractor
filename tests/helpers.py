from __future__ import annotations

import csv
import json
import plistlib
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from tvtime_extractor.extract import PRIMARY_DOMAIN

PROFILE_SENTINEL = "SYNTHETIC_PROFILE_SENTINEL"
MOVIE_UUID = "11111111-1111-4111-8111-111111111111"
SAVED_MOVIE_UUID = "22222222-2222-4222-8222-222222222222"
SERIES_UUID = "33333333-3333-4333-8333-333333333333"


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
    documents.mkdir(parents=True)
    support.mkdir(parents=True)
    metadata.mkdir(parents=True)

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

    with (metadata / "inventory.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "file_id",
                "domain",
                "relative_path",
                "declared_size",
                "actual_size",
                "size_match",
                "mtime",
                "sha256",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "file_id": "a" * 40,
                "domain": PRIMARY_DOMAIN,
                "relative_path": "Documents/DioCache.db",
                "declared_size": cache_db.stat().st_size,
                "actual_size": cache_db.stat().st_size,
                "size_match": True,
                "mtime": "2025-01-01T00:00:00Z",
                "sha256": "0" * 64,
            }
        )
    return extraction


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
