from __future__ import annotations

import plistlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from tests.helpers import (
    create_synthetic_extraction,
    read_csv_rows,
    refresh_synthetic_source_snapshot,
    write_legacy_archive,
)
from tvtime_extractor.analyze import analyze_extraction
from tvtime_extractor.errors import UnsupportedSchemaError
from tvtime_extractor.extract import PRIMARY_DOMAIN
from tvtime_extractor.legacy_cache import decode_legacy_cache_archive
from tvtime_extractor.report import build_report

SYNTHETIC_OWNER_ID = "900000001"
SERIES_ID = 7100
SOCIAL_PROFILE_ID = 7999
MOVIE_ONE_UUID = "10000000-0000-4000-8000-000000000001"
MOVIE_TWO_UUID = "10000000-0000-4000-8000-000000000002"


def synthetic_movie(
    uuid: str,
    *,
    name: str,
    tvdb_id: int,
    watched_at: str,
    extended_is_watched: bool = True,
) -> dict[str, object]:
    return {
        "uuid": uuid,
        "entity_type": "movie",
        "type": "follow",
        "created_at": "2020-01-01T00:00:00Z",
        "updated_at": "2020-01-02T00:00:00Z",
        "watched_at": watched_at,
        "extended": {"is_watched": extended_is_watched},
        "filter": ["watched"],
        "meta": {
            "name": name,
            "external_sources": [{"source": "tvdb", "id": str(tvdb_id)}],
        },
    }


class LegacyURLCacheAnalysisTests(unittest.TestCase):
    def test_decoder_requires_one_nskeyedarchiver_url_and_json_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "synthetic-archive"
            write_legacy_archive(
                archive_path,
                url="https://api.example.invalid/v2/cacheable/show/7100",
                payload={"data": {"id": SERIES_ID, "name": "Synthetic Legacy Series"}},
            )
            archive_bytes = archive_path.read_bytes()

            decoded = decode_legacy_cache_archive(
                archive_bytes,
                source_id="synthetic-source",
                observed_mtime_ns=1,
                maximum_nodes=100,
            )
            self.assertIsNotNone(decoded)

            envelope = plistlib.loads(archive_bytes)
            envelope["$archiver"] = "SyntheticOtherArchiver"
            self.assertIsNone(
                decode_legacy_cache_archive(
                    plistlib.dumps(envelope, fmt=plistlib.FMT_BINARY),
                    source_id="synthetic-source",
                    observed_mtime_ns=1,
                    maximum_nodes=100,
                )
            )

            envelope["$archiver"] = "NSKeyedArchiver"
            envelope["$objects"][2] = b"not-json"
            self.assertIsNone(
                decode_legacy_cache_archive(
                    plistlib.dumps(envelope, fmt=plistlib.FMT_BINARY),
                    source_id="synthetic-source",
                    observed_mtime_ns=1,
                    maximum_nodes=100,
                )
            )

    def test_legacy_archives_share_the_cache_row_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            documents = extraction / "raw" / PRIMARY_DOMAIN / "Documents"
            with closing(sqlite3.connect(documents / "DioCache.db")) as connection:
                connection.execute("DELETE FROM cache_dio")
                connection.commit()
            write_legacy_archive(
                documents / "synthetic-legacy-cache",
                url=(
                    "https://api.example.invalid/prod/v1/tracking/cgw/follows/user/"
                    "900000003?entity_type=movie"
                ),
                payload={"data": {"type": "list", "objects": []}},
            )
            refresh_synthetic_source_snapshot(extraction)

            with (
                mock.patch("tvtime_extractor.analyze.MAXIMUM_CACHE_ROWS", 0),
                self.assertRaises(UnsupportedSchemaError),
            ):
                analyze_extraction(extraction_directory=extraction)
            self.assertFalse((extraction / "analysis").exists())

    def test_legacy_url_cache_archives_recover_supported_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            documents = extraction / "raw" / PRIMARY_DOMAIN / "Documents"
            cache = documents / "DioCache.db"
            with closing(sqlite3.connect(cache)) as connection:
                connection.execute("DELETE FROM cache_dio")
                connection.commit()

            movie_one = synthetic_movie(
                MOVIE_ONE_UUID,
                name="Synthetic Legacy Movie One",
                tvdb_id=7201,
                watched_at="2020-02-03T04:05:06Z",
            )
            movie_two = synthetic_movie(
                MOVIE_TWO_UUID,
                name="Synthetic Legacy Movie Two",
                tvdb_id=7202,
                watched_at="0001-01-01T00:00:00Z",
                extended_is_watched=False,
            )
            write_legacy_archive(
                documents / "legacy-cache-profile",
                url=f"https://api.example.invalid/v2/user/{SYNTHETIC_OWNER_ID}",
                payload={
                    "data": {
                        "id": int(SYNTHETIC_OWNER_ID),
                        "created_at": "2020-01-01T00:00:00Z",
                        "shows": [
                            {
                                "id": SERIES_ID,
                                "name": "Synthetic Legacy Series",
                                "status": "Continuing",
                                "watched_episode_count": 1,
                                "aired_episode_count": 2,
                                "seasons": [
                                    {
                                        "number": 1,
                                        "episodes": [
                                            {
                                                "id": 710001,
                                                "number": 1,
                                                "name": "Synthetic Episode One",
                                                "air_date": "2020-01-01T00:00:00Z",
                                                "is_special": False,
                                            },
                                            {
                                                "id": 710002,
                                                "number": 2,
                                                "name": "Synthetic Episode Two",
                                                "air_date": "2020-01-08T00:00:00Z",
                                                "is_special": False,
                                            },
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                },
            )
            write_legacy_archive(
                documents / "legacy-cache-following",
                url=(
                    "https://api.example.invalid/v2/cacheable/user/"
                    f"{SYNTHETIC_OWNER_ID}/allfollowing"
                ),
                payload={
                    "data": [
                        {
                            "id": SERIES_ID,
                            "name": "Synthetic Legacy Series",
                            "watched_episode_count": 1,
                            "aired_episode_count": 2,
                        },
                        {
                            "id": SOCIAL_PROFILE_ID,
                            "name": "Synthetic Social Profile Must Stay Private",
                        },
                    ]
                },
            )
            write_legacy_archive(
                documents / "legacy-cache-movies",
                url=(
                    "https://api.example.invalid/prod/v1/tracking/cgw/follows/user/"
                    f"{SYNTHETIC_OWNER_ID}?entity_type=movie"
                ),
                payload={"data": {"type": "list", "objects": [movie_one, movie_two]}},
            )
            write_legacy_archive(
                documents / "legacy-cache-watches",
                url=(
                    "https://api.example.invalid/prod/v1/tracking/watches/user/"
                    f"{SYNTHETIC_OWNER_ID}?entity_type=movie"
                ),
                payload={
                    "data": {
                        "type": "watch",
                        "objects": [
                            {
                                "uuid": MOVIE_ONE_UUID,
                                "entity_type": "movie",
                                "type": "watch",
                                "watched_at": "2020-02-03T04:05:06Z",
                                "created_at": "2020-02-03T04:05:06Z",
                                "updated_at": "2020-02-03T04:05:06Z",
                            }
                        ],
                    }
                },
            )
            write_legacy_archive(
                documents / "legacy-cache-favorites",
                url=(f"https://api.example.invalid/prod/v1/lists/cgw/user/{SYNTHETIC_OWNER_ID}"),
                payload={
                    "data": [
                        {
                            "id": "favorite-movies",
                            "name": "Synthetic Favorite Movies",
                            "type": "list",
                            "objects": [movie_one],
                        }
                    ]
                },
            )
            refresh_synthetic_source_snapshot(extraction)

            summary = analyze_extraction(extraction_directory=extraction)

            self.assertEqual(summary["series_library"], 1)
            self.assertEqual(summary["movie_library"], 2)
            self.assertEqual(summary["watched_movies"], 2)
            self.assertEqual(summary["movie_watchlist"], 0)
            self.assertEqual(summary["favorite_movies"], 1)
            self.assertEqual(summary["watch_events"], 1)
            self.assertEqual(summary["episode_cache_unique"], 2)
            analysis = extraction / "analysis"
            movies = read_csv_rows(analysis / "movie_library.csv")
            self.assertEqual(
                [row["name"] for row in movies],
                ["Synthetic Legacy Movie One", "Synthetic Legacy Movie Two"],
            )
            self.assertEqual(movies[1]["watched_at"], "")
            normalized_text = "\n".join(
                path.read_text(encoding="utf-8") for path in analysis.iterdir() if path.is_file()
            )
            self.assertNotIn("Synthetic Social Profile Must Stay Private", normalized_text)
            self.assertNotIn("api.example.invalid", normalized_text)

            build_report(extraction_directory=extraction)
            report = (analysis / "TVTime-Recovered-Data.md").read_text(encoding="utf-8")
            self.assertIn("Synthetic Legacy Series", report)
            self.assertIn("Synthetic Legacy Movie One", report)
            self.assertNotIn("Synthetic Social Profile Must Stay Private", report)


if __name__ == "__main__":
    unittest.main()
