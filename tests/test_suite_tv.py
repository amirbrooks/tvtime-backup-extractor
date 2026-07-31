from __future__ import annotations

import csv
import hashlib
import io
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from tvtime_extractor.suite_tv import (
    LIBERATOR_FILENAMES,
    build_liberator_files,
    validate_liberator_files,
    write_suite_tv_zip,
)

SERIES = [
    {
        "uuid": "30000000-0000-4000-8000-000000000001",
        "series_id": "101",
        "name": "Synthetic Suite Series",
        "followed_at": "2020-01-01T00:00:00Z",
        "created_at": "2020-01-01T00:00:00Z",
        "watched_episode_count": "2",
        "aired_episode_count": "3",
    }
]
MOVIES = [
    {
        "uuid": "40000000-0000-4000-8000-000000000001",
        "name": "Synthetic Suite Movie",
        "tvdb_id": "501",
        "imdb_id": "",
        "created_at": "2020-02-01T00:00:00Z",
        "is_watched": "True",
        "watched_at": "2020-02-02T03:04:05Z",
        "rewatch_count": "2",
    },
    {
        "uuid": "40000000-0000-4000-8000-000000000002",
        "name": "Synthetic Unknown-Date Movie",
        "tvdb_id": "502",
        "imdb_id": "tt0000502",
        "created_at": "2020-02-03T00:00:00Z",
        "is_watched": "True",
        "watched_at": "",
        "rewatch_count": "0",
    },
    {
        "uuid": "40000000-0000-4000-8000-000000000003",
        "name": "Synthetic Movie Without TVDB",
        "tvdb_id": "",
        "is_watched": "False",
    },
]
EPISODES = [
    {
        "episode_id": "1000",
        "show_id": "101",
        "show_name": "Synthetic Suite Series",
        "season": "0",
        "episode": "1",
        "is_special": "",
        "is_watched": "False",
        "seen": "False",
        "seen_date": "",
    },
    {
        "episode_id": "1001",
        "show_id": "101",
        "show_name": "Synthetic Suite Series",
        "season": "1",
        "episode": "1",
        "is_special": "False",
        "is_watched": "False",
        "seen": "False",
        "seen_date": "",
    },
    {
        "episode_id": "1002",
        "show_id": "101",
        "show_name": "Synthetic Suite Series",
        "season": "1",
        "episode": "2",
        "is_special": "False",
        "is_watched": "True",
        "seen": "True",
        "seen_date": "2020-03-02T01:02:03Z",
    },
    {
        "episode_id": "1003",
        "show_id": "101",
        "show_name": "Synthetic Suite Series",
        "season": "1",
        "episode": "3",
        "is_special": "False",
        "is_watched": "False",
        "seen": "False",
        "seen_date": "",
    },
]
FAVORITES = {
    "movies": [
        {
            "uuid": "40000000-0000-4000-8000-000000000001",
            "created_at": "2020-04-01T00:00:00Z",
        }
    ],
    "shows": [
        {
            "uuid": "30000000-0000-4000-8000-000000000001",
            "created_at": "2020-04-02T00:00:00Z",
        }
    ],
}


class SuiteTVLiberatorTests(unittest.TestCase):
    def test_confirmed_files_match_liberator_schema(self) -> None:
        files = build_liberator_files(
            series=SERIES,
            movies=MOVIES,
            favorites=FAVORITES,
            episodes=EPISODES,
            estimate_progress=False,
        )

        self.assertEqual(tuple(files), LIBERATOR_FILENAMES)
        shows = json.loads(files["shows.json"])
        movies = json.loads(files["movies.json"])
        favorites = json.loads(files["favorites.json"])
        self.assertEqual(json.loads(files["lists.json"]), [])

        self.assertEqual(
            movies[0],
            {
                "id": {"tvdb": 501, "imdb": "-1"},
                "uuid": "40000000-0000-4000-8000-000000000001",
                "title": "Synthetic Suite Movie",
                "created_at": "2020-02-01T00:00:00Z",
                "rating": None,
                "is_watched": True,
                "rewatch_count": 2,
                "watched_at": "2020-02-02T03:04:05Z",
            },
        )
        self.assertEqual(movies[1]["id"], {"tvdb": 502, "imdb": "tt0000502"})
        self.assertNotIn("watched_at", movies[1])
        self.assertEqual(len(movies), 2)

        self.assertEqual(shows[0]["id"], {"tvdb": 101, "imdb": "-1"})
        self.assertEqual(shows[0]["status"], "continuing")
        episodes = {
            episode["id"]["tvdb"]: episode
            for season in shows[0]["seasons"]
            for episode in season["episodes"]
        }
        self.assertTrue(episodes[1000]["special"])
        self.assertFalse(episodes[1000]["is_watched"])
        self.assertFalse(episodes[1001]["is_watched"])
        self.assertTrue(episodes[1002]["is_watched"])
        self.assertEqual(episodes[1002]["watched_at"], "2020-03-02T01:02:03Z")
        self.assertFalse(episodes[1003]["is_watched"])

        self.assertEqual(favorites["name"], "Favorites")
        self.assertFalse(favorites["is_public"])
        self.assertEqual(
            favorites["movies"],
            [
                {
                    "id": {"tvdb": 501, "imdb": "-1"},
                    "uuid": "40000000-0000-4000-8000-000000000001",
                    "title": "Synthetic Suite Movie",
                    "created_at": "2020-02-01T00:00:00Z",
                    "rating": None,
                    "added_at": "2020-04-01T00:00:00Z",
                }
            ],
        )
        self.assertNotIn("is_watched", favorites["movies"][0])
        self.assertEqual(favorites["shows"][0]["added_at"], "2020-04-02T00:00:00Z")
        self.assertNotIn("status", favorites["shows"][0])

        activity = files["activity_history.csv"].decode("utf-8")
        self.assertIn("\r\n", activity)
        rows = list(csv.DictReader(io.StringIO(activity)))
        self.assertEqual([row["type"] for row in rows], ["movie", "movie", "episode", "show"])
        self.assertEqual(rows[0]["is_watched"], "true")
        self.assertEqual(rows[0]["is_watchlisted"], "false")
        self.assertEqual(rows[1]["is_watched"], "true")
        self.assertEqual(rows[1]["is_watchlisted"], "true")
        self.assertEqual(rows[2]["is_special"], "false")

    def test_estimated_progress_retains_exact_watches_and_never_marks_specials(self) -> None:
        files = build_liberator_files(
            series=SERIES,
            movies=MOVIES,
            favorites=FAVORITES,
            episodes=EPISODES,
            estimate_progress=True,
        )

        shows = json.loads(files["shows.json"])
        episodes = {
            episode["id"]["tvdb"]: episode
            for season in shows[0]["seasons"]
            for episode in season["episodes"]
        }
        self.assertFalse(episodes[1000]["is_watched"])
        self.assertTrue(episodes[1001]["is_watched"])
        self.assertNotIn("watched_at", episodes[1001])
        self.assertTrue(episodes[1002]["is_watched"])
        self.assertEqual(episodes[1002]["watched_at"], "2020-03-02T01:02:03Z")
        self.assertFalse(episodes[1003]["is_watched"])

    def test_invalid_series_identifier_is_omitted(self) -> None:
        files = build_liberator_files(
            series=[{**SERIES[0], "series_id": "0"}],
            movies=MOVIES,
            favorites=FAVORITES,
            episodes=EPISODES,
            estimate_progress=False,
        )

        self.assertEqual(json.loads(files["shows.json"]), [])

    def test_recovered_stopped_status_is_preserved_and_invalid_episodes_are_omitted(self) -> None:
        files = build_liberator_files(
            series=[{**SERIES[0], "filters": "followed | stopped"}],
            movies=MOVIES,
            favorites=FAVORITES,
            episodes=[
                *EPISODES,
                {
                    "episode_id": "1004",
                    "show_id": "101",
                    "season": "1",
                    "episode": "0",
                    "is_watched": "True",
                },
            ],
            estimate_progress=False,
        )

        shows = json.loads(files["shows.json"])
        self.assertEqual(shows[0]["status"], "stopped")
        self.assertNotIn(
            1004,
            {
                episode["id"]["tvdb"]
                for season in shows[0]["seasons"]
                for episode in season["episodes"]
            },
        )

    def test_semantic_validator_rejects_resealed_false_data(self) -> None:
        files = build_liberator_files(
            series=SERIES,
            movies=MOVIES,
            favorites=FAVORITES,
            episodes=EPISODES,
            estimate_progress=False,
        )
        corruptions = []

        invalid_show = dict(files)
        shows = json.loads(invalid_show["shows.json"])
        shows[0]["id"]["tvdb"] = 0
        invalid_show["shows.json"] = json.dumps(shows).encode("utf-8")
        corruptions.append(invalid_show)

        public_favorites = dict(files)
        favorites = json.loads(public_favorites["favorites.json"])
        favorites["is_public"] = True
        public_favorites["favorites.json"] = json.dumps(favorites).encode("utf-8")
        corruptions.append(public_favorites)

        wrong_activity = dict(files)
        wrong_activity["activity_history.csv"] += b"synthetic,false,row\r\n"
        corruptions.append(wrong_activity)

        for corrupted in corruptions:
            with (
                self.subTest(
                    filename=next(name for name in files if files[name] != corrupted[name])
                ),
                self.assertRaises(ValueError),
            ):
                validate_liberator_files(corrupted)

    def test_synthetic_compatibility_fixture_pins_exact_bytes(self) -> None:
        fixture = json.loads(
            (Path(__file__).parent / "fixtures" / "suite_tv_liberator_v1.json").read_text(
                encoding="utf-8"
            )
        )
        files = build_liberator_files(
            series=SERIES,
            movies=MOVIES,
            favorites=FAVORITES,
            episodes=EPISODES,
            estimate_progress=False,
        )

        self.assertEqual(fixture["contract"], "suite-tv-liberator-v1")
        self.assertEqual(
            fixture["upstream_commit"],
            "a18caa46fbf8d611cc60f048c480e8981d7e6c05",
        )
        self.assertEqual(
            fixture["sha256"],
            {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()},
        )

    def test_zip_has_exact_root_members_and_private_permissions(self) -> None:
        files = build_liberator_files(
            series=SERIES,
            movies=MOVIES,
            favorites=FAVORITES,
            episodes=EPISODES,
            estimate_progress=False,
        )
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "Suite-TV-Liberator-confirmed.zip"

            write_suite_tv_zip(archive_path, files)

            self.assertEqual(stat.S_IMODE(archive_path.stat().st_mode), 0o600)
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(tuple(archive.namelist()), LIBERATOR_FILENAMES)
                self.assertTrue(all("/" not in name for name in archive.namelist()))
                self.assertTrue(
                    all(info.compress_type == zipfile.ZIP_STORED for info in archive.infolist())
                )
                self.assertTrue(
                    all((info.external_attr >> 16) & 0o777 == 0o600 for info in archive.infolist())
                )
                self.assertEqual(
                    {name: archive.read(name) for name in archive.namelist()},
                    files,
                )


if __name__ == "__main__":
    unittest.main()
