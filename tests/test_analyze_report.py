from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from tests.helpers import (
    PROFILE_SENTINEL,
    create_synthetic_extraction,
    read_csv_rows,
    refresh_synthetic_source_snapshot,
)
from tvtime_extractor.analyze import analyze_extraction, latest_watch_events, readonly_sqlite
from tvtime_extractor.display_text import has_display_text, normalize_display_text
from tvtime_extractor.errors import TVTimeError, UserInputError
from tvtime_extractor.extract import PRIMARY_DOMAIN
from tvtime_extractor.report import build_report, decode_tvtime_image_url


def mutate_cache_payload(
    extraction: Path,
    *,
    key: str,
    subkey: str,
    mutate,
) -> None:
    cache = extraction / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
    with closing(sqlite3.connect(cache)) as connection:
        row = connection.execute(
            "SELECT content FROM cache_dio WHERE key = ? AND subKey = ?",
            (key, subkey),
        ).fetchone()
        if row is None:
            raise AssertionError("Synthetic cache row was missing")
        payload = json.loads(row[0])
        mutate(payload)
        connection.execute(
            "UPDATE cache_dio SET content = ? WHERE key = ? AND subKey = ?",
            (json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(), key, subkey),
        )
        connection.commit()
    refresh_synthetic_source_snapshot(extraction)


class AnalyzeAndReportTests(unittest.TestCase):
    def test_invisible_movie_name_uses_placeholder_without_report_mismatch(self) -> None:
        for invisible_name in (" \t\n ", "\u200b\u2060\u200e\ufe0f"):
            with (
                self.subTest(value=ascii(invisible_name)),
                tempfile.TemporaryDirectory() as temporary,
            ):
                extraction = create_synthetic_extraction(Path(temporary))

                def replace_movie_name(
                    payload: dict[str, object], replacement: str = invisible_name
                ) -> None:
                    data = payload["data"]
                    assert isinstance(data, dict)
                    objects = data["objects"]
                    assert isinstance(objects, list)
                    movie = objects[0]
                    assert isinstance(movie, dict)
                    meta = movie["meta"]
                    assert isinstance(meta, dict)
                    meta["name"] = replacement

                mutate_cache_payload(
                    extraction,
                    key="https://api.example.invalid/library?account=synthetic",
                    subkey="library",
                    mutate=replace_movie_name,
                )
                summary = analyze_extraction(extraction_directory=extraction)
                self.assertEqual(summary["watch_events_with_titles"], 0)

                report_summary = build_report(extraction_directory=extraction)
                self.assertEqual(report_summary["named_watch_events"], 0)
                report = (extraction / "analysis" / "TVTime-Recovered-Data.md").read_text(
                    encoding="utf-8"
                )
                self.assertIn(r"\[movie title not present in cache\]", report)
                self.assertIn(r"\[title not present in cache\]", report)

    def test_display_text_preserves_joiners_but_neutralizes_format_controls(self) -> None:
        self.assertFalse(has_display_text("\u200b\u2060\u200e\ufe0f"))
        self.assertEqual(
            normalize_display_text("Safe\u202eTitle\u2066Name"),
            "Safe Title Name",
        )
        self.assertEqual(normalize_display_text("👩\u200d💻"), "👩\u200d💻")

    def test_distinct_episodes_without_ids_remain_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))

            def replace_episodes(payload: dict[str, object]) -> None:
                data = payload["data"]
                assert isinstance(data, list)
                first = dict(data[0])
                first.pop("id", None)
                show = dict(first["show"])
                show["id"] = ""
                first["show"] = show
                first["number"] = 2
                first["name"] = "No-ID Episode Two"
                second = dict(first)
                second["show"] = dict(show)
                second["number"] = 3
                second["name"] = "No-ID Episode Three"
                second["air_date"] = "2025-03-08T00:00:00Z"
                payload["data"] = [first, dict(first), second]

            mutate_cache_payload(
                extraction,
                key="https://api.example.invalid/episodes",
                subkey="series",
                mutate=replace_episodes,
            )
            summary = analyze_extraction(extraction_directory=extraction)
            self.assertEqual(summary["episode_cache_unique"], 2)
            rows = read_csv_rows(extraction / "analysis" / "episode_cache_unique.csv")
            self.assertEqual(
                {row["episode_name"] for row in rows},
                {"No-ID Episode Two", "No-ID Episode Three"},
            )
            build_report(extraction_directory=extraction)
            report = (extraction / "analysis" / "TVTime-Recovered-Data.md").read_text(
                encoding="utf-8"
            )
            self.assertEqual(report.count("No-ID Episode Two"), 1)
            self.assertEqual(report.count("No-ID Episode Three"), 1)

    def test_renamed_favorite_with_stable_id_is_one_latest_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))

            def add_renamed_favorite(payload: dict[str, object]) -> None:
                data = payload["data"]
                assert isinstance(data, dict)
                objects = data["objects"]
                assert isinstance(objects, list)
                renamed = dict(objects[0])
                renamed["name"] = "Renamed Favorite Movie"
                renamed["updated_at"] = "2026-01-10T00:00:00Z"
                objects.append(renamed)

            mutate_cache_payload(
                extraction,
                key="https://api.example.invalid/favorites",
                subkey="movies",
                mutate=add_renamed_favorite,
            )
            summary = analyze_extraction(extraction_directory=extraction)
            self.assertEqual(summary["favorite_movies"], 1)
            rows = read_csv_rows(extraction / "analysis" / "favorite_movies.csv")
            self.assertEqual([row["name"] for row in rows], ["Renamed Favorite Movie"])
            build_report(extraction_directory=extraction)
            report = (extraction / "analysis" / "TVTime-Recovered-Data.md").read_text(
                encoding="utf-8"
            )
            self.assertEqual(report.count("Renamed Favorite Movie"), 1)
            self.assertNotIn("Favorite Example Movie", report)

    def test_image_url_decoder_keeps_only_safe_relative_source_references(self) -> None:
        safe_payload = {
            "key": "episodes/screens/synthetic.jpg",
            "edits": {"resize": {"width": 640, "height": 360}},
        }
        safe_token = (
            base64.urlsafe_b64encode(json.dumps(safe_payload).encode()).decode().rstrip("=")
        )
        source, width, height = decode_tvtime_image_url(
            f"https://images.example.invalid/image/raw/{safe_token}?private=removed"
        )
        self.assertEqual(source, "episodes/screens/synthetic.jpg")
        self.assertEqual((width, height), ("640", "360"))

        unsafe_payload = {"key": "..%2F..%2Fprivate.jpg"}
        unsafe_token = (
            base64.urlsafe_b64encode(json.dumps(unsafe_payload).encode()).decode().rstrip("=")
        )
        source, _, _ = decode_tvtime_image_url(
            f"https://images.example.invalid/image/raw/{unsafe_token}?private=removed"
        )
        self.assertEqual(source, f"https://images.example.invalid/image/raw/{unsafe_token}")

    @unittest.skipIf(os.name == "nt", "Windows mutation lock rejects an active SQLite writer")
    def test_readonly_sqlite_includes_committed_wal_rows_without_modifying_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "synthetic.db"
            writer = sqlite3.connect(database)
            try:
                self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE records (value TEXT)")
                writer.commit()
                writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                writer.execute("INSERT INTO records VALUES ('synthetic committed row')")
                writer.commit()

                wal = database.with_name(database.name + "-wal")
                self.assertTrue(wal.is_file())
                before = {
                    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (database, wal)
                }
                with readonly_sqlite(database) as connection:
                    self.assertEqual(
                        connection.execute("SELECT count(*) FROM records").fetchone()[0], 1
                    )
                after = {
                    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (database, wal)
                }
                self.assertEqual(after, before)
            finally:
                writer.close()

    def test_readonly_sqlite_supports_builds_without_extension_loading_api(self) -> None:
        class ConnectionWithoutExtensionAPI:
            def __init__(self) -> None:
                self.statements: list[str] = []
                self.closed = False

            def execute(self, statement: str):
                self.statements.append(statement)
                return self

            def close(self) -> None:
                self.closed = True

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "synthetic.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("CREATE TABLE records (value TEXT)")
            replacement = ConnectionWithoutExtensionAPI()
            with (
                mock.patch(
                    "tvtime_extractor.analyze.sqlite3.connect",
                    return_value=replacement,
                ),
                readonly_sqlite(database) as connection,
            ):
                self.assertIs(connection, replacement)
            self.assertEqual(
                replacement.statements[:2],
                ["PRAGMA query_only = ON", "PRAGMA trusted_schema = OFF"],
            )
            self.assertTrue(replacement.closed)

    def test_watch_event_identity_retains_rewatches_and_removes_page_duplicates(self) -> None:
        first = {
            "uuid": "11111111-1111-4111-8111-111111111111",
            "entity_type": "movie",
            "type": "watch",
            "watched_at": "2025-01-02T03:04:05Z",
            "updated_at": "2025-01-02T03:04:05Z",
        }
        rewatch = {**first, "watched_at": "2025-02-03T04:05:06Z"}
        self.assertEqual(latest_watch_events([first, dict(first), rewatch]), [first, rewatch])

    def test_safe_defaults_create_normalized_tables_and_sanitized_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            summary = analyze_extraction(extraction_directory=extraction)

            self.assertEqual(summary["dio_cache_quick_check"], "ok")
            self.assertEqual(summary["cache_rows"], 8)
            self.assertEqual(summary["unique_cache_payloads"], 7)
            self.assertEqual(summary["movie_library"], 2)
            self.assertEqual(summary["watched_movies"], 1)
            self.assertEqual(summary["movie_watchlist"], 1)
            self.assertEqual(summary["series_library"], 1)
            self.assertEqual(summary["watch_events"], 1)
            self.assertEqual(summary["favorite_movies"], 1)
            self.assertEqual(summary["favorite_shows"], 1)
            self.assertEqual(summary["episode_cache_unique"], 1)
            self.assertEqual(summary["profile_payloads_detected_not_exported"], 1)
            self.assertFalse(summary["raw_cache_exported"])

            analysis = extraction / "analysis"
            self.assertFalse((analysis / "cache_responses").exists())
            cache_index = read_csv_rows(analysis / "cache_index.csv")
            self.assertEqual(len(cache_index), 8)
            self.assertEqual(
                set(cache_index[0]),
                {
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
                },
            )
            normalized_text = "\n".join(
                path.read_text(encoding="utf-8") for path in analysis.iterdir() if path.is_file()
            )
            self.assertNotIn(PROFILE_SENTINEL, normalized_text)
            self.assertNotIn("duplicate-private-cache-key", normalized_text)
            self.assertNotIn("binary-private-subkey", normalized_text)

            report_summary = build_report(extraction_directory=extraction)
            self.assertEqual(report_summary["series"], 1)
            self.assertEqual(report_summary["watched_movies"], 1)
            self.assertEqual(report_summary["movie_watchlist"], 1)
            self.assertEqual(report_summary["named_watch_events"], 1)
            self.assertEqual(report_summary["image_cache_references"], 1)

            report = (analysis / "TVTime-Recovered-Data.md").read_text(encoding="utf-8")
            self.assertIn("Example Movie", report)
            self.assertIn("Example Series", report)
            self.assertIn("2025-01-02", report)
            self.assertNotIn("2025-01-02T03:04:05Z", report)
            self.assertNotIn("11111111-1111-4111-8111-111111111111", report)
            self.assertNotIn(PROFILE_SENTINEL, report)

            media_text = (analysis / "media_url_inventory.csv").read_text(encoding="utf-8")
            trailer_text = (analysis / "trailer_references.csv").read_text(encoding="utf-8")
            image_text = (analysis / "image_cache_references.csv").read_text(encoding="utf-8")
            published_urls = "\n".join((media_text, trailer_text, image_text))
            self.assertIn("https://www.youtube.com/watch?v=demo-video", published_urls)
            self.assertIn("https://cdn.example.invalid/posters/example.jpg", published_urls)
            self.assertNotIn("SYNTHETIC_TOKEN", published_urls)
            self.assertNotIn("SYNTHETIC_SIGNATURE", published_urls)
            self.assertNotIn("demo:secret", published_urls)
            self.assertNotIn("#private", published_urls)

            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(analysis.stat().st_mode), 0o700)
                self.assertEqual(
                    stat.S_IMODE((analysis / "TVTime-Recovered-Data.md").stat().st_mode),
                    0o600,
                )

    def test_report_escapes_unrecognized_date_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            analyze_extraction(extraction_directory=extraction)
            series_path = extraction / "analysis" / "series_library.csv"
            rows = read_csv_rows(series_path)
            rows[0]["followed_at"] = "<script>alert(1)</script>\n# injected [link]"
            with series_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)

            build_report(extraction_directory=extraction)
            report = (extraction / "analysis" / "TVTime-Recovered-Data.md").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("<script>", report)
            self.assertNotIn("\n# injected", report)
            self.assertIn(
                "&lt;script&gt;alert(1)&lt;/script&gt; \\# injected \\[link\\]",
                report,
            )

    def test_raw_cache_export_is_explicit_and_uses_opaque_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            summary = analyze_extraction(
                extraction_directory=extraction,
                include_raw_cache=True,
            )
            self.assertTrue(summary["raw_cache_exported"])
            responses = extraction / "analysis" / "cache_responses"
            exported = sorted(path.name for path in responses.iterdir())
            self.assertEqual(len(exported), 8)
            self.assertTrue(
                all(re.fullmatch(r"[0-9a-f]{24}\.(?:json|bin)", name) for name in exported)
            )
            raw_text = "\n".join(
                path.read_text(encoding="utf-8", errors="replace") for path in responses.iterdir()
            )
            self.assertIn(PROFILE_SENTINEL, raw_text)

    def test_analysis_refuses_to_mix_with_existing_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            analyze_extraction(extraction_directory=extraction)
            with self.assertRaises(UserInputError):
                analyze_extraction(extraction_directory=extraction)

    def test_schema_preflight_fails_before_creating_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            cache = extraction / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
            with closing(sqlite3.connect(cache)) as connection:
                connection.execute("DROP TABLE cache_dio")
                connection.execute("CREATE TABLE cache_dio (key TEXT, items BLOB)")
                connection.commit()
            refresh_synthetic_source_snapshot(extraction)

            with self.assertRaisesRegex(TVTimeError, "unsupported cache_dio schema"):
                analyze_extraction(extraction_directory=extraction)
            self.assertFalse((extraction / "analysis").exists())

    def test_populated_unknown_payload_shape_is_not_reported_as_empty_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            cache = extraction / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
            with closing(sqlite3.connect(cache)) as connection:
                connection.execute("DELETE FROM cache_dio")
                connection.execute(
                    "INSERT INTO cache_dio (key, subKey, content, statusCode) VALUES (?, ?, ?, ?)",
                    (
                        "https://api.example.invalid/new-schema",
                        "synthetic",
                        json.dumps({"data": {"type": "list", "items": []}}).encode(),
                        200,
                    ),
                )
                connection.commit()
            refresh_synthetic_source_snapshot(extraction)

            with self.assertRaisesRegex(TVTimeError, "no supported TV Time payloads"):
                analyze_extraction(extraction_directory=extraction)
            self.assertFalse((extraction / "analysis").exists())


if __name__ == "__main__":
    unittest.main()
