from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import os
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

from script import convert_refract_series as refract_cli
from tvtime_extractor.errors import OutputExistsError
from tvtime_extractor.refract import (
    EPISODE_FIELDS,
    FAVORITE_FIELDS,
    SERIES_FIELDS,
    RefractConversionError,
    build_refract_series_payload,
    convert_refract_series,
)
from tvtime_extractor.safety import (
    secure_directory,
    write_csv_private,
    write_json_private,
)


def _series_row(**changes: object) -> dict[str, object]:
    row: dict[str, object] = {
        "uuid": "synthetic-series-uuid",
        "series_id": "101",
        "name": "Synthetic Series",
        "country": "ZZ",
        "is_ended": "False",
        "followed_at": "2024-01-01T00:00:00Z",
        "last_watch_date": "2024-02-03T04:05:06Z",
        "filters": "followed | continuing",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-02-03T04:05:06Z",
    }
    row.update(changes)
    return row


def _episode_row(**changes: object) -> dict[str, object]:
    row: dict[str, object] = {
        "source_id": "synthetic-cache-source",
        "episode_id": "1001",
        "show_id": "101",
        "show_name": "Synthetic Series",
        "season": "1",
        "episode": "1",
        "episode_name": "Synthetic Pilot",
        "air_date": "2024-01-01T00:00:00Z",
        "seen": "True",
        "seen_date": "2024-02-03T05:05:06+01:00",
        "is_watched": "False",
        "runtime": "2700",
    }
    row.update(changes)
    return row


def _favorite_row(**changes: object) -> dict[str, object]:
    row: dict[str, object] = {
        "uuid": "synthetic-favorite-uuid",
        "id": "101",
        "name": "Synthetic Series",
        "type": "series",
        "status": "followed",
        "created_at": "2024-01-01T00:00:00Z",
        "watched_episode_count": "1",
        "aired_episode_count": "1",
        "is_followed": "True",
        "is_up_to_date": "True",
    }
    row.update(changes)
    return row


def _write_analysis(
    root: Path,
    *,
    series: list[dict[str, object]],
    episodes: list[dict[str, object]] | None = None,
    favorites: list[dict[str, object]] | None = None,
) -> Path:
    extraction = secure_directory(root / "Synthetic-Extraction")
    analysis = secure_directory(extraction / "analysis")
    escapes: dict[str, object] = {}
    series_escapes = write_csv_private(
        analysis / "series_library.csv",
        series,
        SERIES_FIELDS,
    )
    if series_escapes:
        escapes["series_library.csv"] = series_escapes
    if episodes is not None:
        episode_escapes = write_csv_private(
            analysis / "episode_cache_unique.csv",
            episodes,
            EPISODE_FIELDS,
        )
        if episode_escapes:
            escapes["episode_cache_unique.csv"] = episode_escapes
    if favorites is not None:
        favorite_escapes = write_csv_private(
            analysis / "favorite_shows.csv",
            favorites,
            FAVORITE_FIELDS,
        )
        if favorite_escapes:
            escapes["favorite_shows.csv"] = favorite_escapes
    write_json_private(
        analysis / "analysis_summary.json",
        {"csv_spreadsheet_escaped_cells": escapes},
    )
    return analysis


def _analysis_hashes(analysis: Path) -> dict[str, str]:
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(analysis.iterdir())
    }


class RefractPayloadTests(unittest.TestCase):
    def test_maps_series_episodes_specials_favorites_and_recorded_escapes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = _write_analysis(
                root,
                series=[
                    _series_row(name="=Synthetic Escaped Series"),
                    _series_row(
                        uuid="synthetic-empty-uuid",
                        series_id="202",
                        name="Synthetic Empty Series",
                        created_at="",
                    ),
                ],
                episodes=[
                    _episode_row(),
                    _episode_row(
                        episode_id="1002",
                        season="0",
                        episode="2",
                        episode_name="Synthetic Special",
                        seen="False",
                        seen_date="",
                        is_watched="False",
                    ),
                    _episode_row(
                        episode_id="1003",
                        episode="3",
                        episode_name="TBA",
                    ),
                    _episode_row(episode_id="9001", show_id="999"),
                ],
                favorites=[
                    _favorite_row(),
                    _favorite_row(uuid="synthetic-unmatched-favorite", id="999"),
                ],
            )

            payload, stats = build_refract_series_payload(analysis)

            self.assertEqual(stats.series, 2)
            self.assertEqual(stats.episodes, 2)
            self.assertEqual(stats.unmatched_episode_rows, 1)
            self.assertEqual(stats.ignored_episode_rows, 1)
            self.assertEqual(stats.unmatched_favorite_rows, 1)
            first = payload[0]
            self.assertEqual(first["title"], "=Synthetic Escaped Series")
            self.assertEqual(first["id"], {"tvdb": 101, "imdb": None})
            self.assertEqual(first["status"], "up_to_date")
            self.assertTrue(first["is_favorite"])
            self.assertFalse(first["_noEpisodeData"])
            self.assertEqual([season["number"] for season in first["seasons"]], [0, 1])
            special = first["seasons"][0]["episodes"][0]
            watched = first["seasons"][1]["episodes"][0]
            self.assertTrue(special["special"])
            self.assertFalse(special["is_watched"])
            self.assertEqual(special["watched_count"], 0)
            self.assertEqual(watched["watched_at"], "2024-02-03T04:05:06Z")
            self.assertTrue(watched["is_watched"])
            self.assertEqual(watched["rewatch_count"], 0)
            self.assertEqual(watched["watched_count"], 1)

            empty = payload[1]
            self.assertEqual(empty["title"], "Synthetic Empty Series")
            self.assertEqual(empty["status"], "up_to_date")
            self.assertIsNone(empty["created_at"])
            self.assertTrue(empty["_noEpisodeData"])
            self.assertEqual(empty["seasons"], [])

    def test_missing_optional_tables_produces_completed_status_with_empty_seasons(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            analysis = _write_analysis(Path(temporary), series=[_series_row()])

            payload, stats = build_refract_series_payload(analysis)

            self.assertEqual(stats.episodes, 0)
            self.assertEqual(payload[0]["status"], "up_to_date")
            self.assertTrue(payload[0]["_noEpisodeData"])
            self.assertEqual(payload[0]["seasons"], [])
            self.assertFalse(payload[0]["is_favorite"])

    def test_seen_flag_survives_an_invalid_watch_date_without_inference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            analysis = _write_analysis(
                Path(temporary),
                series=[_series_row(last_watch_date="2099-12-31T23:59:59Z")],
                episodes=[_episode_row(seen="True", seen_date="not-a-date")],
            )

            payload, _stats = build_refract_series_payload(analysis)

            episode = payload[0]["seasons"][0]["episodes"][0]
            self.assertTrue(episode["is_watched"])
            self.assertIsNone(episode["watched_at"])

    def test_invalid_or_duplicate_series_ids_fail(self) -> None:
        for rows in (
            [_series_row(series_id="not-an-id")],
            [_series_row(), _series_row(uuid="synthetic-duplicate")],
        ):
            with self.subTest(rows=len(rows)), tempfile.TemporaryDirectory() as temporary:
                analysis = _write_analysis(Path(temporary), series=rows)
                with self.assertRaises(RefractConversionError):
                    build_refract_series_payload(analysis)

    def test_malformed_header_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extraction = secure_directory(root / "Synthetic-Extraction")
            analysis = secure_directory(extraction / "analysis")
            with (analysis / "series_library.csv").open(
                "w", encoding="utf-8", newline=""
            ) as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=SERIES_FIELDS[:-1],
                    extrasaction="ignore",
                )
                writer.writeheader()
                writer.writerow(_series_row())
            if os.name != "nt":
                os.chmod(analysis / "series_library.csv", 0o600)
            write_json_private(
                analysis / "analysis_summary.json",
                {"csv_spreadsheet_escaped_cells": {}},
            )

            with self.assertRaises(RefractConversionError):
                build_refract_series_payload(analysis)


class RefractOutputTests(unittest.TestCase):
    def test_conversion_creates_only_atomic_json_and_does_not_change_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = _write_analysis(
                root,
                series=[_series_row()],
                episodes=[_episode_row()],
                favorites=[_favorite_row()],
            )
            before = _analysis_hashes(analysis)
            output = root / "Synthetic-Refract-Output"

            result = convert_refract_series(
                analysis_directory=analysis,
                output_directory=output,
                export_date=date(2026, 7, 23),
            )

            self.assertEqual(before, _analysis_hashes(analysis))
            self.assertEqual(result.output_file.name, "tvtime-series-2026-07-23.json")
            self.assertEqual([path.name for path in output.iterdir()], [result.output_file.name])
            payload = json.loads(result.output_file.read_text(encoding="utf-8"))
            self.assertIsInstance(payload, list)
            self.assertEqual(payload[0]["id"]["tvdb"], 101)
            if os.name != "nt":
                self.assertEqual(stat_mode(output), 0o700)
                self.assertEqual(stat_mode(result.output_file), 0o600)

    def test_existing_output_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = _write_analysis(root, series=[_series_row()])
            output = secure_directory(root / "Synthetic-Existing-Output")
            sentinel = output / "synthetic-sentinel.txt"
            sentinel.write_text("synthetic sentinel", encoding="utf-8")

            with self.assertRaises(OutputExistsError):
                convert_refract_series(
                    analysis_directory=analysis,
                    output_directory=output,
                    export_date=date(2026, 7, 23),
                )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "synthetic sentinel")

    def test_invalid_input_creates_no_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = _write_analysis(root, series=[_series_row(series_id="invalid")])
            output = root / "Synthetic-No-Output"

            with self.assertRaises(RefractConversionError):
                convert_refract_series(
                    analysis_directory=analysis,
                    output_directory=output,
                    export_date=date(2026, 7, 23),
                )

            self.assertFalse(output.exists())

    def test_cli_suppresses_unexpected_secret_bearing_exception_text(self) -> None:
        secret = "SYNTHETIC-PASSWORD C:\\Synthetic\\Private recovered title"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                refract_cli,
                "convert_refract_series",
                side_effect=RuntimeError(secret),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = refract_cli.main(
                ["--analysis", "Synthetic-Analysis", "--output", "Synthetic-Output"]
            )

        self.assertEqual(result, 1)
        self.assertNotIn(secret, stdout.getvalue())
        self.assertNotIn(secret, stderr.getvalue())
        self.assertNotIn("RuntimeError", stderr.getvalue())

    @unittest.skipUnless(os.name == "nt", "Windows path parsing applies only on Windows")
    def test_cli_accepts_windows_paths(self) -> None:
        arguments = refract_cli.build_parser().parse_args(
            [
                "--analysis",
                r"C:\Private\Synthetic-Extraction\analysis",
                "--output",
                r"C:\Private\Synthetic-Refract-Output",
            ]
        )
        self.assertTrue(arguments.analysis.is_absolute())
        self.assertTrue(arguments.output.is_absolute())


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
