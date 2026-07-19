from __future__ import annotations

import base64
import csv
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from pypdf import PdfReader

from tests.helpers import create_synthetic_extraction, refresh_synthetic_source_snapshot
from tvtime_extractor.analyze import (
    _parse_cache_json,
    _sqlite_snapshot_sources,
    _validate_analysis_csv_output,
    _validate_analysis_summary_output,
    _validate_cache_json_complexity,
    _validate_cache_table_limits,
    _validate_csv_escape_metadata,
    analyze_extraction,
)
from tvtime_extractor.errors import UnsupportedSchemaError
from tvtime_extractor.report import (
    _preflight_report_table_counts,
    build_report,
    decode_tvtime_image_url,
    read_csv,
)
from tvtime_extractor.safety import secure_file
from tvtime_extractor.visual_report import (
    PRIVATE_NOTICE,
    SYNTHETIC_FIXTURE_NOTICE,
    build_visual_report_model,
    render_html_report,
    render_markdown_report,
    write_pdf_report,
)


def _visual_model(*, synthetic_fixture: bool):
    return build_visual_report_model(
        series=[
            {"name": "Same Series"},
            {"name": "same series"},
            {"name": ""},
        ],
        watched_movies=[],
        movie_watchlist=[],
        favorite_shows=[],
        favorite_movies=[],
        episodes=[],
        watch_events=[],
        extracted_file_count=1,
        image_cache_status="not present",
        trailer_count=0,
        media_url_counts={},
        image_category_counts={},
        synthetic_fixture=synthetic_fixture,
    )


class AnalysisBoundsTests(unittest.TestCase):
    def test_json_string_limit_counts_strict_utf8_bytes_at_exact_boundary(self) -> None:
        with mock.patch("tvtime_extractor.analyze.MAXIMUM_CACHE_JSON_STRING_BYTES", 4):
            self.assertEqual(_validate_cache_json_complexity({"éé": ""}), 3)
            with self.assertRaisesRegex(UnsupportedSchemaError, "JSON string byte size"):
                _validate_cache_json_complexity({"ééa": ""})

    def test_cache_metadata_types_and_multibyte_sizes_are_bounded_before_iteration(self) -> None:
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.execute(
                "CREATE TABLE cache_dio (key TEXT, subKey TEXT, content BLOB, statusCode INTEGER)"
            )
            connection.execute(
                "INSERT INTO cache_dio VALUES (?, ?, ?, ?)",
                ("éé", "ok", b"{}", 200),
            )
            with mock.patch("tvtime_extractor.analyze.MAXIMUM_CACHE_KEY_BYTES", 4):
                _validate_cache_table_limits(connection)
                connection.execute("UPDATE cache_dio SET key = ?", ("ééa",))
                with self.assertRaisesRegex(UnsupportedSchemaError, "cache-key byte size"):
                    _validate_cache_table_limits(connection)

            connection.execute("UPDATE cache_dio SET key = CAST(? AS BLOB)", ("not text",))
            with self.assertRaisesRegex(UnsupportedSchemaError, "unsupported cache key"):
                _validate_cache_table_limits(connection)

    def test_sqlite_snapshot_bounds_preflight_each_file_and_combined_total(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "bounded.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("CREATE TABLE sample (value TEXT)")
                connection.commit()
            sidecar = database.with_name(database.name + "-journal")
            sidecar.write_bytes(b"synthetic-sidecar")
            main_bytes = database.stat().st_size
            total_bytes = main_bytes + sidecar.stat().st_size

            with (
                mock.patch(
                    "tvtime_extractor.analyze.MAXIMUM_SQLITE_SNAPSHOT_FILE_BYTES",
                    main_bytes,
                ),
                mock.patch(
                    "tvtime_extractor.analyze.MAXIMUM_SQLITE_SNAPSHOT_TOTAL_BYTES",
                    total_bytes,
                ),
            ):
                self.assertEqual(len(_sqlite_snapshot_sources(database)), 2)

            with (
                mock.patch(
                    "tvtime_extractor.analyze.MAXIMUM_SQLITE_SNAPSHOT_FILE_BYTES",
                    main_bytes - 1,
                ),
                self.assertRaisesRegex(UnsupportedSchemaError, "snapshot-file byte size"),
            ):
                _sqlite_snapshot_sources(database)

            with (
                mock.patch(
                    "tvtime_extractor.analyze.MAXIMUM_SQLITE_SNAPSHOT_FILE_BYTES",
                    main_bytes,
                ),
                mock.patch(
                    "tvtime_extractor.analyze.MAXIMUM_SQLITE_SNAPSHOT_TOTAL_BYTES",
                    total_bytes - 1,
                ),
                self.assertRaisesRegex(UnsupportedSchemaError, "combined snapshot byte size"),
            ):
                _sqlite_snapshot_sources(database)

    def test_oversized_main_sqlite_fails_before_analysis_output_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            with (
                mock.patch("tvtime_extractor.analyze.MAXIMUM_SQLITE_SNAPSHOT_FILE_BYTES", 1),
                self.assertRaisesRegex(UnsupportedSchemaError, "snapshot-file byte size"),
            ):
                analyze_extraction(extraction_directory=extraction)
            self.assertFalse((extraction / "analysis").exists())
            self.assertFalse((extraction / ".analysis-incomplete").exists())

    def test_oversized_optional_sqlite_is_never_promoted_as_complete_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            app_root = extraction / "raw" / "AppDomain-com.tozelabs.tvshowtime"
            main_database = app_root / "Documents" / "DioCache.db"
            optional_database = (
                app_root / "Library" / "Application Support" / "libCachedImageData.db"
            )
            with optional_database.open("ab") as handle:
                handle.write(b"\x00" * (main_database.stat().st_size + 1))
            refresh_synthetic_source_snapshot(extraction)
            limit = max(main_database.stat().st_size, optional_database.stat().st_size - 1)
            self.assertLess(limit, optional_database.stat().st_size)
            with (
                mock.patch(
                    "tvtime_extractor.analyze.MAXIMUM_SQLITE_SNAPSHOT_FILE_BYTES",
                    limit,
                ),
                self.assertRaisesRegex(UnsupportedSchemaError, "snapshot-file byte size"),
            ):
                analyze_extraction(extraction_directory=extraction)
            self.assertFalse((extraction / "analysis").exists())
            self.assertTrue((extraction / ".analysis-incomplete").is_dir())

    def test_generated_csv_cell_file_and_summary_bounds_are_exact(self) -> None:
        rows = [{"value": "éé"}]
        with (
            mock.patch("tvtime_extractor.analyze.MAXIMUM_ANALYSIS_CSV_CELL_BYTES", 4),
            mock.patch("tvtime_extractor.analyze.MAXIMUM_ANALYSIS_CSV_ROW_BYTES", 1_024),
            mock.patch("tvtime_extractor.analyze.MAXIMUM_ANALYSIS_CSV_BYTES", 1_024),
        ):
            _validate_analysis_csv_output(rows, ("value",))
            with self.assertRaisesRegex(UnsupportedSchemaError, "CSV cell byte size"):
                _validate_analysis_csv_output([{"value": "ééa"}], ("value",))

        encoded = "value\r\néé\r\n".encode()
        with mock.patch(
            "tvtime_extractor.analyze.MAXIMUM_ANALYSIS_CSV_BYTES",
            len(encoded),
        ):
            _validate_analysis_csv_output(rows, ("value",))
        with (
            mock.patch(
                "tvtime_extractor.analyze.MAXIMUM_ANALYSIS_CSV_BYTES",
                len(encoded) - 1,
            ),
            self.assertRaisesRegex(UnsupportedSchemaError, "CSV file byte size"),
        ):
            _validate_analysis_csv_output(rows, ("value",))

        summary = {"value": "éé"}
        summary_bytes = len(
            (json.dumps(summary, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        )
        with mock.patch(
            "tvtime_extractor.analyze.MAXIMUM_ANALYSIS_SUMMARY_BYTES",
            summary_bytes,
        ):
            _validate_analysis_summary_output(summary)
        with (
            mock.patch(
                "tvtime_extractor.analyze.MAXIMUM_ANALYSIS_SUMMARY_BYTES",
                summary_bytes - 1,
            ),
            self.assertRaisesRegex(UnsupportedSchemaError, "analysis-summary byte size"),
        ):
            _validate_analysis_summary_output(summary)

    def test_escape_metadata_and_report_csv_preopen_bounds_are_exact(self) -> None:
        metadata = {
            "synthetic.csv": [
                {"row": 1, "field": "value"},
                {"row": 2, "field": "value"},
            ]
        }
        with mock.patch("tvtime_extractor.analyze.MAXIMUM_CSV_ESCAPE_ENTRIES", 2):
            _validate_csv_escape_metadata(metadata)
        with (
            mock.patch("tvtime_extractor.analyze.MAXIMUM_CSV_ESCAPE_ENTRIES", 1),
            self.assertRaisesRegex(UnsupportedSchemaError, "escape-coordinate count"),
        ):
            _validate_csv_escape_metadata(metadata)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "synthetic.csv"
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["value"])
                writer.writeheader()
                writer.writerow({"value": "éé"})
            secure_file(path)
            exact_size = path.stat().st_size
            self.assertEqual(
                read_csv(
                    path,
                    maximum_bytes=exact_size,
                    expected_fields=("value",),
                ),
                [{"value": "éé"}],
            )
            with (
                mock.patch(
                    "tvtime_extractor.report.regular_text_reader",
                    side_effect=AssertionError("oversized CSV was opened"),
                ),
                self.assertRaisesRegex(UnsupportedSchemaError, "CSV file byte size"),
            ):
                read_csv(path, maximum_bytes=exact_size - 1)

    def test_payload_byte_depth_and_node_limits_raise_domain_errors(self) -> None:
        with (
            self.subTest(limit="bytes"),
            mock.patch("tvtime_extractor.analyze.MAXIMUM_CACHE_PAYLOAD_BYTES", 1),
            self.assertRaisesRegex(UnsupportedSchemaError, "single-response byte size"),
        ):
            _parse_cache_json(b"[]")

        with (
            self.subTest(limit="depth"),
            mock.patch("tvtime_extractor.analyze.MAXIMUM_CACHE_JSON_DEPTH", 2),
            self.assertRaisesRegex(UnsupportedSchemaError, "JSON nesting depth"),
        ):
            _validate_cache_json_complexity({"one": {"two": {"three": []}}})

        with (
            self.subTest(limit="nodes"),
            mock.patch("tvtime_extractor.analyze.MAXIMUM_CACHE_JSON_NODES", 3),
            self.assertRaisesRegex(UnsupportedSchemaError, "JSON node count"),
        ):
            _validate_cache_json_complexity({"one": [1, 2, 3]})

        deeply_nested = b'{"data":' * 1_100 + b"null" + b"}" * 1_100
        with self.assertRaisesRegex(UnsupportedSchemaError, "JSON nesting depth"):
            _parse_cache_json(deeply_nested)

    def test_analysis_preflights_aggregate_nodes_and_derived_rows_without_output(self) -> None:
        for patch_name, patch_value, expected_message in (
            ("MAXIMUM_TOTAL_CACHE_JSON_NODES", 1, "combined JSON node count"),
            ("MAXIMUM_DERIVED_ROWS_PER_TABLE", 1, "derived library row count"),
        ):
            with (
                self.subTest(limit=patch_name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                extraction = create_synthetic_extraction(Path(temporary))
                with (
                    mock.patch(f"tvtime_extractor.analyze.{patch_name}", patch_value),
                    self.assertRaisesRegex(UnsupportedSchemaError, expected_message),
                ):
                    analyze_extraction(extraction_directory=extraction)
                self.assertFalse((extraction / "analysis").exists())
                self.assertFalse((extraction / ".analysis-incomplete").exists())

    def test_report_table_limit_fails_before_analysis_is_staged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            analyze_extraction(extraction_directory=extraction)

            with (
                mock.patch("tvtime_extractor.report.MAXIMUM_REPORT_TABLE_ROWS", 0),
                self.assertRaisesRegex(UnsupportedSchemaError, "visual-report row count"),
            ):
                build_report(extraction_directory=extraction)

            self.assertTrue((extraction / "analysis").is_dir())
            self.assertFalse((extraction / ".report-incomplete").exists())

    def test_copy_size_differences_share_the_combined_visual_row_budget(self) -> None:
        summary = {
            "series_library": 1,
            "watched_movies": 0,
            "movie_watchlist": 0,
            "favorite_shows": 0,
            "favorite_movies": 0,
            "episode_cache_unique": 0,
            "watch_events": 0,
        }
        with (
            mock.patch("tvtime_extractor.report.MAXIMUM_REPORT_TABLE_ROWS", 2),
            mock.patch("tvtime_extractor.report.MAXIMUM_TOTAL_REPORT_TABLE_ROWS", 2),
            self.assertRaisesRegex(UnsupportedSchemaError, "combined visual-report row count"),
        ):
            _preflight_report_table_counts(summary, additional_rows=2)

    def test_report_media_growth_is_bounded_by_a_domain_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            analyze_extraction(extraction_directory=extraction)

            with (
                mock.patch("tvtime_extractor.report.MAXIMUM_REPORT_DERIVED_ROWS", 1),
                self.assertRaisesRegex(UnsupportedSchemaError, "media-reference row count"),
            ):
                build_report(extraction_directory=extraction)

            self.assertTrue((extraction / ".report-incomplete").is_dir())

    def test_deep_image_token_fails_with_a_bounded_domain_error(self) -> None:
        nested = b'{"key":"posters/example.jpg","edits":' + b'{"n":' * 1_100
        nested += b"null" + b"}" * 1_100 + b"}"
        token = base64.urlsafe_b64encode(nested).decode("ascii").rstrip("=")
        url = f"https://images.example.invalid/image/raw/{token}"
        with self.assertRaisesRegex(UnsupportedSchemaError, "JSON nesting depth"):
            decode_tvtime_image_url(url)


class CountSemanticsAndWatermarkTests(unittest.TestCase):
    def test_series_count_is_truthfully_labeled_without_collapsing_records(self) -> None:
        production = _visual_model(synthetic_fixture=False)
        self.assertEqual(production.metrics[0].label, "Recovered series records")
        self.assertEqual(production.metrics[0].value, 3)
        self.assertEqual(production.sections[0].title, "Recovered TV series records")
        statistics = {item.label: item.value for item in production.summary_statistics}
        self.assertEqual(
            statistics["Series record title coverage"],
            "2 named; 1 unnamed; 3 total records",
        )
        self.assertEqual(statistics["Distinct named series titles"], "1")

        synthetic = _visual_model(synthetic_fixture=True)
        self.assertEqual(synthetic.metrics[0].label, "Synthetic series records")
        self.assertEqual(synthetic.sections[0].title, "Synthetic series fixture records")

    def test_synthetic_label_covers_text_html_metadata_and_every_pdf_page(self) -> None:
        synthetic = _visual_model(synthetic_fixture=True)
        production = _visual_model(synthetic_fixture=False)

        synthetic_markdown = render_markdown_report(synthetic)
        synthetic_html = render_html_report(synthetic)
        self.assertTrue(synthetic_markdown.startswith(f"# {SYNTHETIC_FIXTURE_NOTICE}\n"))
        self.assertIn(f"<title>{SYNTHETIC_FIXTURE_NOTICE}</title>", synthetic_html)
        self.assertIn(
            f'<meta name="description" content="{SYNTHETIC_FIXTURE_NOTICE}">',
            synthetic_html,
        )
        self.assertIn(f"<h1>{SYNTHETIC_FIXTURE_NOTICE}</h1>", synthetic_html)
        self.assertIn(f'<aside class="privacy">{SYNTHETIC_FIXTURE_NOTICE}</aside>', synthetic_html)
        self.assertNotIn("Every recovered", synthetic_markdown)
        self.assertNotIn("Every recovered", synthetic_html)

        production_markdown = render_markdown_report(production)
        production_html = render_html_report(production)
        self.assertNotIn(SYNTHETIC_FIXTURE_NOTICE, production_markdown)
        self.assertNotIn(SYNTHETIC_FIXTURE_NOTICE, production_html)
        self.assertIn(f'<meta name="description" content="{PRIVATE_NOTICE}">', production_html)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            synthetic_pdf = root / "synthetic.pdf"
            production_pdf = root / "production.pdf"
            write_pdf_report(synthetic, output_path=synthetic_pdf)
            write_pdf_report(production, output_path=production_pdf)

            synthetic_reader = PdfReader(synthetic_pdf)
            self.assertEqual(synthetic_reader.metadata.title, SYNTHETIC_FIXTURE_NOTICE)
            self.assertEqual(
                synthetic_reader.metadata.subject,
                "Synthetic report-layout quality assurance fixture",
            )
            self.assertGreater(synthetic_reader.get_num_pages(), 0)
            for page_number, page in enumerate(synthetic_reader.pages, 1):
                with self.subTest(synthetic_pdf_page=page_number):
                    text = page.extract_text()
                    self.assertIn("SYNTHETIC QA FIXTURE - NOT USER DATA", text)
                    self.assertIn("Synthetic QA fixture - not recovered user data", text)

            production_reader = PdfReader(production_pdf)
            self.assertEqual(production_reader.metadata.title, "TV Time recovered-data report")
            self.assertEqual(production_reader.metadata.subject, "Private recovered TV Time data")
            self.assertGreater(production_reader.get_num_pages(), 0)
            for page_number, page in enumerate(production_reader.pages, 1):
                with self.subTest(production_pdf_page=page_number):
                    text = page.extract_text()
                    self.assertNotIn("SYNTHETIC QA FIXTURE", text)
                    self.assertNotIn("Synthetic QA fixture", text)


if __name__ == "__main__":
    unittest.main()
