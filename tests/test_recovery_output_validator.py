from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    DecodedStreamObject,
    DictionaryObject,
    FloatObject,
    NameObject,
    TextStringObject,
)

from script.validate_recovery_output import (
    PRIVATE_STAGING_PREFIX,
    ValidationFailure,
    _bounded_pdf_decoders,
    _media_rows,
    _pdf_report,
    _semantic_pdf_text,
    _sqlite_snapshot,
    _State,
    _validate_json_complexity,
    validate_recovery_output,
)
from tests.helpers import create_synthetic_extraction, refresh_synthetic_source_snapshot
from tvtime_extractor.analyze import analyze_extraction
from tvtime_extractor.errors import UnsafePathError
from tvtime_extractor.extract import PRIMARY_DOMAIN
from tvtime_extractor.report import build_report
from tvtime_extractor.safety import write_json_private_atomic
from tvtime_extractor.visual_report import HTML_REPORT_FILENAME, PDF_REPORT_FILENAME


def _tree_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    records: list[tuple[object, ...]] = []
    for path in sorted((root, *root.rglob("*")), key=lambda item: item.as_posix()):
        metadata = path.lstat()
        relative = path.relative_to(root).as_posix()
        if path.is_file() and not path.is_symlink():
            records.append(
                (
                    relative,
                    "file",
                    metadata.st_mode,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            )
        else:
            records.append((relative, "directory", metadata.st_mode, metadata.st_mtime_ns))
    return tuple(records)


class RecoveryOutputValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._fixture_temporary = tempfile.TemporaryDirectory()
        cls.fixture = Path(cls._fixture_temporary.name) / "complete-output"
        cls.fixture.mkdir(mode=0o700)
        extraction = create_synthetic_extraction(cls.fixture)
        analyze_extraction(extraction_directory=extraction)
        result = build_report(extraction_directory=extraction)
        if result["pdf_status"] != "generated":
            raise AssertionError("The ASCII validator fixture did not generate its PDF")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._fixture_temporary.cleanup()

    def _copy_fixture(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "candidate-output"
        shutil.copytree(self.fixture, output)
        return output

    def _marker(self, output: Path) -> tuple[Path, dict[str, object]]:
        path = output / "TVTime-Extraction" / "analysis" / "recovery_state.json"
        return path, json.loads(path.read_text(encoding="utf-8"))

    def _reseal_artifact(self, output: Path, artifact_id: str, artifact: Path) -> None:
        marker_path, marker = self._marker(output)
        bindings = marker["artifacts"]
        assert isinstance(bindings, list)
        for binding in bindings:
            if isinstance(binding, dict) and binding.get("id") == artifact_id:
                payload = artifact.read_bytes()
                binding["bytes"] = len(payload)
                binding["sha256"] = hashlib.sha256(payload).hexdigest()
                write_json_private_atomic(marker_path, marker)
                return
        raise AssertionError("Synthetic artifact binding was not found")

    @staticmethod
    def _staging_members(output: Path) -> list[Path]:
        return [path for path in output.iterdir() if path.name.startswith(PRIVATE_STAGING_PREFIX)]

    def test_complete_generated_output_passes_all_gates(self) -> None:
        output = self._copy_fixture()
        before = _tree_snapshot(output)
        result = validate_recovery_output(output)
        self.assertEqual(_tree_snapshot(output), before)
        self.assertEqual(
            result.gates,
            (
                "root_layout",
                "completion_contracts",
                "source_integrity",
                "artifact_bindings",
                "data_parity",
                "visual_reports",
                "pdf_report",
                "final_immutability",
            ),
        )
        self.assertEqual(dict(result.counts)["series_library"], 1)
        self.assertEqual(dict(result.counts)["saved_movies"], 1)

    def test_extra_output_root_member_fails_closed(self) -> None:
        output = self._copy_fixture()
        extra = output / "unexpected.txt"
        extra.write_text("unexpected\n", encoding="utf-8")
        if os.name != "nt":
            extra.chmod(0o600)
        with self.assertRaises(ValidationFailure) as raised:
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "root_layout")

    def test_unknown_completion_marker_key_is_rejected(self) -> None:
        output = self._copy_fixture()
        marker_path, marker = self._marker(output)
        marker["unexpected"] = True
        write_json_private_atomic(marker_path, marker)
        with self.assertRaises(ValidationFailure) as raised:
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "completion_contracts")

    def test_raw_byte_change_is_rejected_before_analysis_is_trusted(self) -> None:
        output = self._copy_fixture()
        database = (
            output / "TVTime-Extraction" / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
        )
        with database.open("ab") as handle:
            handle.write(b"synthetic-tamper")
        with self.assertRaises(ValidationFailure) as raised:
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "source_integrity")

    def test_resealed_series_title_not_derived_from_raw_cache_is_rejected(self) -> None:
        output = self._copy_fixture()
        series = output / "TVTime-Extraction" / "analysis" / "series_library.csv"
        with series.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fields = tuple(reader.fieldnames or ())
            rows = list(reader)
        self.assertTrue(rows)
        rows[0]["name"] = "Synthetic title not present in raw cache"
        with series.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        if os.name != "nt":
            series.chmod(0o600)
        self._reseal_artifact(output, "series_library", series)
        with self.assertRaises(ValidationFailure) as raised:
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "data_parity")

    def test_nonempty_cache_without_supported_payloads_is_rejected(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "unsupported-output"
        output.mkdir(mode=0o700)
        extraction = create_synthetic_extraction(output)
        database = extraction / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
        unsupported = json.dumps(
            {"data": {"type": "unknown", "objects": []}},
            separators=(",", ":"),
        ).encode("utf-8")
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("DELETE FROM cache_dio")
            connection.execute(
                "INSERT INTO cache_dio (key, subKey, content, statusCode) VALUES (?, ?, ?, ?)",
                ("https://api.example.invalid/unsupported", "unsupported", unsupported, 200),
            )
            connection.commit()
        refresh_synthetic_source_snapshot(extraction)
        with mock.patch("tvtime_extractor.analyze._is_supported_payload", return_value=True):
            analyze_extraction(extraction_directory=extraction)
        summary_path = extraction / "analysis" / "analysis_summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["recognized_payloads"] = 0
        write_json_private_atomic(summary_path, summary)
        build_report(extraction_directory=extraction)

        with self.assertRaises(ValidationFailure) as raised:
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "data_parity")

    def test_sqlite_text_cache_payloads_match_analyzer_and_validator_semantics(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "text-affinity-output"
        output.mkdir(mode=0o700)
        extraction = create_synthetic_extraction(output)
        database = extraction / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
        with closing(sqlite3.connect(database)) as connection:
            rows = connection.execute("SELECT rowid, content FROM cache_dio").fetchall()
            self.assertGreater(len(rows), 0)
            for rowid, content in rows:
                self.assertIsInstance(content, bytes)
                try:
                    decoded = content.decode("utf-8")
                except UnicodeDecodeError:
                    connection.execute("DELETE FROM cache_dio WHERE rowid = ?", (rowid,))
                    continue
                connection.execute(
                    "UPDATE cache_dio SET content = ? WHERE rowid = ?",
                    (decoded, rowid),
                )
            connection.commit()
            storage_types = {
                value
                for (value,) in connection.execute("SELECT DISTINCT typeof(content) FROM cache_dio")
            }
            self.assertEqual(storage_types, {"text"})

        refresh_synthetic_source_snapshot(extraction)
        analyze_extraction(extraction_directory=extraction)
        build_report(extraction_directory=extraction)
        result = validate_recovery_output(output)
        self.assertIn("data_parity", result.gates)

    def test_deep_optional_image_token_is_sealed_as_unreadable_and_validates(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "deep-image-output"
        output.mkdir(mode=0o700)
        extraction = create_synthetic_extraction(output)
        image_database = (
            extraction
            / "raw"
            / PRIMARY_DOMAIN
            / "Library"
            / "Application Support"
            / "libCachedImageData.db"
        )
        nested = b'{"key":"posters/example.jpg","edits":' + b'{"n":' * 1_100
        nested += b"null" + b"}" * 1_100 + b"}"
        token = base64.urlsafe_b64encode(nested).decode("ascii").rstrip("=")
        with closing(sqlite3.connect(image_database)) as connection:
            connection.execute(
                "UPDATE cacheObject SET url = ?",
                (f"https://images.example.invalid/image/raw/{token}",),
            )
            connection.commit()

        refresh_synthetic_source_snapshot(extraction)
        analyze_extraction(extraction_directory=extraction)
        report = build_report(extraction_directory=extraction)
        self.assertEqual(report["image_cache_references"], 0)
        markdown = (extraction / "analysis" / "TVTime-Recovered-Data.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("unreadable", markdown)
        result = validate_recovery_output(output)
        self.assertIn("data_parity", result.gates)

    def test_sqlite_snapshot_stays_inside_private_output_and_cleans_up(self) -> None:
        output = self._copy_fixture()
        database = (
            output / "TVTime-Extraction" / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
        )
        state = _State(output_root=output)
        observed: list[Path] = []
        real_connect = sqlite3.connect

        def observe_connect(path: object, *args: object, **kwargs: object):
            candidate = Path(os.fspath(path))
            observed.append(candidate)
            self.assertTrue(candidate.is_relative_to(output))
            self.assertTrue(candidate.parent.name.startswith(PRIVATE_STAGING_PREFIX))
            if os.name != "nt":
                self.assertEqual(candidate.parent.stat().st_mode & 0o777, 0o700)
            return real_connect(path, *args, **kwargs)

        before = _tree_snapshot(output)
        with (
            mock.patch(
                "script.validate_recovery_output.sqlite3.connect",
                side_effect=observe_connect,
            ),
            _sqlite_snapshot(state, database) as connection,
        ):
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
        self.assertTrue(observed)
        self.assertEqual(self._staging_members(output), [])
        self.assertEqual(_tree_snapshot(output), before)

    def test_sqlite_snapshot_exception_cleans_private_staging(self) -> None:
        output = self._copy_fixture()
        database = (
            output / "TVTime-Extraction" / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
        )
        before = _tree_snapshot(output)
        with (
            mock.patch(
                "script.validate_recovery_output.sqlite3.connect",
                side_effect=RuntimeError("synthetic connect failure"),
            ),
            self.assertRaises(RuntimeError),
            _sqlite_snapshot(_State(output_root=output), database),
        ):
            self.fail("Synthetic SQLite connection unexpectedly opened")
        self.assertEqual(self._staging_members(output), [])
        self.assertEqual(_tree_snapshot(output), before)

    @unittest.skipIf(os.name == "nt", "symbolic-link creation varies on Windows")
    def test_sqlite_snapshot_rejects_linked_sidecar_without_traversal(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("Symbolic links are unavailable")
        output = self._copy_fixture()
        database = (
            output / "TVTime-Extraction" / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
        )
        external = output.parent / "outside-private-bytes"
        external.write_bytes(b"synthetic external content")
        if os.name != "nt":
            external.chmod(0o600)
        sidecar = database.with_name(database.name + "-wal")
        sidecar.symlink_to(external)
        before_external = external.read_bytes()
        with (
            self.assertRaises(UnsafePathError),
            _sqlite_snapshot(_State(output_root=output), database),
        ):
            self.fail("Linked sidecar unexpectedly passed")
        self.assertEqual(external.read_bytes(), before_external)
        self.assertEqual(self._staging_members(output), [])

    @unittest.skipIf(os.name == "nt", "POSIX private-mode regression")
    def test_sqlite_snapshot_rejects_nonprivate_source_permissions(self) -> None:
        output = self._copy_fixture()
        database = (
            output / "TVTime-Extraction" / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
        )
        database.chmod(0o644)
        with (
            self.assertRaises(UnsafePathError),
            _sqlite_snapshot(_State(output_root=output), database),
        ):
            self.fail("Nonprivate SQLite source unexpectedly passed")
        self.assertEqual(self._staging_members(output), [])

    def test_rebound_html_change_still_fails_model_parity(self) -> None:
        output = self._copy_fixture()
        html = output / "TVTime-Extraction" / "analysis" / HTML_REPORT_FILENAME
        html.write_text(html.read_text(encoding="utf-8") + "<!-- changed -->", encoding="utf-8")
        if os.name != "nt":
            html.chmod(0o600)
        self._reseal_artifact(output, "html_report", html)
        with self.assertRaises(ValidationFailure) as raised:
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "visual_reports")

    def test_rebound_pdf_action_token_is_rejected(self) -> None:
        output = self._copy_fixture()
        pdf = output / "TVTime-Extraction" / "analysis" / PDF_REPORT_FILENAME
        reader = PdfReader(pdf)
        writer = PdfWriter()
        writer.clone_document_from_reader(reader)
        writer._root_object[NameObject("/OpenAction")] = DictionaryObject(
            {
                NameObject("/S"): NameObject("/JavaScript"),
                NameObject("/JS"): TextStringObject("synthetic unsafe action"),
            }
        )
        with pdf.open("wb") as handle:
            writer.write(handle)
        if os.name != "nt":
            pdf.chmod(0o600)
        self._reseal_artifact(output, "pdf_report", pdf)
        with self.assertRaises(ValidationFailure) as raised:
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "pdf_report")

    def test_rebound_named_link_annotation_is_rejected(self) -> None:
        output = self._copy_fixture()
        pdf = output / "TVTime-Extraction" / "analysis" / PDF_REPORT_FILENAME
        reader = PdfReader(pdf)
        writer = PdfWriter()
        writer.clone_document_from_reader(reader)
        annotation = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Annot"),
                NameObject("/Subtype"): NameObject("/Link"),
                NameObject("/Rect"): ArrayObject(
                    [FloatObject(0), FloatObject(0), FloatObject(20), FloatObject(20)]
                ),
                NameObject("/A"): DictionaryObject(
                    {
                        NameObject("/S"): NameObject("/Named"),
                        NameObject("/N"): NameObject("/NextPage"),
                    }
                ),
            }
        )
        writer.pages[0][NameObject("/Annots")] = ArrayObject([writer._add_object(annotation)])
        with pdf.open("wb") as handle:
            writer.write(handle)
        if os.name != "nt":
            pdf.chmod(0o600)
        self._reseal_artifact(output, "pdf_report", pdf)
        with self.assertRaises(ValidationFailure) as raised:
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "pdf_report")

    def test_resealed_full_page_white_overlay_is_rejected(self) -> None:
        output = self._copy_fixture()
        pdf = output / "TVTime-Extraction" / "analysis" / PDF_REPORT_FILENAME
        reader = PdfReader(pdf)
        original_page_text = reader.pages[0].extract_text()
        writer = PdfWriter()
        writer.clone_document_from_reader(reader)
        page = writer.pages[0]
        overlay = DecodedStreamObject()
        overlay.set_data(
            (
                "q\n1 1 1 rg\n"
                f"0 0 {float(page.mediabox.width)} {float(page.mediabox.height)} re\n"
                "f\nQ\n"
            ).encode("ascii")
        )
        overlay_reference = writer._add_object(overlay)
        contents = page.get("/Contents")
        if isinstance(contents, ArrayObject):
            contents.append(overlay_reference)
        else:
            page[NameObject("/Contents")] = ArrayObject([contents, overlay_reference])
        with pdf.open("wb") as handle:
            writer.write(handle)
        if os.name != "nt":
            pdf.chmod(0o600)
        self.assertEqual(PdfReader(pdf).pages[0].extract_text(), original_page_text)
        self._reseal_artifact(output, "pdf_report", pdf)
        with self.assertRaises(ValidationFailure) as raised:
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "pdf_report")

    def test_generated_pdf_contains_no_annotations(self) -> None:
        pdf = self.fixture / "TVTime-Extraction" / "analysis" / PDF_REPORT_FILENAME
        reader = PdfReader(pdf, strict=True)
        self.assertTrue(reader.pages)
        self.assertTrue(all("/Annots" not in page for page in reader.pages))

    def test_pdf_outline_order_must_exactly_match_report_sections(self) -> None:
        output = self._copy_fixture()
        with (
            mock.patch(
                "script.validate_recovery_output._outline_titles",
                return_value=["Aggregate media statistics", "Recovery summary"],
            ),
            self.assertRaises(ValidationFailure) as raised,
        ):
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "pdf_report")

    def test_pdf_text_normalization_preserves_word_boundaries(self) -> None:
        self.assertNotEqual(
            _semantic_pdf_text("Synthetic Movie"),
            _semantic_pdf_text("SyntheticMovie"),
        )
        self.assertEqual(
            _semantic_pdf_text("Synthetic\n\tMovie"),
            _semantic_pdf_text("Synthetic Movie"),
        )

    def test_pypdf_decompression_limits_are_bounded_and_restored(self) -> None:
        from pypdf import filters

        original = filters.ZLIB_MAX_OUTPUT_LENGTH
        with (
            mock.patch(
                "script.validate_recovery_output.MAXIMUM_PDF_DECOMPRESSED_BYTES",
                1_024,
            ),
            _bounded_pdf_decoders(),
        ):
            self.assertEqual(filters.ZLIB_MAX_OUTPUT_LENGTH, 1_024)
        self.assertEqual(filters.ZLIB_MAX_OUTPUT_LENGTH, original)

    def test_generated_pdf_fails_closed_without_semantic_reader(self) -> None:
        output = self._copy_fixture()
        with (
            mock.patch("script.validate_recovery_output._pdf_reader", return_value=None),
            self.assertRaises(ValidationFailure) as raised,
        ):
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "pdf_report")

    def test_csv_byte_bound_fails_before_unbounded_parsing(self) -> None:
        output = self._copy_fixture()
        with (
            mock.patch("script.validate_recovery_output.MAXIMUM_INVENTORY_BYTES", 32),
            self.assertRaises(ValidationFailure) as raised,
        ):
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "source_integrity")

    def test_sqlite_row_bound_fails_closed(self) -> None:
        output = self._copy_fixture()
        with (
            mock.patch("script.validate_recovery_output.MAXIMUM_SQLITE_ROWS", 0),
            self.assertRaises(ValidationFailure) as raised,
        ):
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "data_parity")

    def test_pdf_byte_bound_fails_before_semantic_parsing(self) -> None:
        output = self._copy_fixture()
        with (
            mock.patch("script.validate_recovery_output.MAXIMUM_PDF_BYTES", 32),
            self.assertRaises(ValidationFailure) as raised,
        ):
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "pdf_report")

    def test_json_object_depth_is_bounded(self) -> None:
        with (
            mock.patch("script.validate_recovery_output.MAXIMUM_JSON_DEPTH", 2),
            self.assertRaises(ValueError),
        ):
            _validate_json_complexity({"one": {"two": {"three": True}}})

    def test_json_string_limit_counts_multibyte_utf8_at_exact_boundary(self) -> None:
        with mock.patch("script.validate_recovery_output.MAXIMUM_JSON_STRING_BYTES", 4):
            _validate_json_complexity({"éé": ""})
            with self.assertRaises(ValueError):
                _validate_json_complexity({"ééa": ""})

    def test_media_collectors_share_one_cross_payload_budget(self) -> None:
        payload = {
            "trailers": [
                {
                    "name": "Synthetic trailer",
                    "url": "https://media.example.invalid/trailer",
                }
            ]
        }
        with mock.patch("script.validate_recovery_output.MAXIMUM_REPORT_DERIVED_ROWS", 2):
            trailers, media = _media_rows([payload])
            self.assertEqual(len(trailers), 1)
            self.assertEqual(len(media), 1)
        with (
            mock.patch("script.validate_recovery_output.MAXIMUM_REPORT_DERIVED_ROWS", 1),
            self.assertRaises(ValueError),
        ):
            _media_rows([payload])

    def test_combined_cache_json_node_budget_is_enforced(self) -> None:
        output = self._copy_fixture()
        with (
            mock.patch("script.validate_recovery_output.MAXIMUM_TOTAL_CACHE_JSON_NODES", 1),
            self.assertRaises(ValidationFailure) as raised,
        ):
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "data_parity")

    def test_sqlite_combined_snapshot_bound_fails_before_staging_copy(self) -> None:
        output = self._copy_fixture()
        database = (
            output / "TVTime-Extraction" / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
        )
        before = _tree_snapshot(output)
        with (
            mock.patch(
                "script.validate_recovery_output.MAXIMUM_SQLITE_SNAPSHOT_TOTAL_BYTES",
                database.stat().st_size - 1,
            ),
            self.assertRaises(ValueError),
            _sqlite_snapshot(_State(output_root=output), database),
        ):
            self.fail("Oversized SQLite snapshot unexpectedly opened")
        self.assertEqual(_tree_snapshot(output), before)

    def test_domains_file_is_rechecked_at_final_immutability(self) -> None:
        output = self._copy_fixture()

        def validate_pdf_then_tamper(state: _State) -> None:
            _pdf_report(state)
            domains = state.metadata / "domains.txt"
            domains.write_text("synthetic changed domain\n", encoding="utf-8")
            if os.name != "nt":
                domains.chmod(0o600)

        with (
            mock.patch(
                "script.validate_recovery_output._pdf_report",
                side_effect=validate_pdf_then_tamper,
            ),
            self.assertRaises(ValidationFailure) as raised,
        ):
            validate_recovery_output(output)
        self.assertEqual(raised.exception.gate, "final_immutability")

    def test_stdin_cli_emits_only_gates_and_aggregate_counts(self) -> None:
        output = self._copy_fixture()
        completed = subprocess.run(
            [sys_executable(), "script/validate_recovery_output.py"],
            input=(str(output) + "\n").encode("utf-8"),
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        text = completed.stdout.decode("utf-8")
        self.assertNotIn(str(output), text)
        self.assertNotIn("Example Movie", text)
        self.assertIsNone(re.search(r"\b[0-9a-f]{64}\b", text))
        self.assertIsNone(
            re.search(
                r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                text,
            )
        )
        self.assertTrue(
            all(line.startswith(("GATE ", "COUNT ", "RESULT ")) for line in text.splitlines())
        )

        rejected = subprocess.run(
            [sys_executable(), "script/validate_recovery_output.py", str(output)],
            input=b"",
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(
            rejected.stdout.decode("utf-8").splitlines(),
            ["GATE input FAIL", "RESULT FAIL"],
        )
        self.assertEqual(rejected.stderr, b"")

    def test_legitimate_fidelity_omission_passes(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "omitted-output"
        output.mkdir(mode=0o700)
        extraction = create_synthetic_extraction(output)
        database = extraction / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
        with closing(sqlite3.connect(database)) as connection:
            key, subkey, encoded = connection.execute(
                "SELECT key, subKey, content FROM cache_dio WHERE subKey = 'library' LIMIT 1"
            ).fetchone()
            payload = json.loads(encoded)
            payload["data"]["objects"][0]["meta"]["name"] = "Arabic \u0645\u062b\u0627\u0644"
            connection.execute(
                "UPDATE cache_dio SET content = ? WHERE key = ? AND subKey = ?",
                (json.dumps(payload, separators=(",", ":")).encode("utf-8"), key, subkey),
            )
            connection.commit()
        refresh_synthetic_source_snapshot(extraction)
        analyze_extraction(extraction_directory=extraction)
        report = build_report(extraction_directory=extraction)
        self.assertEqual(report["pdf_status"], "omitted")
        self.assertFalse((extraction / "analysis" / PDF_REPORT_FILENAME).exists())
        result = validate_recovery_output(output)
        self.assertIn("pdf_report", result.gates)


def sys_executable() -> str:
    import sys

    return sys.executable


if __name__ == "__main__":
    unittest.main()
