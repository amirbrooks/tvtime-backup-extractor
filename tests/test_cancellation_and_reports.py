from __future__ import annotations

import hashlib
import html
import json
import os
import re
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

from pypdf import PdfReader

from tests.helpers import (
    create_synthetic_extraction,
    read_csv_rows,
    refresh_synthetic_source_snapshot,
)
from tvtime_extractor.analyze import analyze_extraction
from tvtime_extractor.errors import (
    OutputExistsError,
    PartialExtractionError,
    RecoveryCancelled,
    TVTimeError,
    UnsafePathError,
)
from tvtime_extractor.extract import PRIMARY_DOMAIN
from tvtime_extractor.integrity import reconcile_raw_tree
from tvtime_extractor.models import CancellationToken
from tvtime_extractor.report import build_report, read_csv
from tvtime_extractor.safety import (
    promote_directory_no_replace_atomic as promote_directory_no_replace_atomic_real,
)
from tvtime_extractor.safety import (
    write_bytes_private,
    write_csv_private,
    write_text_private,
)
from tvtime_extractor.safety import (
    write_json_private_atomic as write_real_json_private_atomic,
)
from tvtime_extractor.visual_report import (
    HTML_REPORT_FILENAME,
    PDF_FIDELITY_WARNING,
    PDF_REPORT_FILENAME,
)
from tvtime_extractor.visual_report import (
    write_visual_reports as write_real_visual_reports,
)


def _minimal_visual_reports(
    _model: object,
    *,
    analysis_directory: Path,
    cancellation_check: object = None,
) -> dict[str, str]:
    if callable(cancellation_check):
        cancellation_check()
    html_path = analysis_directory / HTML_REPORT_FILENAME
    pdf_path = analysis_directory / PDF_REPORT_FILENAME
    write_text_private(html_path, "<!doctype html><title>Synthetic</title>")
    write_bytes_private(pdf_path, b"%PDF-synthetic")
    return {
        "visual_report": str(html_path),
        "pdf_report": str(pdf_path),
        "pdf_status": "generated",
        "pdf_warning": "",
    }


def _rewrite_library_names(extraction: Path, replacements: dict[str, str]) -> None:
    cache = extraction / "raw" / "AppDomain-com.tozelabs.tvshowtime" / "Documents" / "DioCache.db"
    with closing(sqlite3.connect(cache)) as connection:
        records = list(connection.execute("SELECT rowid, content FROM cache_dio"))
        for rowid, encoded in records:
            try:
                payload = json.loads(bytes(encoded))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            data = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(data, dict) and data.get("id") == "library":
                for item in data.get("objects") or []:
                    if not isinstance(item, dict):
                        continue
                    entity = str(item.get("entity_type") or "")
                    watched = bool(item.get("watched_at"))
                    key = "series" if entity == "series" else ("watched" if watched else "saved")
                    meta = item.get("meta")
                    if isinstance(meta, dict) and key in replacements:
                        meta["name"] = replacements[key]
            elif isinstance(data, dict) and data.get("id") == "favorite-movies":
                for item in data.get("objects") or []:
                    if isinstance(item, dict) and "favorite_movie" in replacements:
                        item["name"] = replacements["favorite_movie"]
            elif isinstance(data, dict) and data.get("id") == "favorite-series":
                for item in data.get("objects") or []:
                    if isinstance(item, dict) and "favorite_series" in replacements:
                        item["name"] = replacements["favorite_series"]
            elif isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    show = item.get("show")
                    if isinstance(show, dict) and "episode_show" in replacements:
                        show["name"] = replacements["episode_show"]
                    if "episode_name" in replacements:
                        item["name"] = replacements["episode_name"]
            connection.execute(
                "UPDATE cache_dio SET content = ? WHERE rowid = ?",
                (json.dumps(payload, separators=(",", ":")).encode(), rowid),
            )
        connection.commit()
    refresh_synthetic_source_snapshot(extraction)


class _HTMLReportNames(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.section_names: dict[str, list[str]] = {}
        self._section = ""
        self._capturing_name = False
        self._name_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "section":
            self._section = str(attributes.get("id") or "")
        if tag == "td" and "name" in str(attributes.get("class") or "").split():
            self._capturing_name = True
            self._name_parts = []

    def handle_data(self, data: str) -> None:
        if self._capturing_name:
            self._name_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "td" and self._capturing_name:
            self.section_names.setdefault(self._section, []).append(
                "".join(self._name_parts).strip()
            )
            self._capturing_name = False
            self._name_parts = []
        elif tag == "section":
            self._section = ""


def _markdown_sections(value: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current = ""
    for line in value.splitlines():
        if line.startswith("## "):
            current = line[3:]
            sections.setdefault(current, [])
        elif current:
            sections[current].append(line)
    return {title: "\n".join(lines) for title, lines in sections.items()}


def _pdf_text(path: Path) -> str:
    return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)


def _without_layout_whitespace(value: str) -> str:
    """Ignore only whitespace inserted by PDF table wrapping and page layout."""

    return re.sub(r"\s+", "", value)


class CancellationCommitTests(unittest.TestCase):
    def _analysis(self, base: Path) -> Path:
        extraction = create_synthetic_extraction(base)
        analyze_extraction(extraction_directory=extraction)
        return extraction

    def test_cancel_before_commit_keeps_staging_and_promotes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = self._analysis(Path(temporary))
            token = CancellationToken()

            def cancel_then_seal() -> bool:
                token.cancel()
                return token.seal_for_commit()

            with (
                mock.patch(
                    "tvtime_extractor.report.write_visual_reports",
                    side_effect=_minimal_visual_reports,
                ),
                self.assertRaises(RecoveryCancelled),
            ):
                build_report(
                    extraction_directory=extraction,
                    cancellation_check=token.raise_if_cancelled,
                    commit_seal=cancel_then_seal,
                )

            self.assertFalse((extraction / "analysis").exists())
            staging = extraction / ".report-incomplete"
            self.assertTrue(staging.is_dir())
            self.assertEqual(
                json.loads((staging / "recovery_state.json").read_text())["status"],
                "complete",
            )

    def test_cancel_after_seal_is_ignored_and_success_is_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = self._analysis(Path(temporary))
            token = CancellationToken()
            cancellation_results: list[bool] = []

            def seal_then_cancel() -> bool:
                sealed = token.seal_for_commit()
                cancellation_results.append(token.cancel())
                return sealed

            with mock.patch(
                "tvtime_extractor.report.write_visual_reports",
                side_effect=_minimal_visual_reports,
            ):
                result = build_report(
                    extraction_directory=extraction,
                    cancellation_check=token.raise_if_cancelled,
                    commit_seal=seal_then_cancel,
                )

            self.assertEqual(cancellation_results, [False])
            self.assertTrue(token.try_finish())
            self.assertTrue(Path(result["report"]).is_file())
            self.assertTrue((extraction / "analysis" / "recovery_state.json").is_file())
            self.assertFalse((extraction / ".report-incomplete").exists())

    def test_cancel_during_final_raw_reconciliation_wins_before_commit_seal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = self._analysis(Path(temporary))
            token = CancellationToken()
            reconciliation_calls = 0
            seal_calls = 0

            def cancel_during_final_reconciliation(*args: object, **kwargs: object):
                nonlocal reconciliation_calls
                reconciliation_calls += 1
                if reconciliation_calls == 2:
                    token.cancel()
                return reconcile_raw_tree(*args, **kwargs)

            def seal() -> bool:
                nonlocal seal_calls
                seal_calls += 1
                return token.seal_for_commit()

            with (
                mock.patch(
                    "tvtime_extractor.report.write_visual_reports",
                    side_effect=_minimal_visual_reports,
                ),
                mock.patch(
                    "tvtime_extractor.report.reconcile_raw_tree",
                    side_effect=cancel_during_final_reconciliation,
                ),
                self.assertRaises(RecoveryCancelled),
            ):
                build_report(
                    extraction_directory=extraction,
                    cancellation_check=token.raise_if_cancelled,
                    commit_seal=seal,
                )

            self.assertEqual(reconciliation_calls, 2)
            self.assertEqual(seal_calls, 0)
            self.assertFalse((extraction / "analysis").exists())
            self.assertTrue((extraction / ".report-incomplete").is_dir())

    def test_cancel_during_final_artifact_binding_wins_before_commit_seal(self) -> None:
        from tvtime_extractor.report import _private_artifact_binding

        with tempfile.TemporaryDirectory() as temporary:
            extraction = self._analysis(Path(temporary))
            token = CancellationToken()
            bound_artifact_ids: set[str] = set()
            seal_calls = 0

            def cancel_when_binding_repeats(
                path: Path,
                *,
                artifact_id: str,
                relative_path: str,
                cancellation_check: object = None,
            ):
                if artifact_id in bound_artifact_ids:
                    token.cancel()
                bound_artifact_ids.add(artifact_id)
                return _private_artifact_binding(
                    path,
                    artifact_id=artifact_id,
                    relative_path=relative_path,
                    cancellation_check=cancellation_check if callable(cancellation_check) else None,
                )

            def seal() -> bool:
                nonlocal seal_calls
                seal_calls += 1
                return token.seal_for_commit()

            with (
                mock.patch(
                    "tvtime_extractor.report.write_visual_reports",
                    side_effect=_minimal_visual_reports,
                ),
                mock.patch(
                    "tvtime_extractor.report._private_artifact_binding",
                    side_effect=cancel_when_binding_repeats,
                ),
                self.assertRaises(RecoveryCancelled),
            ):
                build_report(
                    extraction_directory=extraction,
                    cancellation_check=token.raise_if_cancelled,
                    commit_seal=seal,
                )

            self.assertEqual(seal_calls, 0)
            self.assertFalse((extraction / "analysis").exists())
            self.assertTrue((extraction / ".report-incomplete").is_dir())

    def test_raced_final_directory_is_never_replaced_during_report_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = self._analysis(Path(temporary))
            promotion_calls = 0
            raced_identity: tuple[int, int] | None = None

            def create_destination_before_final_promotion(
                source: Path,
                destination: Path,
                *,
                durable: bool = False,
            ) -> None:
                nonlocal promotion_calls, raced_identity
                promotion_calls += 1
                if promotion_calls == 2:
                    destination.mkdir(mode=0o700)
                    metadata = destination.stat()
                    raced_identity = (metadata.st_dev, metadata.st_ino)
                promote_directory_no_replace_atomic_real(
                    source,
                    destination,
                    durable=durable,
                )

            with (
                mock.patch(
                    "tvtime_extractor.report.write_visual_reports",
                    side_effect=_minimal_visual_reports,
                ),
                mock.patch(
                    "tvtime_extractor.report.promote_directory_no_replace_atomic",
                    side_effect=create_destination_before_final_promotion,
                ),
                self.assertRaises(OutputExistsError),
            ):
                build_report(extraction_directory=extraction)

            self.assertEqual(promotion_calls, 2)
            self.assertIsNotNone(raced_identity)
            self.assertEqual(
                ((extraction / "analysis").stat().st_dev, (extraction / "analysis").stat().st_ino),
                raced_identity,
            )
            self.assertTrue((extraction / ".report-incomplete").is_dir())

    def test_signal_pending_flag_is_lock_free_and_wins_before_commit_seal(self) -> None:
        token = CancellationToken()
        with token._lock:  # prove the signal-safe setter does not reacquire this lock
            token.mark_signal_pending()
        self.assertFalse(token.seal_for_commit())
        with self.assertRaises(RecoveryCancelled):
            token.raise_if_cancelled()


class AnalysisPromotionTests(unittest.TestCase):
    def test_raced_final_directory_is_never_replaced_during_analysis_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            raced_identity: tuple[int, int] | None = None

            def create_destination_before_promotion(
                source: Path,
                destination: Path,
                *,
                durable: bool = False,
            ) -> None:
                nonlocal raced_identity
                destination.mkdir(mode=0o700)
                metadata = destination.stat()
                raced_identity = (metadata.st_dev, metadata.st_ino)
                promote_directory_no_replace_atomic_real(
                    source,
                    destination,
                    durable=durable,
                )

            with (
                mock.patch(
                    "tvtime_extractor.analyze.promote_directory_no_replace_atomic",
                    side_effect=create_destination_before_promotion,
                ),
                self.assertRaises(OutputExistsError),
            ):
                analyze_extraction(extraction_directory=extraction)

            self.assertIsNotNone(raced_identity)
            self.assertEqual(
                ((extraction / "analysis").stat().st_dev, (extraction / "analysis").stat().st_ino),
                raced_identity,
            )
            self.assertTrue((extraction / ".analysis-incomplete").is_dir())


class ReportInputSecurityTests(unittest.TestCase):
    def test_report_rejects_unknown_and_duplicate_contract_fields_before_staging(self) -> None:
        def analysis_top(extraction: Path) -> None:
            path = extraction / "analysis" / "analysis_summary.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["unexpected_private_field"] = "must not be preserved"
            write_real_json_private_atomic(path, value)

        def analysis_nested(extraction: Path) -> None:
            path = extraction / "analysis" / "analysis_summary.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["csv_spreadsheet_escaped_cells"] = {
                "series_library.csv": [{"row": 1, "field": "name", "unexpected": True}]
            }
            write_real_json_private_atomic(path, value)

        def extraction_top(extraction: Path) -> None:
            path = extraction / "metadata" / "summary.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["unexpected_private_field"] = True
            write_real_json_private_atomic(path, value)

        def extraction_nested(extraction: Path) -> None:
            path = extraction / "metadata" / "summary.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["size_discrepancies"] = [
                {
                    "domain": "AppDomain-com.tozelabs.tvshowtime",
                    "relative_path": "Documents/example",
                    "declared_size": 2,
                    "actual_size": 1,
                    "unexpected": True,
                }
            ]
            write_real_json_private_atomic(path, value)

        def run_state_top(extraction: Path) -> None:
            path = extraction / "metadata" / "run_state.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["unexpected_private_field"] = True
            write_real_json_private_atomic(path, value)

        def run_state_nested(extraction: Path) -> None:
            path = extraction / "metadata" / "run_state.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["source_snapshot"]["inventory"]["unexpected"] = True
            write_real_json_private_atomic(path, value)

        def timestamp_mismatch(extraction: Path) -> None:
            path = extraction / "metadata" / "summary.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["completed_utc"] = "2020-01-01T00:00:00+00:00"
            write_real_json_private_atomic(path, value)

        def impossible_episode_counts(extraction: Path) -> None:
            path = extraction / "analysis" / "analysis_summary.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["episode_cache_unique"] = value["episode_cache_rows"] + 1
            write_real_json_private_atomic(path, value)

        def coherent_wrong_inventory_total(extraction: Path) -> None:
            summary_path = extraction / "metadata" / "summary.json"
            run_path = extraction / "metadata" / "run_state.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            run_state = json.loads(run_path.read_text(encoding="utf-8"))
            summary["bytes_extracted"] += 1
            run_state["bytes_extracted"] += 1
            write_real_json_private_atomic(summary_path, summary)
            write_real_json_private_atomic(run_path, run_state)

        def coherent_fake_discrepancy(extraction: Path) -> None:
            summary_path = extraction / "metadata" / "summary.json"
            run_path = extraction / "metadata" / "run_state.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            run_state = json.loads(run_path.read_text(encoding="utf-8"))
            summary["size_discrepancies"] = [
                {
                    "domain": "AppDomain-com.tozelabs.tvshowtime",
                    "relative_path": "Documents/example",
                    "declared_size": 2,
                    "actual_size": 1,
                }
            ]
            run_state["size_discrepancy_count"] = 1
            write_real_json_private_atomic(summary_path, summary)
            write_real_json_private_atomic(run_path, run_state)

        def mismatched_domains_file(extraction: Path) -> None:
            write_text_private(
                extraction / "metadata" / "domains.txt",
                "AppDomainPlugin-com.tozelabs.tvshowtime.synthetic\n"
                "AppDomain-com.tozelabs.tvshowtime\n",
            )

        def duplicate_analysis_field(extraction: Path) -> None:
            path = extraction / "analysis" / "analysis_summary.json"
            payload = path.read_bytes()
            path.write_bytes(b'{"dio_cache_quick_check":"duplicate",' + payload[1:])
            if os.name != "nt":
                path.chmod(0o600)

        cases = {
            "analysis top-level": analysis_top,
            "analysis nested": analysis_nested,
            "extraction top-level": extraction_top,
            "extraction nested": extraction_nested,
            "run-state top-level": run_state_top,
            "run-state nested": run_state_nested,
            "timestamp mismatch": timestamp_mismatch,
            "impossible episode counts": impossible_episode_counts,
            "coherent wrong inventory total": coherent_wrong_inventory_total,
            "coherent fake discrepancy": coherent_fake_discrepancy,
            "mismatched domains file": mismatched_domains_file,
            "duplicate analysis field": duplicate_analysis_field,
        }
        for label, mutate in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                extraction = create_synthetic_extraction(Path(temporary))
                analyze_extraction(extraction_directory=extraction)
                mutate(extraction)
                with self.assertRaises(TVTimeError):
                    build_report(extraction_directory=extraction)
                self.assertTrue((extraction / "analysis").is_dir())
                self.assertFalse((extraction / ".report-incomplete").exists())
                self.assertFalse((extraction / "analysis" / "recovery_state.json").exists())

    @unittest.skipIf(os.name == "nt", "symbolic-link creation varies on Windows")
    def test_every_required_analysis_csv_is_rejected_before_staging_if_linked(self) -> None:
        filenames = (
            "cache_index.csv",
            "movie_library.csv",
            "watch_events.csv",
            "episode_cache.csv",
            "sqlite_integrity.csv",
            "plist_key_inventory.csv",
            "series_library.csv",
            "watched_movies.csv",
            "movie_watchlist.csv",
            "favorite_shows.csv",
            "favorite_movies.csv",
            "episode_cache_unique.csv",
            "watch_events_named.csv",
        )
        for filename in filenames:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                extraction = create_synthetic_extraction(Path(temporary))
                analyze_extraction(extraction_directory=extraction)
                target = extraction / "analysis" / filename
                external = extraction / f"external-{filename}"
                shutil.copyfile(target, external)
                target.unlink()
                target.symlink_to(external)
                with self.assertRaises(UnsafePathError):
                    build_report(extraction_directory=extraction)
                self.assertTrue((extraction / "analysis").is_dir())
                self.assertFalse((extraction / ".report-incomplete").exists())

    @unittest.skipIf(os.name == "nt", "symbolic-link creation varies on Windows")
    def test_inventory_csv_is_also_opened_without_following_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            analyze_extraction(extraction_directory=extraction)
            inventory = extraction / "metadata" / "inventory.csv"
            external = extraction / "external-inventory.csv"
            shutil.copyfile(inventory, external)
            inventory.unlink()
            inventory.symlink_to(external)
            with self.assertRaises(UnsafePathError) as raised:
                build_report(extraction_directory=extraction)
            self.assertEqual(
                str(raised.exception),
                "The private extraction inventory path was unsafe.",
            )
            self.assertNotIn(str(Path(temporary)), str(raised.exception))


class CompletionContractTests(unittest.TestCase):
    def test_v02_completion_marker_binds_exact_private_artifacts_and_aggregates(self) -> None:
        expected_ids = [
            "extraction_run_state",
            "extraction_inventory",
            "extraction_summary",
            "extraction_domains",
            "analysis_summary",
            "cache_index",
            "movie_library",
            "watch_events",
            "episode_cache",
            "sqlite_integrity",
            "plist_key_inventory",
            "series_library",
            "watched_movies",
            "movie_watchlist",
            "favorite_shows",
            "favorite_movies",
            "episode_cache_unique",
            "watch_events_named",
            "trailer_references",
            "media_url_inventory",
            "image_cache_references",
            "markdown_report",
            "html_report",
            "pdf_report",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            analysis_result = analyze_extraction(extraction_directory=extraction)
            with mock.patch(
                "tvtime_extractor.report.write_visual_reports",
                side_effect=_minimal_visual_reports,
            ):
                report_result = build_report(extraction_directory=extraction)

            marker_path = extraction / "analysis" / "recovery_state.json"
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            self.assertLessEqual(marker_path.stat().st_size, 64 * 1024)
            if os.name != "nt":
                self.assertEqual(marker_path.stat().st_mode & 0o077, 0)
            self.assertEqual(marker["schema_version"], 2)
            self.assertEqual(marker["contract"], "tvtime-recovery-state-v0.2")
            self.assertEqual(marker["status"], "complete")
            self.assertEqual(marker["pdf"], {"status": "generated", "artifact_id": "pdf_report"})
            self.assertEqual([item["id"] for item in marker["artifacts"]], expected_ids)

            for binding in marker["artifacts"]:
                with self.subTest(artifact=binding["id"]):
                    relative = Path(binding["relative_path"])
                    self.assertFalse(relative.is_absolute())
                    self.assertNotIn("..", relative.parts)
                    artifact = extraction / relative
                    payload = artifact.read_bytes()
                    self.assertGreater(len(payload), 0)
                    self.assertEqual(binding["bytes"], len(payload))
                    self.assertEqual(binding["sha256"], hashlib.sha256(payload).hexdigest())

            aggregates = marker["aggregates"]
            self.assertEqual(
                aggregates["analysis"]["series_library"], analysis_result["series_library"]
            )
            self.assertEqual(
                aggregates["analysis"]["watch_events_with_titles"],
                analysis_result["watch_events_with_titles"],
            )
            self.assertEqual(
                aggregates["report"]["media_urls"],
                report_result["media_urls"],
            )
            run_state = json.loads(
                (extraction / "metadata" / "run_state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(run_state["schema_version"], 2)
            self.assertEqual(run_state["contract"], "tvtime-extraction-run-state-v0.2")
            self.assertEqual(run_state["status"], "complete")
            self.assertEqual(run_state["files_expected"], run_state["files_extracted"])
            self.assertEqual(marker["source_snapshot"], run_state["source_snapshot"])
            self.assertEqual(
                marker["source_snapshot"]["inventory"]["sha256"],
                hashlib.sha256(
                    (extraction / "metadata" / "inventory.csv").read_bytes()
                ).hexdigest(),
            )
            self.assertEqual(
                marker["source_snapshot"]["raw_tree"]["files"],
                run_state["files_extracted"],
            )
            self.assertEqual(
                marker["source_snapshot"]["raw_tree"]["bytes"],
                run_state["bytes_extracted"],
            )
            analysis_state = json.loads(
                (extraction / "analysis" / "analysis_summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(analysis_state["schema_version"], 2)
            self.assertEqual(analysis_state["contract"], "tvtime-analysis-summary-v0.2")
            self.assertEqual(analysis_state["status"], "complete")

    def test_completion_marker_exact_byte_mutation_stops_before_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            analyze_extraction(extraction_directory=extraction)

            def write_then_mutate(path: Path, value: object, **kwargs: object) -> None:
                write_real_json_private_atomic(path, value, **kwargs)
                if path.name == "recovery_state.json":
                    payload = path.read_bytes()
                    path.write_bytes(
                        payload.replace(b'"status": "complete"', b'"status": "changed"')
                    )

            with (
                mock.patch(
                    "tvtime_extractor.report.write_visual_reports",
                    side_effect=_minimal_visual_reports,
                ),
                mock.patch(
                    "tvtime_extractor.report.write_json_private_atomic",
                    side_effect=write_then_mutate,
                ),
                self.assertRaisesRegex(TVTimeError, "exact serialized bytes"),
            ):
                build_report(extraction_directory=extraction)

            self.assertFalse((extraction / "analysis").exists())
            self.assertTrue((extraction / ".report-incomplete").is_dir())

    def test_legacy_extraction_marker_is_not_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            (extraction / "metadata" / "run_state.json").write_text(
                '{"status":"complete"}\n',
                encoding="utf-8",
            )
            if os.name != "nt":
                (extraction / "metadata" / "run_state.json").chmod(0o600)
            with self.assertRaises(PartialExtractionError):
                analyze_extraction(extraction_directory=extraction)


class VisualParityAndFidelityTests(unittest.TestCase):
    def test_reversible_csv_names_are_exact_in_markdown_html_and_pdf(self) -> None:
        recovered_names = {
            "series": "=L\u2019été… exact series",
            "watched": "+Exact watched movie",
            "saved": "'=Genuine  apostrophe movie",
            "favorite_series": "Favorite series token",
            "favorite_movie": "Favorite movie token",
            "episode_show": "Episode series token",
            "episode_name": "Episode title token",
        }
        display_names = {
            **recovered_names,
            "saved": "'=Genuine apostrophe movie",
        }
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            _rewrite_library_names(extraction, recovered_names)
            summary = analyze_extraction(extraction_directory=extraction)
            escaped = summary["csv_spreadsheet_escaped_cells"]
            self.assertIn("series_library.csv", escaped)
            self.assertIn("watched_movies.csv", escaped)
            self.assertNotIn(
                "movie_watchlist.csv",
                escaped,
                "a genuine leading apostrophe must not be guessed or stripped",
            )

            captured_models: list[object] = []

            def capture_model(model: object, **kwargs: object) -> dict[str, str]:
                captured_models.append(model)
                return write_real_visual_reports(model, **kwargs)

            with mock.patch(
                "tvtime_extractor.report.write_visual_reports",
                side_effect=capture_model,
            ):
                result = build_report(extraction_directory=extraction)
            analysis = extraction / "analysis"
            markdown = (analysis / "TVTime-Recovered-Data.md").read_text(encoding="utf-8")
            offline_html = html.unescape(
                (analysis / HTML_REPORT_FILENAME).read_text(encoding="utf-8")
            )
            markdown_sections = _markdown_sections(markdown)
            html_names = _HTMLReportNames()
            html_names.feed((analysis / HTML_REPORT_FILENAME).read_text(encoding="utf-8"))
            model_sections = {
                section.identifier: [row.name for row in section.rows]
                for section in captured_models[0].sections
            }

            expected_sections = {
                "series-library": ("Recovered TV series records", [display_names["series"]]),
                "watched-movies": ("Watched movies", [display_names["watched"]]),
                "saved-movies": ("Saved movie watchlist", [display_names["saved"]]),
                "favorite-shows": ("Favorite shows", [display_names["favorite_series"]]),
                "favorite-movies": ("Favorite movies", [display_names["favorite_movie"]]),
                "cached-episodes": (
                    "Cached episodes",
                    [f"{display_names['episode_show']} - S1E2 - {display_names['episode_name']}"],
                ),
                "watch-events": ("Watch-event ledger", [display_names["watched"]]),
                "copy-size-differences": ("Copy-size differences", []),
            }
            for identifier, (heading, names) in expected_sections.items():
                with self.subTest(section=identifier):
                    self.assertEqual(model_sections[identifier], names)
                    self.assertEqual(html_names.section_names.get(identifier, []), names)
                    for name in names:
                        self.assertIn(name, markdown_sections[heading])

            for value in display_names.values():
                with self.subTest(display_value=value):
                    self.assertIn(value, markdown)
                    self.assertIn(value, offline_html)

            self.assertEqual(result["pdf_status"], "generated")
            pdf_path = analysis / PDF_REPORT_FILENAME
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF-"))
            extracted_pdf = _pdf_text(pdf_path)
            expected_occurrences = {
                display_names["series"]: 1,
                display_names["watched"]: 2,
                display_names["saved"]: 1,
                display_names["favorite_series"]: 1,
                display_names["favorite_movie"]: 1,
                display_names["episode_show"]: 1,
                display_names["episode_name"]: 1,
            }
            for value, expected_count in expected_occurrences.items():
                with self.subTest(pdf_value=value):
                    self.assertEqual(
                        _without_layout_whitespace(extracted_pdf).count(
                            _without_layout_whitespace(value)
                        ),
                        expected_count,
                    )

            raw_series = (analysis / "series_library.csv").read_text(encoding="utf-8")
            self.assertIn("'=L\u2019été… exact series", raw_series)
            self.assertEqual(
                read_csv(
                    analysis / "series_library.csv",
                    escaped_cells=escaped["series_library.csv"],
                )[0]["name"],
                recovered_names["series"],
            )
            self.assertEqual(
                read_csv(analysis / "movie_watchlist.csv")[0]["name"],
                recovered_names["saved"],
            )
            self.assertNotEqual(recovered_names["saved"], display_names["saved"])

    def test_missing_title_placeholder_matches_markdown_html_and_pdf(self) -> None:
        placeholder = "[series title not present in cache]"
        for missing_name in ("", "\u200b\u2060\u200e\ufe0f"):
            with (
                self.subTest(value=ascii(missing_name)),
                tempfile.TemporaryDirectory() as temporary,
            ):
                extraction = create_synthetic_extraction(Path(temporary))
                _rewrite_library_names(extraction, {"series": missing_name})
                analyze_extraction(extraction_directory=extraction)
                result = build_report(extraction_directory=extraction)
                analysis = extraction / "analysis"

                markdown = (analysis / "TVTime-Recovered-Data.md").read_text(encoding="utf-8")
                markdown_display = markdown.replace("\\[", "[").replace("\\]", "]")
                offline_html = html.unescape(
                    (analysis / HTML_REPORT_FILENAME).read_text(encoding="utf-8")
                )
                self.assertEqual(markdown_display.count(placeholder), 1)
                self.assertEqual(offline_html.count(placeholder), 1)
                self.assertEqual(result["pdf_status"], "generated")
                pdf_reader = PdfReader(analysis / PDF_REPORT_FILENAME)
                self.assertEqual(pdf_reader.trailer["/Root"].get("/Lang"), "en-AU")
                self.assertEqual(_pdf_text(analysis / PDF_REPORT_FILENAME).count(placeholder), 1)

    def test_copy_size_differences_are_visible_in_every_readable_report(self) -> None:
        relative_path = "Documents/Synthetic-size-warning.bin"
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            write_bytes_private(
                extraction / "raw" / PRIMARY_DOMAIN / relative_path,
                b"123456789",
            )
            refresh_synthetic_source_snapshot(extraction)

            inventory_path = extraction / "metadata" / "inventory.csv"
            inventory_rows = read_csv_rows(inventory_path)
            discrepancy_row = next(
                row
                for row in inventory_rows
                if row["domain"] == PRIMARY_DOMAIN and row["relative_path"] == relative_path
            )
            discrepancy_row["declared_size"] = "11"
            discrepancy_row["size_match"] = "False"
            write_csv_private(
                inventory_path,
                inventory_rows,
                list(inventory_rows[0]),
                spreadsheet_safe=False,
            )
            source_snapshot = reconcile_raw_tree(extraction)

            summary_path = extraction / "metadata" / "summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["selected_declared_bytes"] += 2
            summary["size_discrepancies"] = [
                {
                    "domain": PRIMARY_DOMAIN,
                    "relative_path": relative_path,
                    "declared_size": 11,
                    "actual_size": 9,
                }
            ]
            write_real_json_private_atomic(summary_path, summary)
            run_state_path = extraction / "metadata" / "run_state.json"
            run_state = json.loads(run_state_path.read_text(encoding="utf-8"))
            run_state["selected_declared_bytes"] += 2
            run_state["size_discrepancy_count"] = 1
            run_state["source_snapshot"] = source_snapshot.as_dict()
            write_real_json_private_atomic(run_state_path, run_state)

            analyze_extraction(extraction_directory=extraction)
            result = build_report(extraction_directory=extraction)
            analysis = extraction / "analysis"
            markdown = (analysis / "TVTime-Recovered-Data.md").read_text(encoding="utf-8")
            offline_html = html.unescape(
                (analysis / HTML_REPORT_FILENAME).read_text(encoding="utf-8")
            )

            for readable in (markdown, offline_html):
                self.assertIn(relative_path, readable)
                self.assertIn("Declared bytes", readable)
                self.assertIn("Copied bytes", readable)
            pdf_compact = _without_layout_whitespace(_pdf_text(analysis / PDF_REPORT_FILENAME))
            for value in (relative_path, "Declared bytes", "Copied bytes"):
                self.assertIn(_without_layout_whitespace(value), pdf_compact)
            self.assertEqual(result["pdf_status"], "generated")
            marker = json.loads((analysis / "recovery_state.json").read_text(encoding="utf-8"))
            self.assertEqual(marker["aggregates"]["extraction"]["size_discrepancy_count"], 1)

    def test_shaping_required_text_omits_only_pdf_and_commits_complete_reports(self) -> None:
        arabic_name = "مسلسل تجريبي"
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            _rewrite_library_names(extraction, {"series": arabic_name})
            analyze_extraction(extraction_directory=extraction)
            result = build_report(extraction_directory=extraction)
            analysis = extraction / "analysis"
            state = json.loads((analysis / "recovery_state.json").read_text(encoding="utf-8"))

            self.assertEqual(result["pdf_status"], "omitted")
            self.assertEqual(result["pdf_warning"], PDF_FIDELITY_WARNING)
            self.assertNotIn(str(Path(temporary)), result["pdf_warning"])
            self.assertNotIn("pdf_report", result)
            self.assertFalse((analysis / PDF_REPORT_FILENAME).exists())
            self.assertFalse((analysis / f"{PDF_REPORT_FILENAME}.partial").exists())
            self.assertTrue((analysis / "TVTime-Recovered-Data.md").is_file())
            self.assertTrue((analysis / HTML_REPORT_FILENAME).is_file())
            self.assertIn(
                arabic_name,
                (analysis / "TVTime-Recovered-Data.md").read_text(encoding="utf-8"),
            )
            self.assertEqual(state["status"], "complete")
            self.assertEqual(state["pdf"]["status"], "omitted")
            self.assertIsNone(state["pdf"]["artifact_id"])
            self.assertNotIn("pdf_report", [item["id"] for item in state["artifacts"]])
            self.assertEqual(
                state["aggregates"]["report"]["pdf_omission_reason"],
                PDF_FIDELITY_WARNING,
            )

    def test_very_long_unbroken_title_does_not_abort_pdf_or_canonical_reports(self) -> None:
        long_name = "Z" * 5_000
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            _rewrite_library_names(extraction, {"series": long_name})
            analyze_extraction(extraction_directory=extraction)
            result = build_report(extraction_directory=extraction)
            analysis = extraction / "analysis"

            self.assertEqual(result["pdf_status"], "generated")
            self.assertIn(
                long_name,
                (analysis / "TVTime-Recovered-Data.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                long_name,
                html.unescape((analysis / HTML_REPORT_FILENAME).read_text(encoding="utf-8")),
            )
            pdf_without_layout_whitespace = _without_layout_whitespace(
                _pdf_text(analysis / PDF_REPORT_FILENAME)
            )
            self.assertEqual(pdf_without_layout_whitespace.count("Z"), len(long_name))


if __name__ == "__main__":
    unittest.main()
