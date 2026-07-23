from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import create_synthetic_extraction
from tvtime_extractor.analyze import analyze_extraction
from tvtime_extractor.errors import PartialExtractionError, TVTimeError
from tvtime_extractor.extract import PRIMARY_DOMAIN
from tvtime_extractor.integrity import reconcile_raw_tree, source_snapshot_from_mapping
from tvtime_extractor.report import build_report
from tvtime_extractor.safety import write_bytes_private
from tvtime_extractor.visual_report import write_visual_reports as write_real_visual_reports


class RawChainIntegrityTests(unittest.TestCase):
    def test_synthetic_inventory_uses_real_hashes_and_covers_the_exact_raw_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            inventory = extraction / "metadata" / "inventory.csv"
            with inventory.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            actual_files = sorted(
                path for path in (extraction / "raw").rglob("*") if path.is_file()
            )
            self.assertEqual(len(rows), len(actual_files))
            self.assertTrue(rows)
            self.assertTrue(all(row["sha256"] != "0" * 64 for row in rows))
            for row in rows:
                path = extraction / "raw" / row["domain"] / Path(row["relative_path"])
                self.assertEqual(row["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

            run_state = json.loads(
                (extraction / "metadata" / "run_state.json").read_text(encoding="utf-8")
            )
            expected = source_snapshot_from_mapping(run_state["source_snapshot"])
            self.assertEqual(reconcile_raw_tree(extraction, expected=expected), expected)

    def test_analysis_rejects_changed_removed_and_extra_raw_files(self) -> None:
        mutations = ("changed", "removed", "extra_file", "extra_directory")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                extraction = create_synthetic_extraction(Path(temporary))
                raw = extraction / "raw"
                target = raw / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
                if mutation == "changed":
                    payload = bytearray(target.read_bytes())
                    payload[0] ^= 0xFF
                    write_bytes_private(target, bytes(payload))
                elif mutation == "removed":
                    target.unlink()
                elif mutation == "extra_file":
                    write_bytes_private(raw / PRIMARY_DOMAIN / "Documents" / "unexpected.bin", b"x")
                else:
                    extra = raw / PRIMARY_DOMAIN / "Documents" / "unexpected-empty-directory"
                    extra.mkdir(mode=0o700)

                with self.assertRaises(PartialExtractionError):
                    analyze_extraction(extraction_directory=extraction)
                self.assertFalse((extraction / "analysis").exists())

    @unittest.skipIf(os.name == "nt", "Windows source handles deny concurrent mutation")
    def test_descriptor_bound_raw_hashing_rejects_an_in_place_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            target = extraction / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
            target_metadata = target.stat()
            real_read = os.read
            mutated = False

            def race(descriptor: int, count: int) -> bytes:
                nonlocal mutated
                chunk = real_read(descriptor, count)
                opened = os.fstat(descriptor)
                if (
                    chunk
                    and not mutated
                    and (opened.st_dev, opened.st_ino)
                    == (target_metadata.st_dev, target_metadata.st_ino)
                ):
                    mutated = True
                    with target.open("r+b") as handle:
                        original = handle.read(1)
                        handle.seek(0)
                        handle.write(bytes([original[0] ^ 0xFF]))
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.utime(
                        target,
                        ns=(target_metadata.st_atime_ns, target_metadata.st_mtime_ns),
                    )
                return chunk

            with (
                mock.patch("tvtime_extractor.integrity.os.read", side_effect=race),
                self.assertRaises(TVTimeError),
            ):
                analyze_extraction(extraction_directory=extraction)
            self.assertTrue(mutated)
            self.assertFalse((extraction / "analysis").exists())

    def test_report_rechecks_raw_bytes_and_rejects_post_analysis_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            analyze_extraction(extraction_directory=extraction)
            target = extraction / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
            payload = bytearray(target.read_bytes())
            payload[-1] ^= 0xFF
            write_bytes_private(target, bytes(payload))

            with self.assertRaises(PartialExtractionError):
                build_report(extraction_directory=extraction)
            self.assertTrue((extraction / "analysis").is_dir())
            self.assertFalse((extraction / ".report-incomplete").exists())

    def test_sealed_report_fails_closed_for_optional_raw_cache_exports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            analyze_extraction(extraction_directory=extraction, include_raw_cache=True)
            with self.assertRaisesRegex(TVTimeError, "cannot include raw cache-response exports"):
                build_report(extraction_directory=extraction)
            self.assertTrue((extraction / "analysis" / "cache_responses").is_dir())
            self.assertFalse((extraction / ".report-incomplete").exists())

    def test_sealed_report_fails_closed_for_retained_decrypted_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            analyze_extraction(extraction_directory=extraction)
            write_bytes_private(
                extraction / "manifest" / "Manifest.decrypted.db",
                b"synthetic private manifest",
            )
            with self.assertRaisesRegex(TVTimeError, "cannot include a retained decrypted"):
                build_report(extraction_directory=extraction)
            self.assertTrue((extraction / "analysis").is_dir())
            self.assertFalse((extraction / ".report-incomplete").exists())

    def test_sealed_report_rejects_extra_files_and_subdirectories_in_exact_directories(
        self,
    ) -> None:
        for directory_name in ("metadata", "analysis"):
            for extra_kind in ("file", "directory"):
                with (
                    self.subTest(directory=directory_name, extra_kind=extra_kind),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    extraction = create_synthetic_extraction(Path(temporary))
                    analyze_extraction(extraction_directory=extraction)
                    parent = extraction / directory_name
                    extra = parent / "renamed-sensitive-export"
                    if extra_kind == "file":
                        write_bytes_private(extra.with_suffix(".bin"), b"synthetic private export")
                    else:
                        extra.mkdir(mode=0o700)

                    with self.assertRaisesRegex(TVTimeError, "exact sealed membership"):
                        build_report(extraction_directory=extraction)
                    self.assertFalse((extraction / "analysis").exists())
                    self.assertTrue((extraction / ".report-incomplete").is_dir())

    @unittest.skipIf(os.name == "nt", "symbolic-link creation varies on Windows")
    def test_sealed_report_rejects_extra_symlinks_in_exact_directories(self) -> None:
        for directory_name in ("metadata", "analysis"):
            with self.subTest(directory=directory_name), tempfile.TemporaryDirectory() as temporary:
                extraction = create_synthetic_extraction(Path(temporary))
                analyze_extraction(extraction_directory=extraction)
                target = extraction / "raw" / PRIMARY_DOMAIN / "Documents" / "DioCache.db"
                (extraction / directory_name / "renamed-sensitive-export").symlink_to(target)

                with self.assertRaisesRegex(TVTimeError, "exact sealed membership"):
                    build_report(extraction_directory=extraction)
                self.assertFalse((extraction / "analysis").exists())
                self.assertTrue((extraction / ".report-incomplete").is_dir())

    def test_sealed_report_rechecks_exact_membership_after_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            analyze_extraction(extraction_directory=extraction)

            def render_then_inject(model: object, **kwargs: object) -> dict[str, str]:
                result = write_real_visual_reports(model, **kwargs)
                analysis_directory = kwargs["analysis_directory"]
                assert isinstance(analysis_directory, Path)
                write_bytes_private(
                    analysis_directory / "renamed-sensitive-export.bin",
                    b"synthetic private export",
                )
                return result

            with (
                mock.patch(
                    "tvtime_extractor.report.write_visual_reports",
                    side_effect=render_then_inject,
                ),
                self.assertRaisesRegex(TVTimeError, "exact sealed membership"),
            ):
                build_report(extraction_directory=extraction)

            self.assertFalse((extraction / "analysis").exists())
            self.assertTrue((extraction / ".report-incomplete").is_dir())
            self.assertTrue(
                (extraction / ".report-incomplete" / "renamed-sensitive-export.bin").is_file()
            )

    def test_sealed_report_requires_the_documented_domains_metadata_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            analyze_extraction(extraction_directory=extraction)
            (extraction / "metadata" / "domains.txt").unlink()

            with self.assertRaisesRegex(TVTimeError, "required private data file was unavailable"):
                build_report(extraction_directory=extraction)


if __name__ == "__main__":
    unittest.main()
