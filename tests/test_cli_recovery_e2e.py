from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from script.validate_recovery_output import validate_recovery_output
from tests.helpers import create_synthetic_extraction
from tests.test_service_protocol_e2e import (
    _EndToEndBackup,
    _FilePlist,
    _tree_fingerprint,
    _write_completed_encrypted_backup,
)
from tvtime_extractor.cli import main
from tvtime_extractor.extract import PRIMARY_DOMAIN
from tvtime_extractor.extract import extract_backup as real_extract_backup
from tvtime_extractor.visual_report import HTML_REPORT_FILENAME, PDF_REPORT_FILENAME


@unittest.skipIf(os.name == "nt", "Full encrypted-backup recovery is POSIX-only")
class CliSyntheticRecoveryEndToEndTests(unittest.TestCase):
    def test_recover_runs_full_synthetic_pipeline_and_validates_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tvtime-cli-e2e-") as temporary:
            base = Path(temporary)
            template = create_synthetic_extraction(base / "template")
            template_app = template / "raw" / PRIMARY_DOMAIN
            backup = _write_completed_encrypted_backup(base)
            rows: list[tuple[Any, ...]] = []
            plaintext: dict[str, bytes] = {}
            for index, source in enumerate(
                sorted(path for path in template_app.rglob("*") if path.is_file()), 1
            ):
                file_id = f"{index:040x}"
                payload = source.read_bytes()
                plaintext[file_id] = payload
                rows.append(
                    (
                        file_id,
                        PRIMARY_DOMAIN,
                        source.relative_to(template_app).as_posix(),
                        {"filesize": len(payload)},
                    )
                )
                encrypted = backup / file_id[:2] / file_id
                encrypted.parent.mkdir(exist_ok=True)
                encrypted.write_bytes(b"synthetic encrypted payload")

            instances: list[_EndToEndBackup] = []

            def dependency_loader() -> tuple[object, type[_FilePlist]]:
                def factory(*, backup_directory: str, passphrase: str) -> _EndToEndBackup:
                    instance = _EndToEndBackup(
                        backup_directory=backup_directory,
                        passphrase=passphrase,
                        rows=rows,
                        plaintext=plaintext,
                    )
                    instances.append(instance)
                    return instance

                return factory, _FilePlist

            def patched_extract(**kwargs: object) -> object:
                return real_extract_backup(**kwargs, dependency_loader=dependency_loader)

            destination = base / "private-destination"
            source_fingerprint = _tree_fingerprint(backup)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch("tvtime_extractor.service.extract_backup", side_effect=patched_extract),
                mock.patch("sys.stdin", io.StringIO("synthetic passphrase\n")),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = main(
                    [
                        "recover",
                        "--backup",
                        str(backup),
                        "--output",
                        str(destination),
                        "--password-stdin",
                        "--acknowledge-sensitive-output",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertIn("TV Time extraction summary", stdout.getvalue())
            self.assertIn("TV Time analysis summary", stdout.getvalue())
            self.assertIn("Readable recovery report", stdout.getvalue())
            self.assertIn("Recovery completed successfully.", stderr.getvalue())
            self.assertNotIn("synthetic passphrase", stdout.getvalue())
            self.assertNotIn("synthetic passphrase", stderr.getvalue())
            self.assertEqual(_tree_fingerprint(backup), source_fingerprint)

            extraction = destination / "TVTime-Extraction"
            analysis = extraction / "analysis"
            run_state = json.loads(
                (extraction / "metadata" / "run_state.json").read_text(encoding="utf-8")
            )
            recovery_state = json.loads(
                (analysis / "recovery_state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(run_state["status"], "complete")
            self.assertEqual(run_state["files_expected"], len(rows))
            self.assertEqual(run_state["files_extracted"], len(rows))
            self.assertEqual(recovery_state["status"], "complete")
            self.assertFalse((extraction / ".tmp").exists())
            self.assertFalse((extraction / ".analysis-incomplete").exists())
            self.assertFalse((extraction / ".report-incomplete").exists())
            self.assertTrue((analysis / "TVTime-Recovered-Data.md").is_file())
            self.assertTrue((analysis / HTML_REPORT_FILENAME).is_file())
            self.assertTrue((analysis / PDF_REPORT_FILENAME).is_file())

            validation = validate_recovery_output(destination)
            self.assertEqual(
                validation.gates,
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
            self.assertEqual(len(instances), 1)
            self.assertTrue(instances[0].connection.closed)
            self.assertEqual(instances[0].cleanup_calls, 1)


if __name__ == "__main__":
    unittest.main()
