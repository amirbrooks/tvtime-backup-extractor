from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from tests.helpers import create_synthetic_extraction
from tvtime_extractor.cli import main
from tvtime_extractor.errors import TVTimeError
from tvtime_extractor.extract import (
    PRIMARY_DOMAIN,
    RELATED_PLUGIN_DOMAIN_PREFIX,
    extract_backup,
    public_summary,
)


class _FakeCursor:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows
        self.result: list[tuple[Any, ...]] = []

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, _parameters: object = None) -> None:
        if "SELECT DISTINCT domain" in query:
            expected = (PRIMARY_DOMAIN, f"{RELATED_PLUGIN_DOMAIN_PREFIX}%")
            if _parameters != expected:
                raise AssertionError(f"Domain query was not scoped to TV Time: {_parameters!r}")
            self.result = [(PRIMARY_DOMAIN,)]
        elif "SELECT fileID" in query:
            self.result = self.rows
        else:
            raise AssertionError(f"Unexpected synthetic query: {query}")

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self.result


class _FakeKeybag:
    def unwrapKeyForClass(self, protection_class: object, encryption_key: object) -> bytes:
        if protection_class != 1 or encryption_key != b"wrapped-key":
            raise AssertionError("Unexpected synthetic key metadata")
        return b"unwrapped-key"


class _FakeFilePlist:
    def __init__(self, value: dict[str, object]) -> None:
        self.filesize = value["filesize"]
        self.encryption_key = value["encryption_key"]
        self.protection_class = value["protection_class"]
        self.mtime = value["mtime"]


class _FakeBackup:
    def __init__(
        self,
        *,
        rows: list[tuple[Any, ...]],
        expected_directory: Path,
        backup_directory: str,
        passphrase: str,
    ) -> None:
        if Path(backup_directory) != expected_directory.resolve():
            raise AssertionError("The backup path was changed")
        if passphrase != "synthetic-passphrase":
            raise AssertionError("The passphrase was changed")
        self.rows = rows
        self._keybag = _FakeKeybag()

    def test_decryption(self) -> None:
        return None

    def manifest_db_cursor(self) -> _FakeCursor:
        return _FakeCursor(self.rows)

    def _decrypt_file_to_disk(
        self,
        *,
        file_id: str,
        key: bytes,
        file_plist: _FakeFilePlist,
        output_filepath: str,
    ) -> None:
        if file_id != "a" * 40 or key != b"unwrapped-key":
            raise AssertionError("Unexpected synthetic file metadata")
        print(f"synthetic dependency warning for {output_filepath}")
        Path(output_filepath).write_bytes(b"data")

    def save_manifest_file(self, output_path: str) -> None:
        Path(output_path).write_bytes(b"synthetic decrypted manifest")


def _dependency_loader(
    *, rows: list[tuple[Any, ...]], expected_directory: Path
) -> tuple[object, type[_FakeFilePlist]]:
    def factory(*, backup_directory: str, passphrase: str) -> _FakeBackup:
        return _FakeBackup(
            rows=rows,
            expected_directory=expected_directory,
            backup_directory=backup_directory,
            passphrase=passphrase,
        )

    return factory, _FakeFilePlist


class CliTests(unittest.TestCase):
    def test_human_summary_is_default_and_json_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            human_output = io.StringIO()
            with (
                contextlib.redirect_stdout(human_output),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                exit_code = main(["analyze", "--extraction", str(extraction)])
            self.assertEqual(exit_code, 0)
            self.assertIn("TV Time analysis summary", human_output.getvalue())
            self.assertIn("TV series titles: 1", human_output.getvalue())
            self.assertFalse(human_output.getvalue().lstrip().startswith("{"))

        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            json_output = io.StringIO()
            with (
                contextlib.redirect_stdout(json_output),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                exit_code = main(["analyze", "--extraction", str(extraction), "--json"])
            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads(json_output.getvalue())["series_library"], 1)

    def test_module_and_compatibility_entrypoints_show_help(self) -> None:
        commands = (
            [sys.executable, "-m", "tvtime_extractor", "--help"],
            [sys.executable, "scripts/extract_tvtime.py", "--help"],
            [sys.executable, "scripts/analyze_tvtime.py", "--help"],
            [sys.executable, "scripts/build_validation_catalog.py", "--help"],
        )
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        for command in commands:
            with self.subTest(command=command):
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("usage:", completed.stdout.lower())

    def test_extraction_requires_explicit_sensitive_output_acknowledgement(self) -> None:
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            exit_code = main(
                [
                    "extract",
                    "--backup",
                    "synthetic-backup",
                    "--output",
                    "synthetic-output",
                ]
            )
        self.assertEqual(exit_code, 2)
        self.assertIn("acknowledge-sensitive-output", error.getvalue())

    def test_extractor_uses_a_copy_boundary_and_secure_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = base / "backup"
            backup.mkdir()
            manifest = backup / "Manifest.plist"
            manifest.write_bytes(b"synthetic source manifest")
            (backup / "Manifest.db").write_bytes(b"synthetic encrypted manifest database")
            rows = [
                (
                    "a" * 40,
                    PRIMARY_DOMAIN,
                    "Documents/example.bin",
                    {
                        "filesize": 4,
                        "encryption_key": b"wrapped-key",
                        "protection_class": 1,
                        "mtime": 1_700_000_000,
                    },
                )
            ]
            with mock.patch.object(os, "supports_follow_symlinks", set()):
                result = extract_backup(
                    backup_directory=backup,
                    output_directory=base / "private-output",
                    passphrase="synthetic-passphrase",
                    dependency_loader=lambda: _dependency_loader(
                        rows=rows,
                        expected_directory=backup,
                    ),
                )

            extracted = (
                result.extraction_root / "raw" / PRIMARY_DOMAIN / "Documents" / "example.bin"
            )
            self.assertEqual(extracted.read_bytes(), b"data")
            self.assertEqual(manifest.read_bytes(), b"synthetic source manifest")
            self.assertFalse(
                (result.extraction_root / "manifest" / "Manifest.decrypted.db").exists()
            )
            self.assertEqual(result.summary["files_expected"], 1)
            self.assertEqual(result.summary["files_extracted"], 1, result.summary["failures"])
            self.assertEqual(result.summary["failures"], [])
            self.assertEqual(public_summary(result)["size_discrepancy_count"], 0)
            run_state = json.loads(
                (result.extraction_root / "metadata" / "run_state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(run_state["status"], "complete")
            private_summary = json.loads(
                (result.extraction_root / "metadata" / "summary.json").read_text(encoding="utf-8")
            )
            self.assertNotIn(str(backup), json.dumps(private_summary))

    def test_manifest_path_attack_is_recorded_without_escaping_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = base / "backup"
            backup.mkdir()
            (backup / "Manifest.plist").write_bytes(b"synthetic source manifest")
            (backup / "Manifest.db").write_bytes(b"synthetic encrypted manifest database")
            rows = [
                (
                    "a" * 40,
                    PRIMARY_DOMAIN,
                    "../../outside.txt",
                    {
                        "filesize": 4,
                        "encryption_key": b"wrapped-key",
                        "protection_class": 1,
                        "mtime": 1_700_000_000,
                    },
                )
            ]
            result = extract_backup(
                backup_directory=backup,
                output_directory=base / "private-output",
                passphrase="synthetic-passphrase",
                dependency_loader=lambda: _dependency_loader(
                    rows=rows,
                    expected_directory=backup,
                ),
            )
            self.assertEqual(result.summary["files_extracted"], 0)
            self.assertEqual(len(result.summary["failures"]), 1)
            self.assertFalse((base / "outside.txt").exists())

    def test_size_discrepancy_is_publicly_visible_without_leaking_dependency_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = base / "backup"
            backup.mkdir()
            (backup / "Manifest.plist").write_bytes(b"synthetic source manifest")
            (backup / "Manifest.db").write_bytes(b"synthetic encrypted manifest database")
            rows = [
                (
                    "a" * 40,
                    PRIMARY_DOMAIN,
                    "Documents/example.bin",
                    {
                        "filesize": 5,
                        "encryption_key": b"wrapped-key",
                        "protection_class": 1,
                        "mtime": 1_700_000_000,
                    },
                )
            ]
            dependency_output = io.StringIO()
            with contextlib.redirect_stdout(dependency_output):
                result = extract_backup(
                    backup_directory=backup,
                    output_directory=base / "private-output",
                    passphrase="synthetic-passphrase",
                    dependency_loader=lambda: _dependency_loader(
                        rows=rows,
                        expected_directory=backup,
                    ),
                )

            self.assertEqual(dependency_output.getvalue(), "")
            self.assertEqual(len(result.summary["size_discrepancies"]), 1)
            self.assertEqual(public_summary(result)["size_discrepancy_count"], 1)

    def test_dependency_failure_does_not_create_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = base / "backup"
            backup.mkdir()
            (backup / "Manifest.plist").write_bytes(b"synthetic source manifest")
            (backup / "Manifest.db").write_bytes(b"synthetic encrypted manifest database")
            output = base / "private-output"

            def unavailable() -> tuple[object, object]:
                raise TVTimeError("synthetic dependency failure")

            with self.assertRaisesRegex(TVTimeError, "synthetic dependency failure"):
                extract_backup(
                    backup_directory=backup,
                    output_directory=output,
                    passphrase="synthetic-passphrase",
                    dependency_loader=unavailable,
                )
            self.assertFalse(output.exists())

    def test_failed_password_attempt_is_clearly_marked_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = base / "backup"
            backup.mkdir()
            (backup / "Manifest.plist").write_bytes(b"synthetic source manifest")
            (backup / "Manifest.db").write_bytes(b"synthetic encrypted manifest database")
            output = base / "private-output"

            class WrongPasswordBackup(_FakeBackup):
                def test_decryption(self) -> None:
                    raise ValueError("synthetic password rejection")

            def loader() -> tuple[object, type[_FakeFilePlist]]:
                def factory(*, backup_directory: str, passphrase: str) -> WrongPasswordBackup:
                    return WrongPasswordBackup(
                        rows=[],
                        expected_directory=backup,
                        backup_directory=backup_directory,
                        passphrase=passphrase,
                    )

                return factory, _FakeFilePlist

            with self.assertRaisesRegex(TVTimeError, "Extraction failed"):
                extract_backup(
                    backup_directory=backup,
                    output_directory=output,
                    passphrase="synthetic-passphrase",
                    dependency_loader=loader,
                )

            state_path = output / "TVTime-Extraction" / "metadata" / "run_state.json"
            self.assertTrue(state_path.is_file())
            self.assertEqual(json.loads(state_path.read_text())["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
