from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from tests.helpers import create_synthetic_extraction, write_finished_status
from tvtime_extractor.cli import _run_extraction, _run_recovery, build_parser, main
from tvtime_extractor.errors import TVTimeError, UserInputError
from tvtime_extractor.extract import (
    PRIMARY_DOMAIN,
    RELATED_PLUGIN_DOMAIN_PREFIX,
    ExtractionResult,
    extract_backup,
    public_summary,
)
from tvtime_extractor.models import PreflightResult
from tvtime_extractor.safety import no_link_absolute_path, require_bound_destination_parent


class _FakeCursor:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows
        self.result: list[tuple[Any, ...]] = []
        self.position = 0

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, _parameters: object = None) -> None:
        self.position = 0
        if "SELECT DISTINCT domain" in query:
            expected = (PRIMARY_DOMAIN, f"{RELATED_PLUGIN_DOMAIN_PREFIX}%")
            if _parameters != expected:
                raise AssertionError(f"Domain query was not scoped to TV Time: {_parameters!r}")
            self.result = [(PRIMARY_DOMAIN,)]
        elif "SELECT fileID" in query:
            self.result = self.rows
        else:
            raise AssertionError(f"Unexpected synthetic query: {query}")

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        batch = self.result[self.position : self.position + size]
        self.position += len(batch)
        return batch


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


class _FakeConnection:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeBackup:
    def __init__(
        self,
        *,
        rows: list[tuple[Any, ...]],
        expected_directory: Path,
        backup_directory: str,
        passphrase: str,
    ) -> None:
        dependency_source = Path(backup_directory)
        for name in ("Manifest.plist", "Manifest.db", "Status.plist"):
            if (dependency_source / name).read_bytes() != (expected_directory / name).read_bytes():
                raise AssertionError("The dependency did not receive the verified control snapshot")
        if passphrase != "synthetic-passphrase":
            raise AssertionError("The passphrase was changed")
        self.rows = rows
        self._keybag = _FakeKeybag()
        self._passphrase = passphrase.encode()
        self._manifest_plist = {"synthetic": True}
        self._temporary_folder = tempfile.mkdtemp(prefix="dependency-private-")
        self._temp_decrypted_manifest_db_path = str(Path(self._temporary_folder) / "Manifest.db")
        Path(self._temp_decrypted_manifest_db_path).write_bytes(b"private manifest")
        self._temp_manifest_db_conn = _FakeConnection()

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

    def _cleanup(self) -> None:
        print(f"synthetic dependency cleanup for {self._temp_decrypted_manifest_db_path}")
        shutil.rmtree(self._temporary_folder)


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


def _write_selected_source_payload(backup: Path, file_id: str = "a" * 40) -> None:
    source = backup / file_id[:2] / file_id
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"synthetic encrypted payload")


def _synthetic_preflight() -> PreflightResult:
    return PreflightResult(
        encrypted=True,
        snapshot_state="finished",
        backup_date="",
        backup_regular_files=3,
        backup_logical_bytes=4096,
        manifest_database_bytes=1024,
        destination_free_bytes=1024 * 1024 * 1024,
        minimum_working_bytes=512 * 1024 * 1024,
    )


class CliTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "CLI directory-descriptor binding is POSIX-only")
    def test_recover_holds_one_parent_descriptor_across_preflight_password_and_recovery(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "fresh-output"
            args = build_parser().parse_args(
                [
                    "recover",
                    "--backup",
                    str(base / "synthetic-backup"),
                    "--output",
                    str(output),
                    "--acknowledge-sensitive-output",
                ]
            )
            order: list[str] = []
            descriptors: list[int] = []
            recovery_result = object()
            expected_preflight = _synthetic_preflight()
            service = mock.Mock()

            def preflight(
                _request: object, *, destination_parent_descriptor: int
            ) -> PreflightResult:
                order.append("preflight")
                descriptors.append(destination_parent_descriptor)
                self.assertTrue(stat.S_ISDIR(os.fstat(destination_parent_descriptor).st_mode))
                self.assertFalse(output.exists())
                return expected_preflight

            def read_password(*, password_stdin: bool) -> str:
                self.assertFalse(password_stdin)
                order.append("password")
                return "synthetic-passphrase"

            def recover(
                request: object,
                *,
                passphrase: str,
                progress: object,
                destination_parent_descriptor: int,
                preflight_result: PreflightResult,
            ) -> object:
                del progress
                order.append("recovery")
                descriptors.append(destination_parent_descriptor)
                self.assertEqual(passphrase, "synthetic-passphrase")
                self.assertIs(preflight_result, expected_preflight)
                self.assertIsNotNone(request.destination_parent_identity)
                self.assertTrue(stat.S_ISDIR(os.fstat(destination_parent_descriptor).st_mode))
                return recovery_result

            service.preflight.side_effect = preflight
            service.recover.side_effect = recover
            progress_output = io.StringIO()
            with (
                contextlib.redirect_stderr(progress_output),
                mock.patch("tvtime_extractor.cli.RecoveryService", return_value=service),
                mock.patch("tvtime_extractor.cli.read_backup_password", side_effect=read_password),
            ):
                self.assertIs(_run_recovery(args), recovery_result)

            self.assertEqual(order, ["preflight", "password", "recovery"])
            self.assertIn("Preflight passed", progress_output.getvalue())
            self.assertIn("Backup scan: 3 regular files", progress_output.getvalue())
            self.assertEqual(len(descriptors), 2)
            self.assertEqual(descriptors[0], descriptors[1])
            with self.assertRaises(OSError):
                os.fstat(descriptors[0])
            self.assertFalse(output.exists())

    @unittest.skipIf(os.name == "nt", "CLI directory-descriptor binding is POSIX-only")
    def test_extract_holds_parent_descriptor_and_returns_visible_result_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "fresh-output"
            args = build_parser().parse_args(
                [
                    "extract",
                    "--backup",
                    str(base / "synthetic-backup"),
                    "--output",
                    str(output),
                    "--acknowledge-sensitive-output",
                ]
            )
            descriptor_seen: list[int] = []
            service = mock.Mock()
            expected_preflight = _synthetic_preflight()

            def preflight(
                _request: object, *, destination_parent_descriptor: int
            ) -> PreflightResult:
                descriptor_seen.append(destination_parent_descriptor)
                self.assertFalse(output.exists())
                return expected_preflight

            service.preflight.side_effect = preflight
            synthetic_result = ExtractionResult(
                extraction_root=no_link_absolute_path(output) / "TVTime-Extraction",
                summary={"synthetic": True},
            )
            service.extract.return_value = synthetic_result
            with (
                mock.patch("tvtime_extractor.cli.RecoveryService", return_value=service),
                mock.patch(
                    "tvtime_extractor.cli.read_backup_password",
                    return_value="synthetic-passphrase",
                ),
            ):
                result = _run_extraction(args)

            self.assertIs(result, synthetic_result)
            extract = service.extract
            self.assertEqual(
                extract.call_args.args[0].output_directory,
                no_link_absolute_path(output),
            )
            self.assertIs(extract.call_args.kwargs["preflight_result"], expected_preflight)
            self.assertEqual(
                extract.call_args.kwargs["destination_parent_descriptor"],
                descriptor_seen[0],
            )
            with self.assertRaises(OSError):
                os.fstat(descriptor_seen[0])

    @unittest.skipIf(os.name == "nt", "CLI directory-descriptor binding is POSIX-only")
    def test_recover_rejects_parent_substitution_after_password_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            parent = base / "destination"
            moved = base / "moved-destination"
            parent.mkdir()
            output = parent / "fresh-output"
            args = build_parser().parse_args(
                [
                    "recover",
                    "--backup",
                    str(base / "synthetic-backup"),
                    "--output",
                    str(output),
                    "--acknowledge-sensitive-output",
                ]
            )
            held_descriptor: list[int] = []
            service = mock.Mock()

            def preflight(
                _request: object, *, destination_parent_descriptor: int
            ) -> PreflightResult:
                held_descriptor.append(destination_parent_descriptor)
                return _synthetic_preflight()

            def substitute_parent(*, password_stdin: bool) -> str:
                self.assertFalse(password_stdin)
                parent.rename(moved)
                parent.mkdir()
                return "synthetic-passphrase"

            def reject_substitution(
                request: object,
                *,
                passphrase: str,
                progress: object,
                destination_parent_descriptor: int,
                preflight_result: PreflightResult,
            ) -> object:
                del passphrase, progress, preflight_result
                identity = request.destination_parent_identity
                assert identity is not None
                require_bound_destination_parent(
                    request.output_directory,
                    destination_parent_descriptor=destination_parent_descriptor,
                    expected_identity=(identity.device, identity.inode),
                )
                return object()

            service.preflight.side_effect = preflight
            service.recover.side_effect = reject_substitution
            with (
                mock.patch("tvtime_extractor.cli.RecoveryService", return_value=service),
                mock.patch(
                    "tvtime_extractor.cli.read_backup_password", side_effect=substitute_parent
                ),
                self.assertRaisesRegex(UserInputError, "parent path changed"),
            ):
                _run_recovery(args)

            self.assertFalse(output.exists())
            self.assertFalse((moved / output.name).exists())
            with self.assertRaises(OSError):
                os.fstat(held_descriptor[0])

    @unittest.skipIf(os.name == "nt", "CLI directory-descriptor binding is POSIX-only")
    def test_missing_immediate_parent_stops_before_preflight_or_password(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "missing-parent" / "fresh-output"
            args = build_parser().parse_args(
                [
                    "recover",
                    "--backup",
                    str(base / "synthetic-backup"),
                    "--output",
                    str(output),
                    "--acknowledge-sensitive-output",
                ]
            )
            with (
                mock.patch("tvtime_extractor.cli.RecoveryService") as service,
                mock.patch("tvtime_extractor.cli.read_backup_password") as read_password,
                self.assertRaisesRegex(UserInputError, "immediate destination parent must"),
            ):
                _run_recovery(args)
            service.assert_not_called()
            read_password.assert_not_called()
            self.assertFalse(output.exists())

    def test_sealed_recover_does_not_offer_unbound_advanced_exports(self) -> None:
        parser = build_parser()
        base = [
            "recover",
            "--backup",
            "synthetic-backup",
            "--output",
            "synthetic-output",
            "--acknowledge-sensitive-output",
        ]
        for option in ("--include-raw-cache", "--include-decrypted-manifest"):
            with (
                self.subTest(option=option),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                parser.parse_args([*base, option])

        extracted = parser.parse_args(
            [
                "extract",
                "--backup",
                "synthetic-backup",
                "--output",
                "synthetic-output",
                "--acknowledge-sensitive-output",
                "--include-decrypted-manifest",
            ]
        )
        analyzed = parser.parse_args(
            ["analyze", "--extraction", "synthetic-extraction", "--include-raw-cache"]
        )
        self.assertTrue(extracted.include_decrypted_manifest)
        self.assertTrue(analyzed.include_raw_cache)

    def test_debug_help_warns_that_tracebacks_can_expose_secrets_and_must_not_be_shared(
        self,
    ) -> None:
        help_text = " ".join(build_parser().format_help().split())
        self.assertIn("password text", help_text)
        self.assertIn("never paste or share", help_text)

    def test_default_cli_hides_chained_dependency_details_until_debug(self) -> None:
        secret = "pass=do-not-leak /Users/private/Secret Show Title"

        def dependency_failure(*_args: object, **_kwargs: object) -> None:
            try:
                raise RuntimeError(secret)
            except RuntimeError as cause:
                raise TVTimeError("The backup dependency failed safely.") from cause

        command = [
            "extract",
            "--backup",
            "synthetic-backup",
            "--output",
            "synthetic-output",
            "--acknowledge-sensitive-output",
        ]
        stderr = io.StringIO()
        with (
            mock.patch("tvtime_extractor.cli._run_extraction", side_effect=dependency_failure),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(main(command), 1)
        self.assertIn("dependency failed safely", stderr.getvalue())
        self.assertNotIn(secret, stderr.getvalue())

        with (
            mock.patch("tvtime_extractor.cli._run_extraction", side_effect=dependency_failure),
            self.assertRaises(TVTimeError) as raised,
        ):
            main(["--debug", *command])
        self.assertIsNotNone(raised.exception.__cause__)
        self.assertIn(secret, str(raised.exception.__cause__))

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
            self.assertIn("Recovered series records: 1", human_output.getvalue())
            self.assertIn("Recovered movie records:", human_output.getvalue())
            self.assertIn("Recovered cached episode records:", human_output.getvalue())
            self.assertNotIn("Movie titles:", human_output.getvalue())
            self.assertNotIn("Identifiable cached episodes:", human_output.getvalue())
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

    def test_recover_help_explains_the_fresh_output_path_contract(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exit_context:
            main(["recover", "--help"])
        self.assertEqual(exit_context.exception.code, 0)
        help_text = " ".join(output.getvalue().split())
        self.assertIn("parent must exist", help_text)
        self.assertIn("must not already exist", help_text)

    def test_extractor_uses_a_copy_boundary_and_secure_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = base / "backup"
            backup.mkdir()
            manifest = backup / "Manifest.plist"
            manifest.write_bytes(b"synthetic source manifest")
            (backup / "Manifest.db").write_bytes(b"synthetic encrypted manifest database")
            write_finished_status(backup)
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
            _write_selected_source_payload(backup)
            destination_descriptor: int | None = None
            destination_identity: tuple[int, int] | None = None
            if os.name != "nt":
                destination_descriptor = os.open(
                    base,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
                )
                destination_metadata = os.fstat(destination_descriptor)
                destination_identity = (
                    int(destination_metadata.st_dev),
                    int(destination_metadata.st_ino),
                )
            try:
                with mock.patch.object(os, "supports_follow_symlinks", set()):
                    result = extract_backup(
                        backup_directory=backup,
                        output_directory=base / "private-output",
                        passphrase="synthetic-passphrase",
                        destination_parent_descriptor=destination_descriptor,
                        expected_destination_parent_identity=destination_identity,
                        dependency_loader=lambda: _dependency_loader(
                            rows=rows,
                            expected_directory=backup,
                        ),
                    )
            finally:
                if destination_descriptor is not None:
                    os.close(destination_descriptor)

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
            write_finished_status(backup)
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
            _write_selected_source_payload(backup)
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

    def test_dependency_copy_exception_text_is_not_persisted(self) -> None:
        secret = "pass=do-not-leak /Users/private/Secret Show Title"
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = base / "backup"
            backup.mkdir()
            (backup / "Manifest.plist").write_bytes(b"synthetic source manifest")
            (backup / "Manifest.db").write_bytes(b"synthetic encrypted manifest database")
            write_finished_status(backup)
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
            _write_selected_source_payload(backup)

            class FailingBackup(_FakeBackup):
                def _decrypt_file_to_disk(self, **_kwargs: object) -> None:
                    raise RuntimeError(secret)

            def loader() -> tuple[object, type[_FakeFilePlist]]:
                def factory(*, backup_directory: str, passphrase: str) -> FailingBackup:
                    return FailingBackup(
                        rows=rows,
                        expected_directory=backup,
                        backup_directory=backup_directory,
                        passphrase=passphrase,
                    )

                return factory, _FakeFilePlist

            result = extract_backup(
                backup_directory=backup,
                output_directory=base / "private-output",
                passphrase="synthetic-passphrase",
                dependency_loader=loader,
            )
            persisted = (result.extraction_root / "metadata" / "summary.json").read_text(
                encoding="utf-8"
            )
            self.assertNotIn(secret, persisted)
            self.assertEqual(
                result.summary["failures"][0]["error"],
                "The selected backup file could not be copied safely.",
            )

    def test_size_discrepancy_is_publicly_visible_without_leaking_dependency_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = base / "backup"
            backup.mkdir()
            (backup / "Manifest.plist").write_bytes(b"synthetic source manifest")
            (backup / "Manifest.db").write_bytes(b"synthetic encrypted manifest database")
            write_finished_status(backup)
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
            _write_selected_source_payload(backup)
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
            write_finished_status(backup)
            output = base / "private-output"

            def unavailable() -> tuple[object, object]:
                raise TVTimeError("synthetic dependency failure")

            with self.assertRaises(TVTimeError) as raised:
                extract_backup(
                    backup_directory=backup,
                    output_directory=output,
                    passphrase="synthetic-passphrase",
                    dependency_loader=unavailable,
                )
            self.assertNotIn("synthetic dependency failure", str(raised.exception))
            self.assertIn("dependency failed safely", str(raised.exception))
            self.assertIn("synthetic dependency failure", str(raised.exception.__cause__))
            self.assertFalse(output.exists())

    def test_failed_password_attempt_is_clearly_marked_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = base / "backup"
            backup.mkdir()
            (backup / "Manifest.plist").write_bytes(b"synthetic source manifest")
            (backup / "Manifest.db").write_bytes(b"synthetic encrypted manifest database")
            write_finished_status(backup)
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

            with self.assertRaises(TVTimeError) as raised:
                extract_backup(
                    backup_directory=backup,
                    output_directory=output,
                    passphrase="synthetic-passphrase",
                    dependency_loader=loader,
                )
            self.assertNotIn("synthetic password rejection", str(raised.exception))
            self.assertIn("dependency failed safely", str(raised.exception))

            state_path = output / "TVTime-Extraction" / "metadata" / "run_state.json"
            self.assertTrue(state_path.is_file())
            self.assertEqual(json.loads(state_path.read_text())["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
