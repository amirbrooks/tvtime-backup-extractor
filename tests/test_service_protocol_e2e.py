from __future__ import annotations

import hashlib
import json
import os
import plistlib
import queue
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager, suppress
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from tests.helpers import create_synthetic_extraction
from tvtime_extractor.errors import (
    BackupUnencryptedError,
    BackupUnfinishedError,
    SourceChangedError,
    UserInputError,
)
from tvtime_extractor.extract import PRIMARY_DOMAIN, ExtractionResult
from tvtime_extractor.extract import extract_backup as real_extract_backup
from tvtime_extractor.helper_main import (
    _hold_destination_parent_descriptor,
    _protocol_summary,
    _safe_error_payload,
)
from tvtime_extractor.models import (
    DestinationDirectoryIdentity,
    RecoveryEvent,
    RecoveryRequest,
    RecoveryResult,
)
from tvtime_extractor.protocol import (
    DESTINATION_PARENT_FILE_DESCRIPTOR,
    PROTOCOL_VERSION,
    ProtocolError,
    ProtocolWriter,
    read_control_request,
)
from tvtime_extractor.safety import (
    extended_acl_state,
    held_destination_parent,
    no_link_absolute_path,
)
from tvtime_extractor.service import RecoveryService


class _Cursor:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows
        self.result: list[tuple[Any, ...]] = []
        self.position = 0

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, _parameters: object = None) -> None:
        self.position = 0
        if "SELECT DISTINCT domain" in query:
            self.result = [(PRIMARY_DOMAIN,)]
        elif "SELECT fileID" in query:
            self.result = list(self.rows)
        else:
            raise AssertionError("unexpected synthetic manifest query")

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        batch = self.result[self.position : self.position + size]
        self.position += len(batch)
        return list(batch)


class _FilePlist:
    def __init__(self, value: dict[str, object]) -> None:
        self.filesize = int(value["filesize"])
        self.encryption_key = b"wrapped"
        self.protection_class = 1
        self.mtime = 1_700_000_000


class _Keybag:
    def unwrapKeyForClass(self, _protection_class: object, _wrapped: object) -> bytes:
        return b"K" * 32


class _EndToEndBackup:
    def __init__(
        self,
        *,
        backup_directory: str,
        passphrase: str,
        rows: list[tuple[Any, ...]],
        plaintext: dict[str, bytes],
    ) -> None:
        if passphrase != "synthetic passphrase":
            raise AssertionError("service changed the passphrase")
        self.backup_directory = Path(backup_directory)
        self.rows = rows
        self.plaintext = plaintext
        self._passphrase = passphrase.encode()
        self._keybag = _Keybag()
        self._manifest_plist = {"synthetic": True}
        self._temporary_folder = tempfile.mkdtemp(prefix="e2e-dependency-")
        self._temp_decrypted_manifest_db_path = str(Path(self._temporary_folder) / "Manifest.db")
        self._temp_manifest_db_conn = None
        self.cleanup_calls = 0

    def _read_and_unlock_keybag(self) -> None:
        self._manifest_plist = {"ManifestKey": struct.pack("<l", 1) + b"wrapped"}

    def test_decryption(self) -> None:
        return None

    def manifest_db_cursor(self) -> _Cursor:
        return _Cursor(self.rows)

    def _decrypt_file_to_disk(
        self,
        *,
        file_id: str,
        key: bytes,
        file_plist: _FilePlist,
        output_filepath: str,
    ) -> None:
        raise AssertionError("the dependency path-only writer must not be called")

    def _cleanup(self) -> None:
        self.cleanup_calls += 1
        shutil.rmtree(self._temporary_folder)


def _write_completed_encrypted_backup(base: Path) -> Path:
    from Crypto.Cipher import AES

    backup = base / "backup"
    backup.mkdir()
    with (backup / "Manifest.plist").open("wb") as handle:
        plistlib.dump(
            {"IsEncrypted": True, "Date": datetime(2025, 1, 1, tzinfo=timezone.utc)},
            handle,
        )
    plaintext_manifest = base / "synthetic-manifest.db"
    connection = sqlite3.connect(plaintext_manifest)
    try:
        connection.execute(
            "CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, "
            "flags INTEGER, file BLOB)"
        )
        connection.execute(
            "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
            ("0" * 40, PRIMARY_DOMAIN, "Documents/synthetic.db", 1, b"synthetic"),
        )
        connection.commit()
    finally:
        connection.close()
    manifest_bytes = plaintext_manifest.read_bytes()
    plaintext_manifest.unlink()
    if len(manifest_bytes) % 16:
        raise AssertionError("synthetic SQLite manifest was not block aligned")
    (backup / "Manifest.db").write_bytes(
        AES.new(b"K" * 32, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(manifest_bytes)
    )
    with (backup / "Status.plist").open("wb") as handle:
        plistlib.dump(
            {
                "SnapshotState": "finished",
                "Date": datetime(2025, 1, 1, tzinfo=timezone.utc),
            },
            handle,
        )
    return backup


def _tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        for name in (*directory_names, *file_names):
            path = Path(current) / name
            metadata = path.stat(follow_symlinks=False)
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(str(metadata.st_mode).encode())
            digest.update(str(metadata.st_size).encode())
            digest.update(str(metadata.st_mtime_ns).encode())
            if stat.S_ISREG(metadata.st_mode):
                digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _frame(value: object) -> bytes:
    encoded = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack(">I", len(encoded)) + encoded


class RecoveryServiceEndToEndTests(unittest.TestCase):
    def test_full_synthetic_recovery_runs_extraction_analysis_report_and_atomic_markers(
        self,
    ) -> None:
        from Crypto.Cipher import AES

        with tempfile.TemporaryDirectory() as temporary:
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
                padding_size = 16 - len(payload) % 16
                encrypted.write_bytes(
                    AES.new(b"K" * 32, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(
                        payload + bytes([padding_size]) * padding_size
                    )
                )

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

            before = _tree_fingerprint(backup)
            events: list[RecoveryEvent] = []
            destination_parent = base / "acl-destination"
            destination_parent.mkdir(mode=0o700)
            if sys.platform == "darwin":
                subprocess.run(
                    [
                        "/bin/chmod",
                        "+a",
                        "everyone allow read,write,file_inherit,directory_inherit",
                        str(destination_parent),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            destination_descriptor: int | None = None
            destination_identity: DestinationDirectoryIdentity | None = None
            if os.name != "nt":
                destination_descriptor = os.open(
                    destination_parent,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
                )
                destination_metadata = os.fstat(destination_descriptor)
                destination_identity = DestinationDirectoryIdentity(
                    device=int(destination_metadata.st_dev),
                    inode=int(destination_metadata.st_ino),
                )
            request = RecoveryRequest(
                backup_directory=backup,
                output_directory=destination_parent / "private-output",
                acknowledge_sensitive_output=True,
                destination_parent_identity=destination_identity,
            )
            try:
                with mock.patch(
                    "tvtime_extractor.service.extract_backup", side_effect=patched_extract
                ):
                    result = RecoveryService().recover(
                        request,
                        passphrase="synthetic passphrase",
                        progress=events.append,
                        destination_parent_descriptor=destination_descriptor,
                    )
            finally:
                if destination_descriptor is not None:
                    os.close(destination_descriptor)
            after = _tree_fingerprint(backup)

            extraction = result.extraction.extraction_root
            self.assertEqual(before, after)
            self.assertEqual(result.extraction.summary["files_expected"], len(rows))
            self.assertEqual(result.extraction.summary["files_extracted"], len(rows))
            self.assertEqual(result.extraction.summary["failures"], [])
            self.assertEqual(result.analysis["series_library"], 1)
            self.assertEqual(result.analysis["watched_movies"], 1)
            self.assertEqual(result.report["pdf_status"], "generated")
            run_state = json.loads((extraction / "metadata" / "run_state.json").read_text())
            self.assertEqual(run_state["schema_version"], 2)
            self.assertEqual(run_state["contract"], "tvtime-extraction-run-state-v0.2")
            self.assertEqual(run_state["status"], "complete")
            self.assertEqual(run_state["files_expected"], len(rows))
            self.assertEqual(run_state["files_extracted"], len(rows))
            self.assertEqual(
                run_state["bytes_extracted"], result.extraction.summary["bytes_extracted"]
            )
            recovery_state = json.loads(
                (extraction / "analysis" / "recovery_state.json").read_text()
            )
            self.assertEqual(recovery_state["schema_version"], 2)
            self.assertEqual(recovery_state["contract"], "tvtime-recovery-state-v0.2")
            self.assertEqual(recovery_state["status"], "complete")
            self.assertEqual(
                recovery_state["aggregates"]["extraction"]["files_extracted"],
                len(rows),
            )
            self.assertFalse((extraction / ".tmp").exists())
            self.assertFalse((extraction / ".analysis-incomplete").exists())
            self.assertFalse((extraction / ".report-incomplete").exists())
            self.assertIsNone(instances[0]._temp_manifest_db_conn)
            self.assertEqual(instances[0].cleanup_calls, 1)
            completed_stages = [
                event.stage.value for event in events if event.kind.value == "completed"
            ]
            self.assertEqual(
                completed_stages,
                ["preflight", "extraction", "analysis", "report", "complete"],
            )
            if sys.platform == "darwin":
                output_root = extraction.parent

                def assert_acl_free(path: Path, *, is_directory: bool) -> None:
                    flags = (
                        getattr(
                            os,
                            "O_SEARCH",
                            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                        )
                        if is_directory
                        else os.O_RDONLY
                    )
                    flags |= getattr(os, "O_NOFOLLOW", 0)
                    descriptor = os.open(path, flags)
                    try:
                        self.assertEqual(
                            extended_acl_state(descriptor).entry_count,
                            0,
                            path.relative_to(output_root).as_posix() or ".",
                        )
                    finally:
                        os.close(descriptor)

                assert_acl_free(output_root, is_directory=True)
                for current, directory_names, file_names in os.walk(output_root):
                    for name in directory_names:
                        assert_acl_free(Path(current) / name, is_directory=True)
                    for name in file_names:
                        assert_acl_free(Path(current) / name, is_directory=False)

    def test_preflight_rejects_unencrypted_and_unfinished_backups(self) -> None:
        for encrypted, state, expected in (
            (False, "finished", BackupUnencryptedError),
            (True, "running", BackupUnfinishedError),
        ):
            with (
                self.subTest(encrypted=encrypted, state=state),
                tempfile.TemporaryDirectory() as td,
            ):
                base = Path(td)
                backup = _write_completed_encrypted_backup(base)
                with (backup / "Manifest.plist").open("wb") as handle:
                    plistlib.dump({"IsEncrypted": encrypted}, handle)
                with (backup / "Status.plist").open("wb") as handle:
                    plistlib.dump({"SnapshotState": state}, handle)
                request = RecoveryRequest(
                    backup_directory=backup,
                    output_directory=base / "fresh-output",
                )
                with self.assertRaises(expected):
                    RecoveryService().preflight(request)

    def test_same_service_can_consume_exact_preflight_without_rescanning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_completed_encrypted_backup(base)
            request = RecoveryRequest(
                backup_directory=backup,
                output_directory=base / "fresh-output",
                acknowledge_sensitive_output=True,
            )
            service = RecoveryService()
            with held_destination_parent(request.output_directory) as (
                descriptor,
                identity,
                visible_output,
            ):
                bound_request = replace(
                    request,
                    output_directory=visible_output,
                    destination_parent_identity=DestinationDirectoryIdentity(*identity),
                )
                preflight = service.preflight(
                    bound_request,
                    destination_parent_descriptor=descriptor,
                )
                sentinel = RecoveryResult(
                    preflight=preflight,
                    extraction=ExtractionResult(Path("TVTime-Extraction"), {}),
                    analysis={},
                    report={},
                )
                with (
                    mock.patch.object(
                        service,
                        "preflight",
                        side_effect=AssertionError("preflight unexpectedly repeated"),
                    ),
                    mock.patch(
                        "tvtime_extractor.service._run_recovery_stages",
                        return_value=sentinel,
                    ),
                    mock.patch(
                        "tvtime_extractor.service._visible_recovery_result",
                        side_effect=lambda result, _output: result,
                    ),
                ):
                    self.assertIs(
                        service.recover(
                            bound_request,
                            passphrase="synthetic",
                            destination_parent_descriptor=descriptor,
                            preflight_result=preflight,
                        ),
                        sentinel,
                    )

    def test_same_service_extract_consumes_receipt_and_passes_bound_source_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_completed_encrypted_backup(base)
            output = base / "fresh-output"
            request = RecoveryRequest(
                backup_directory=backup,
                output_directory=output,
                acknowledge_sensitive_output=True,
            )
            service = RecoveryService()
            captured: dict[str, object] = {}
            with held_destination_parent(output) as (descriptor, identity, visible_output):
                bound_request = replace(
                    request,
                    output_directory=visible_output,
                    destination_parent_identity=DestinationDirectoryIdentity(*identity),
                )
                preflight = service.preflight(
                    bound_request,
                    destination_parent_descriptor=descriptor,
                )
                expected_snapshot = service.preflight_receipt(preflight).snapshot

                def synthetic_extract(**kwargs: object) -> ExtractionResult:
                    source_descriptor = int(kwargs["source_root_descriptor"])
                    if os.name == "nt":
                        from tvtime_extractor.windows_native import handle_information

                        self.assertTrue(handle_information(source_descriptor).is_directory)
                    else:
                        self.assertTrue(stat.S_ISDIR(os.fstat(source_descriptor).st_mode))
                    captured.update(kwargs)
                    return ExtractionResult(
                        Path("TVTime-Extraction"),
                        {"files_extracted": 1, "files_expected": 1},
                    )

                with mock.patch(
                    "tvtime_extractor.service.extract_backup",
                    side_effect=synthetic_extract,
                ):
                    result = service.extract(
                        bound_request,
                        passphrase="synthetic",
                        destination_parent_descriptor=descriptor,
                        preflight_result=preflight,
                    )

            self.assertEqual(
                result.extraction_root,
                no_link_absolute_path(output) / "TVTime-Extraction",
            )
            self.assertEqual(
                captured["expected_backup_snapshot"],
                expected_snapshot,
            )
            self.assertTrue(captured["output_root_is_anchored"])

    def test_same_service_extract_rejects_backup_root_swap_before_output_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_completed_encrypted_backup(base)
            output = base / "fresh-output"
            request = RecoveryRequest(
                backup_directory=backup,
                output_directory=output,
                acknowledge_sensitive_output=True,
            )
            service = RecoveryService()
            with held_destination_parent(output) as (descriptor, identity, visible_output):
                bound_request = replace(
                    request,
                    output_directory=visible_output,
                    destination_parent_identity=DestinationDirectoryIdentity(*identity),
                )
                preflight = service.preflight(
                    bound_request,
                    destination_parent_descriptor=descriptor,
                )
                original_backup = base / "original-backup"
                backup.rename(original_backup)
                shutil.copytree(original_backup, backup)
                with (
                    mock.patch(
                        "tvtime_extractor.service.extract_backup",
                        side_effect=AssertionError("extraction must not start"),
                    ),
                    self.assertRaises(SourceChangedError),
                ):
                    service.extract(
                        bound_request,
                        passphrase="synthetic",
                        destination_parent_descriptor=descriptor,
                        preflight_result=preflight,
                    )
            self.assertFalse(output.exists())

    def test_preflight_receipt_revalidates_manifest_hash_before_output_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_completed_encrypted_backup(base)
            output = base / "fresh-output"
            request = RecoveryRequest(
                backup_directory=backup,
                output_directory=output,
                acknowledge_sensitive_output=True,
            )
            service = RecoveryService()
            with held_destination_parent(output) as (descriptor, identity, visible_output):
                bound_request = replace(
                    request,
                    output_directory=visible_output,
                    destination_parent_identity=DestinationDirectoryIdentity(*identity),
                )
                preflight = service.preflight(
                    bound_request,
                    destination_parent_descriptor=descriptor,
                )
                manifest_database = backup / "Manifest.db"
                original = manifest_database.read_bytes()
                manifest_database.write_bytes(original[::-1])
                with (
                    mock.patch(
                        "tvtime_extractor.service._run_recovery_stages",
                        side_effect=AssertionError("recovery stages must not start"),
                    ),
                    self.assertRaisesRegex(SourceChangedError, "changed after preflight"),
                ):
                    service.recover(
                        bound_request,
                        passphrase="synthetic",
                        destination_parent_descriptor=descriptor,
                        preflight_result=preflight,
                    )
            self.assertFalse(output.exists())

    def test_detached_native_receipt_rejects_backup_root_replacement_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_completed_encrypted_backup(base)
            output = base / "fresh-output"
            request = RecoveryRequest(
                backup_directory=backup,
                output_directory=output,
                acknowledge_sensitive_output=True,
            )
            preflight_service = RecoveryService()
            with held_destination_parent(output) as (descriptor, identity, visible_output):
                bound_request = replace(
                    request,
                    output_directory=visible_output,
                    destination_parent_identity=DestinationDirectoryIdentity(*identity),
                )
                preflight = preflight_service.preflight(
                    bound_request,
                    destination_parent_descriptor=descriptor,
                )
                receipt = preflight_service.preflight_receipt(preflight)

                original_backup = base / "original-backup"
                backup.rename(original_backup)
                shutil.copytree(original_backup, backup)
                recovery_request = replace(bound_request, backup_receipt=receipt)
                with (
                    mock.patch(
                        "tvtime_extractor.service._run_recovery_stages",
                        side_effect=AssertionError("recovery stages must not start"),
                    ),
                    self.assertRaisesRegex(SourceChangedError, "confirmed preflight receipt"),
                ):
                    RecoveryService().recover(
                        recovery_request,
                        passphrase="synthetic",
                        destination_parent_descriptor=descriptor,
                    )
            self.assertFalse(output.exists())

    def test_detached_native_receipt_allows_unchanged_source_and_rebases_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_completed_encrypted_backup(base)
            output = base / "fresh-output"
            request = RecoveryRequest(
                backup_directory=backup,
                output_directory=output,
                acknowledge_sensitive_output=True,
            )
            preflight_service = RecoveryService()
            with held_destination_parent(output) as (descriptor, identity, visible_output):
                bound_request = replace(
                    request,
                    output_directory=visible_output,
                    destination_parent_identity=DestinationDirectoryIdentity(*identity),
                )
                preflight = preflight_service.preflight(
                    bound_request,
                    destination_parent_descriptor=descriptor,
                )
                receipt = preflight_service.preflight_receipt(preflight)
                recovery_request = replace(bound_request, backup_receipt=receipt)

                def synthetic_recovery(*_args: object, **kwargs: object) -> RecoveryResult:
                    current_preflight = kwargs["preflight"]
                    assert isinstance(current_preflight, type(preflight))
                    return RecoveryResult(
                        preflight=current_preflight,
                        extraction=ExtractionResult(Path("TVTime-Extraction"), {}),
                        analysis={},
                        report={},
                    )

                with mock.patch(
                    "tvtime_extractor.service._run_recovery_stages",
                    side_effect=synthetic_recovery,
                ):
                    result = RecoveryService().recover(
                        recovery_request,
                        passphrase="synthetic",
                        destination_parent_descriptor=descriptor,
                    )

            self.assertEqual(
                result.extraction.extraction_root,
                no_link_absolute_path(output) / "TVTime-Extraction",
            )
            self.assertTrue(output.is_dir())

    @unittest.skipIf(os.name == "nt", "Windows holds the source root without delete sharing")
    def test_source_root_swap_after_revalidation_stops_before_output_or_stages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_completed_encrypted_backup(base)
            output = base / "fresh-output"
            request = RecoveryRequest(
                backup_directory=backup,
                output_directory=output,
                acknowledge_sensitive_output=True,
            )
            service = RecoveryService()
            with held_destination_parent(output) as (descriptor, identity, visible_output):
                bound_request = replace(
                    request,
                    output_directory=visible_output,
                    destination_parent_identity=DestinationDirectoryIdentity(*identity),
                )
                preflight = service.preflight(
                    bound_request,
                    destination_parent_descriptor=descriptor,
                )

                @contextmanager
                def swap_before_output(*_args: object, **_kwargs: object) -> object:
                    moved = base / "original-backup"
                    backup.rename(moved)
                    shutil.copytree(moved, backup)
                    yield Path(".")

                with (
                    mock.patch(
                        "tvtime_extractor.service.anchored_bound_output_root",
                        side_effect=swap_before_output,
                    ),
                    mock.patch(
                        "tvtime_extractor.service._run_recovery_stages",
                        side_effect=AssertionError("recovery stages must not start"),
                    ),
                    self.assertRaisesRegex(SourceChangedError, "backup root changed"),
                ):
                    service.recover(
                        bound_request,
                        passphrase="synthetic",
                        destination_parent_descriptor=descriptor,
                        preflight_result=preflight,
                    )
            self.assertFalse(output.exists())

    def test_preflight_rejects_oversized_plist_before_output_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_completed_encrypted_backup(base)
            output = base / "fresh-output"
            request = RecoveryRequest(backup_directory=backup, output_directory=output)
            with (
                mock.patch("tvtime_extractor.service.MAXIMUM_MANIFEST_PLIST_BYTES", 8),
                self.assertRaisesRegex(UserInputError, "unsafe byte size"),
            ):
                RecoveryService().preflight(request)
            self.assertFalse(output.exists())

    def test_detached_public_preflight_receipt_is_rejected_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            request = RecoveryRequest(
                backup_directory=_write_completed_encrypted_backup(base),
                output_directory=base / "fresh-output",
                acknowledge_sensitive_output=True,
            )
            service = RecoveryService()
            preflight = service.preflight(request)
            with self.assertRaisesRegex(UserInputError, "exact destination-parent handle"):
                service.recover(
                    request,
                    passphrase="synthetic",
                    preflight_result=preflight,
                )

    def test_preflight_receipt_is_identity_bound_and_single_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_completed_encrypted_backup(base)
            request = RecoveryRequest(
                backup_directory=backup,
                output_directory=base / "fresh-output",
                acknowledge_sensitive_output=True,
            )
            service = RecoveryService()
            with held_destination_parent(request.output_directory) as (
                descriptor,
                identity,
                visible_output,
            ):
                bound_request = replace(
                    request,
                    output_directory=visible_output,
                    destination_parent_identity=DestinationDirectoryIdentity(*identity),
                )
                preflight = service.preflight(
                    bound_request,
                    destination_parent_descriptor=descriptor,
                )
                with self.assertRaisesRegex(UserInputError, "same service instance"):
                    service.recover(
                        bound_request,
                        passphrase="synthetic",
                        destination_parent_descriptor=descriptor,
                        preflight_result=replace(preflight),
                    )

                # A failed forged receipt does not consume the real prepared result.
                sentinel = RecoveryResult(
                    preflight=preflight,
                    extraction=ExtractionResult(Path("TVTime-Extraction"), {}),
                    analysis={},
                    report={},
                )
                with (
                    mock.patch(
                        "tvtime_extractor.service._run_recovery_stages",
                        return_value=sentinel,
                    ),
                    mock.patch(
                        "tvtime_extractor.service._visible_recovery_result",
                        side_effect=lambda result, _output: result,
                    ),
                ):
                    service.recover(
                        bound_request,
                        passphrase="synthetic",
                        destination_parent_descriptor=descriptor,
                        preflight_result=preflight,
                    )
                with self.assertRaisesRegex(UserInputError, "same service instance"):
                    service.recover(
                        bound_request,
                        passphrase="synthetic",
                        destination_parent_descriptor=descriptor,
                        preflight_result=preflight,
                    )

    def test_recovery_requires_sensitive_output_acknowledgement(self) -> None:
        request = RecoveryRequest(Path("backup"), Path("output"))
        with self.assertRaisesRegex(UserInputError, "private encrypted storage"):
            RecoveryService().recover(request, passphrase="synthetic")

    def test_sealed_recovery_rejects_advanced_unbound_exports_before_preflight(self) -> None:
        for request in (
            RecoveryRequest(
                Path("backup"),
                Path("output"),
                acknowledge_sensitive_output=True,
                include_raw_cache=True,
            ),
            RecoveryRequest(
                Path("backup"),
                Path("output"),
                acknowledge_sensitive_output=True,
                include_decrypted_manifest=True,
            ),
        ):
            with (
                self.subTest(request=request),
                self.assertRaisesRegex(UserInputError, "privacy-preserving defaults"),
            ):
                RecoveryService().recover(request, passphrase="synthetic")


class HelperProtocolTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "The native helper descriptor contract is POSIX-only")
    def test_helper_holds_bound_destination_descriptor_and_closes_reserved_fd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            metadata = parent.stat()
            expected = DestinationDirectoryIdentity(
                device=int(metadata.st_dev),
                inode=int(metadata.st_ino),
            )
            saved_reserved: int | None
            try:
                saved_reserved = os.dup(DESTINATION_PARENT_FILE_DESCRIPTOR)
            except OSError:
                saved_reserved = None
            source = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            held = -1
            try:
                if source != DESTINATION_PARENT_FILE_DESCRIPTOR:
                    os.dup2(source, DESTINATION_PARENT_FILE_DESCRIPTOR, inheritable=True)
                    os.close(source)
                source = -1
                held = _hold_destination_parent_descriptor(expected)
                self.assertFalse(os.get_inheritable(held))
                self.assertTrue(stat.S_ISDIR(os.fstat(held).st_mode))
                with self.assertRaises(OSError):
                    os.fstat(DESTINATION_PARENT_FILE_DESCRIPTOR)
            finally:
                if source >= 0:
                    os.close(source)
                if held >= 0:
                    os.close(held)
                if saved_reserved is None:
                    with suppress(OSError):
                        os.close(DESTINATION_PARENT_FILE_DESCRIPTOR)
                else:
                    os.dup2(saved_reserved, DESTINATION_PARENT_FILE_DESCRIPTOR)
                    os.close(saved_reserved)

    @unittest.skipIf(os.name == "nt", "The native helper descriptor contract is POSIX-only")
    def test_helper_identity_mismatch_closes_duplicated_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            metadata = parent.stat()
            wrong = DestinationDirectoryIdentity(
                device=int(metadata.st_dev),
                inode=int(metadata.st_ino) + 1,
            )
            saved_reserved: int | None
            try:
                saved_reserved = os.dup(DESTINATION_PARENT_FILE_DESCRIPTOR)
            except OSError:
                saved_reserved = None
            source = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            duplicated: list[int] = []
            real_dup = os.dup

            def tracked_dup(descriptor: int) -> int:
                result = real_dup(descriptor)
                duplicated.append(result)
                return result

            try:
                if source != DESTINATION_PARENT_FILE_DESCRIPTOR:
                    os.dup2(source, DESTINATION_PARENT_FILE_DESCRIPTOR, inheritable=True)
                    os.close(source)
                source = -1
                with (
                    mock.patch("tvtime_extractor.helper_main.os.dup", side_effect=tracked_dup),
                    self.assertRaises(UserInputError),
                ):
                    _hold_destination_parent_descriptor(wrong)
                self.assertEqual(len(duplicated), 1)
                with self.assertRaises(OSError):
                    os.fstat(duplicated[0])
                with self.assertRaises(OSError):
                    os.fstat(DESTINATION_PARENT_FILE_DESCRIPTOR)
            finally:
                if source >= 0:
                    os.close(source)
                if saved_reserved is None:
                    with suppress(OSError):
                        os.close(DESTINATION_PARENT_FILE_DESCRIPTOR)
                else:
                    os.dup2(saved_reserved, DESTINATION_PARENT_FILE_DESCRIPTOR)
                    os.close(saved_reserved)

    def test_recovery_request_strictly_validates_destination_identity(self) -> None:
        payload: dict[str, object] = {
            "backup_directory": "/synthetic/backup",
            "output_directory": "/synthetic/output",
            "destination_parent_identity": {"device": 7, "inode": 11},
            "acknowledge_sensitive_output": False,
            "include_raw_cache": False,
            "include_decrypted_manifest": False,
            "backup_receipt": None,
        }
        request = RecoveryRequest.from_dict(payload)
        self.assertEqual(
            request.destination_parent_identity,
            DestinationDirectoryIdentity(device=7, inode=11),
        )
        for invalid in (
            {"device": True, "inode": 11},
            {"device": 7},
            {"device": 7, "inode": -1},
            {"device": 7, "inode": 11, "extra": 12},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(UserInputError):
                RecoveryRequest.from_dict({**payload, "destination_parent_identity": invalid})
        for invalid_receipt in ({}, True, {"contract": "unexpected"}):
            with self.subTest(invalid_receipt=invalid_receipt), self.assertRaises(UserInputError):
                RecoveryRequest.from_dict({**payload, "backup_receipt": invalid_receipt})

    def test_control_request_and_writer_enforce_version_shape_and_sequence(self) -> None:
        request = {
            "protocolVersion": PROTOCOL_VERSION,
            "type": "preflight",
            "payload": {
                "backup_directory": "/synthetic/backup",
                "output_directory": "/synthetic/output",
                "destination_parent_identity": {"device": 7, "inode": 11},
                "acknowledge_sensitive_output": False,
                "include_raw_cache": False,
                "include_decrypted_manifest": False,
                "backup_receipt": None,
            },
        }
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, _frame(request))
        os.close(write_descriptor)
        with os.fdopen(read_descriptor, "rb") as stream:
            parsed = read_control_request(stream)
        self.assertEqual(parsed.action, "preflight")
        self.assertEqual(parsed.payload, request["payload"])

        with tempfile.SpooledTemporaryFile(mode="w+") as output:
            writer = ProtocolWriter(output)
            writer.write("ready", {"message": "synthetic"})
            writer.write("completed", {"ok": True})
            output.seek(0)
            frames = [json.loads(line) for line in output]
        self.assertEqual([frame["sequence"] for frame in frames], [1, 2])
        self.assertEqual([frame["type"] for frame in frames], ["ready", "completed"])

    def test_control_request_rejects_unknown_fields(self) -> None:
        request = {
            "protocolVersion": PROTOCOL_VERSION,
            "type": "preflight",
            "payload": {
                "backup_directory": "/synthetic/backup",
                "output_directory": "/synthetic/output",
                "destination_parent_identity": {"device": 7, "inode": 11},
                "acknowledge_sensitive_output": False,
                "include_raw_cache": False,
                "include_decrypted_manifest": False,
                "backup_receipt": None,
                "unexpected_option": True,
            },
        }
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, _frame(request))
        os.close(write_descriptor)
        with os.fdopen(read_descriptor, "rb") as stream, self.assertRaises(ProtocolError):
            read_control_request(stream)

    @unittest.skipIf(os.name == "nt", "The native macOS helper uses inherited POSIX descriptors")
    def test_helper_subprocess_preflight_emits_only_sequenced_protocol_frames(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_completed_encrypted_backup(base)
            parent_metadata = base.stat()
            request = {
                "protocolVersion": PROTOCOL_VERSION,
                "type": "preflight",
                "payload": {
                    "backup_directory": str(backup),
                    "output_directory": str(base / "fresh-output"),
                    "destination_parent_identity": {
                        "device": int(parent_metadata.st_dev),
                        "inode": int(parent_metadata.st_ino),
                    },
                    "acknowledge_sensitive_output": False,
                    "include_raw_cache": False,
                    "include_decrypted_manifest": False,
                    "backup_receipt": None,
                },
            }
            try:
                original_inheritable = os.get_inheritable(DESTINATION_PARENT_FILE_DESCRIPTOR)
            except OSError:
                saved_reserved = -1
                original_inheritable = False
            else:
                saved_reserved = os.dup(DESTINATION_PARENT_FILE_DESCRIPTOR)
            source_descriptor = -1
            try:
                source_descriptor = os.open(
                    base,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
                )
                if source_descriptor != DESTINATION_PARENT_FILE_DESCRIPTOR:
                    os.dup2(
                        source_descriptor,
                        DESTINATION_PARENT_FILE_DESCRIPTOR,
                        inheritable=True,
                    )
                    os.close(source_descriptor)
                source_descriptor = -1
                process = subprocess.Popen(
                    [sys.executable, "-m", "tvtime_extractor.helper_main"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                    pass_fds=(DESTINATION_PARENT_FILE_DESCRIPTOR,),
                )
            finally:
                if source_descriptor >= 0:
                    os.close(source_descriptor)
                if saved_reserved < 0:
                    with suppress(OSError):
                        os.close(DESTINATION_PARENT_FILE_DESCRIPTOR)
                else:
                    os.dup2(
                        saved_reserved,
                        DESTINATION_PARENT_FILE_DESCRIPTOR,
                        inheritable=original_inheritable,
                    )
                    os.close(saved_reserved)

            def cleanup_process() -> None:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                for stream in (process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()

            self.addCleanup(cleanup_process)
            assert process.stdin is not None
            assert process.stdout is not None
            events: queue.Queue[bytes] = queue.Queue()

            def read_output() -> None:
                for line in process.stdout:
                    events.put(line)

            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            process.stdin.write(_frame(request))
            process.stdin.flush()
            frames: list[dict[str, object]] = []
            while True:
                line = events.get(timeout=10)
                frame = json.loads(line)
                frames.append(frame)
                if frame["type"] in {"completed", "failed", "cancelled"}:
                    break
            process.stdin.close()
            return_code = process.wait(timeout=10)
            reader.join(timeout=2)
            stderr = process.stderr.read() if process.stderr is not None else b""
            process.stdout.close()
            process.stderr.close()

            self.assertEqual(return_code, 0, stderr.decode(errors="replace"))
            self.assertEqual(stderr, b"")
            self.assertEqual(frames[0]["type"], "ready")
            self.assertEqual(frames[-1]["type"], "completed")
            self.assertEqual(
                [frame["sequence"] for frame in frames],
                list(range(1, len(frames) + 1)),
            )
            encoded = json.dumps(frames)
            self.assertNotIn(str(backup), encoded)
            terminal_payload = frames[-1]["payload"]
            self.assertEqual(terminal_payload["preflight"]["snapshot_state"], "finished")
            receipt = terminal_payload["backup_receipt"]
            self.assertEqual(receipt["schema_version"], 1)
            self.assertEqual(
                receipt["contract"],
                "tvtime-backup-preflight-receipt-v0.2",
            )
            self.assertEqual(
                receipt["backup_regular_files"],
                terminal_payload["preflight"]["backup_regular_files"],
            )
            self.assertEqual(
                receipt["backup_logical_bytes"],
                terminal_payload["preflight"]["backup_logical_bytes"],
            )

    def test_protocol_summary_uses_relative_artifacts_and_optional_pdf_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            template = create_synthetic_extraction(base)
            # Reuse a real analysis/report result without exposing its local paths.
            from tvtime_extractor.analyze import analyze_extraction
            from tvtime_extractor.extract import ExtractionResult
            from tvtime_extractor.models import PreflightResult, RecoveryResult
            from tvtime_extractor.report import build_report

            analysis = analyze_extraction(extraction_directory=template)
            report = build_report(extraction_directory=template)
            extraction_summary = {
                "files_expected": 1,
                "files_extracted": 1,
                "bytes_extracted": 1,
                "selected_declared_bytes": 1,
                "size_discrepancies": [],
                "failures": [],
            }
            recovery = RecoveryResult(
                preflight=PreflightResult(True, "finished", "", 1, 1, 1, 1, 1),
                extraction=ExtractionResult(template, extraction_summary),
                analysis=analysis,
                report=report,
            )
            generated = _protocol_summary(recovery)
            omitted = _protocol_summary(
                replace(
                    recovery,
                    report={
                        **report,
                        "pdf_status": "omitted",
                        "pdf_warning": "PDF omitted for synthetic fidelity.",
                        "pdf_report": "",
                    },
                )
            )

            self.assertEqual(
                generated["artifacts"]["recovery_state"],
                "TVTime-Extraction/analysis/recovery_state.json",
            )
            self.assertNotIn("pdf_omission_reason", generated["report"])
            self.assertEqual(
                omitted["report"]["pdf_omission_reason"],
                "PDF omitted for synthetic fidelity.",
            )
            self.assertNotIn("pdf_report", omitted["artifacts"])
            self.assertNotIn(str(base), json.dumps(generated))
            self.assertNotIn(str(base), json.dumps(omitted))

    def test_error_payload_is_allowlisted_and_does_not_expose_exception_text(self) -> None:
        event_type, payload, exit_code = _safe_error_payload(
            UserInputError("private path and secret must not escape")
        )
        self.assertEqual(event_type, "failed")
        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["code"], "invalid_input")
        self.assertNotIn("private path", json.dumps(payload))
        self.assertNotIn("secret", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
