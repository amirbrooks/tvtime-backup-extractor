from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import plistlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from tvtime_extractor.errors import (
    BackupUnfinishedError,
    SourceChangedError,
    TVTimeError,
    UnsafePathError,
)
from tvtime_extractor.extract import (
    PRIMARY_DOMAIN,
    _bounded_manifest_rows,
    _create_private_staging_descriptor,
    _finished_status_state,
    _harden_private_staging_descriptor,
    _sha256_staging_descriptor,
    _source_payload_state,
    _verified_dependency_output_alias,
    extract_backup,
)
from tvtime_extractor.report import read_csv
from tvtime_extractor.safety import (
    read_json_regular,
    regular_text_reader,
    write_csv_private,
    write_json_private_atomic,
)


class _Connection:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.closed = False

    def close(self) -> None:
        self.closed = True
        if self.fail:
            raise OSError("synthetic close failure")


class _Keybag:
    def unwrapKeyForClass(self, _protection_class: object, _wrapped_key: object) -> bytes:
        return b"synthetic-unwrapped-key"


class _FilePlist:
    def __init__(self, value: dict[str, Any]) -> None:
        self.filesize = value["filesize"]
        self.encryption_key = (
            b"wrapped"
            if isinstance(self.filesize, int)
            and not isinstance(self.filesize, bool)
            and self.filesize > 0
            else None
        )
        self.protection_class = 1
        self.mtime = 1_700_000_000


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
            self.result = self.rows
        else:
            raise AssertionError("unexpected synthetic manifest query")

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        batch = self.result[self.position : self.position + size]
        self.position += len(batch)
        return list(batch)


class _CleanupBackup:
    def __init__(
        self,
        *,
        backup_directory: str,
        passphrase: str,
        rows: list[tuple[Any, ...]],
        plaintext: dict[str, bytes],
        close_fails: bool,
        cleanup_fails: bool,
        decryption_fails: bool,
        mutate_status_path: Path | None,
    ) -> None:
        print("dependency constructor private path")
        self.backup_directory = Path(backup_directory)
        self.rows = rows
        self.plaintext = plaintext
        self.close_fails = close_fails
        self.cleanup_fails = cleanup_fails
        self.decryption_fails = decryption_fails
        self.mutate_status_path = mutate_status_path
        self._passphrase = passphrase.encode()
        self._keybag = _Keybag()
        self._manifest_plist = {"private": True}
        self._temporary_folder = tempfile.mkdtemp(prefix="dependency-private-")
        self._temp_decrypted_manifest_db_path = str(Path(self._temporary_folder) / "Manifest.db")
        Path(self._temp_decrypted_manifest_db_path).write_bytes(b"private manifest")
        self.connection = _Connection(fail=close_fails)
        self._temp_manifest_db_conn = self.connection
        self.cleanup_calls = 0
        self.run_state_at_cleanup = ""
        self.decrypted_from_private_snapshot = False

    def test_decryption(self) -> None:
        print("dependency test private path", file=os.sys.stderr)
        if self.decryption_fails:
            raise RuntimeError("original synthetic decryption failure")

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
        self.assert_key(key)
        source = Path(self._backup_directory) / file_id[:2] / file_id
        self.decrypted_from_private_snapshot = (
            source.is_file()
            and source.parent.parent != self.backup_directory
            and source.read_bytes() == b"synthetic encrypted payload"
        )
        if not self.decrypted_from_private_snapshot:
            raise AssertionError("decryption did not use the verified private source snapshot")
        print(f"dependency output path: {output_filepath}")
        Path(output_filepath).write_bytes(self.plaintext[file_id])

    @staticmethod
    def assert_key(key: bytes) -> None:
        if key != b"synthetic-unwrapped-key":
            raise AssertionError("unexpected synthetic key")

    def _cleanup(self) -> None:
        self.cleanup_calls += 1
        print(f"dependency cleanup path: {self._temp_decrypted_manifest_db_path}")
        marker = Path(self._temporary_folder).parent.parent / "metadata" / "run_state.json"
        if marker.is_file():
            self.run_state_at_cleanup = str(json.loads(marker.read_text())["status"])
        shutil.rmtree(self._temporary_folder)
        if self.mutate_status_path is not None:
            with self.mutate_status_path.open("wb") as handle:
                plistlib.dump({"SnapshotState": "running"}, handle)
        if self.cleanup_fails:
            raise OSError("synthetic cleanup failure")


class ManifestBoundsTests(unittest.TestCase):
    class Cursor:
        def __init__(self, rows: list[tuple[object, ...]]) -> None:
            self.rows = rows
            self.position = 0
            self.fetch_sizes: list[int] = []

        def fetchmany(self, size: int) -> list[tuple[object, ...]]:
            self.fetch_sizes.append(size)
            batch = self.rows[self.position : self.position + size]
            self.position += len(batch)
            return batch

        def fetchall(self) -> list[tuple[object, ...]]:
            raise AssertionError("unbounded fetchall must never be used")

    def test_manifest_cursor_is_streamed_with_row_cell_and_combined_bounds(self) -> None:
        cases = (
            ([("a",), ("b",)], 1, 10, 100, "row limit"),
            ([("too-long",)], 10, 4, 100, "metadata value"),
            ([("1234",), ("5678",)], 10, 10, 6, "byte limit"),
            ([(object(),)], 10, 100, 100, "unsupported metadata value"),
        )
        for rows, row_limit, cell_limit, combined_limit, message in cases:
            with (
                self.subTest(message=message),
                mock.patch("tvtime_extractor.extract.MAXIMUM_MANIFEST_CELL_BYTES", cell_limit),
                mock.patch(
                    "tvtime_extractor.extract.MAXIMUM_MANIFEST_COMBINED_BYTES",
                    combined_limit,
                ),
            ):
                cursor = self.Cursor(rows)
                with self.assertRaisesRegex(TVTimeError, message):
                    _bounded_manifest_rows(
                        cursor,
                        expected_columns=1,
                        maximum_rows=row_limit,
                        validate_row=lambda _row: None,
                    )
                self.assertTrue(cursor.fetch_sizes)


@unittest.skipUnless(
    sys.platform == "darwin" or sys.platform.startswith("linux"),
    "descriptor aliases are supported only by the macOS/Linux recovery path",
)
class DependencyDescriptorBindingTests(unittest.TestCase):
    def test_pinned_cbc_dependency_writes_through_exact_held_descriptor(self) -> None:
        from importlib.metadata import version

        from Crypto.Cipher import AES
        from iphone_backup_decrypt import utils

        self.assertEqual(version("iphone-backup-decrypt"), "0.9.0")
        plaintext = b"descriptor-bound synthetic plaintext"
        padding_size = 16 - len(plaintext) % 16
        encryption_key = b"K" * 32
        encrypted = AES.new(
            encryption_key,
            AES.MODE_CBC,
            iv=b"\x00" * 16,
        ).encrypt(plaintext + bytes([padding_size]) * padding_size)

        class FilePlist:
            filesize = len(plaintext)
            mtime = 1_700_000_000

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            encrypted_path = root / "encrypted.bin"
            encrypted_path.write_bytes(encrypted)
            staging = root / "plaintext.partial"
            descriptor, identity = _create_private_staging_descriptor(staging)
            try:
                alias = _verified_dependency_output_alias(
                    staging,
                    descriptor,
                    expected_identity=identity,
                )
                utils.aes_decrypt_chunked(
                    in_filename=str(encrypted_path),
                    file_plist=FilePlist(),
                    key=encryption_key,
                    out_filepath=alias,
                )
                _harden_private_staging_descriptor(
                    staging,
                    descriptor,
                    expected_identity=identity,
                )
                actual_size, actual_hash = _sha256_staging_descriptor(
                    staging,
                    descriptor,
                    expected_identity=identity,
                )

                self.assertEqual(os.pread(descriptor, len(plaintext), 0), plaintext)
                self.assertEqual(actual_size, len(plaintext))
                self.assertEqual(actual_hash, hashlib.sha256(plaintext).hexdigest())
                self.assertEqual(
                    (staging.stat().st_dev, staging.stat().st_ino),
                    identity,
                )
                self.assertEqual(staging.stat().st_mtime, FilePlist.mtime)
            finally:
                os.close(descriptor)

    def test_visible_staging_substitution_cannot_redirect_dependency_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            staging = root / "plaintext.partial"
            moved = root / "held-plaintext.partial"
            outside = root / "outside.bin"
            outside.write_bytes(b"unchanged")
            descriptor, identity = _create_private_staging_descriptor(staging)
            try:
                alias = _verified_dependency_output_alias(
                    staging,
                    descriptor,
                    expected_identity=identity,
                )
                staging.rename(moved)
                staging.symlink_to(outside)
                Path(alias).write_bytes(b"descriptor-only secret")

                self.assertEqual(outside.read_bytes(), b"unchanged")
                self.assertEqual(
                    os.pread(descriptor, len(b"descriptor-only secret"), 0),
                    b"descriptor-only secret",
                )
                with self.assertRaisesRegex(UnsafePathError, "identity changed"):
                    _harden_private_staging_descriptor(
                        staging,
                        descriptor,
                        expected_identity=identity,
                    )
            finally:
                os.close(descriptor)


def _write_backup(base: Path, *, snapshot_state: str = "finished") -> Path:
    backup = base / "backup"
    backup.mkdir()
    (backup / "Manifest.plist").write_bytes(b"synthetic manifest")
    (backup / "Manifest.db").write_bytes(b"synthetic encrypted manifest")
    with (backup / "Status.plist").open("wb") as handle:
        plistlib.dump({"SnapshotState": snapshot_state}, handle)
    return backup


def _row(
    backup: Path, *, plaintext: bytes = b"recovered"
) -> tuple[list[tuple[Any, ...]], dict[str, bytes]]:
    file_id = "a" * 40
    encrypted = backup / file_id[:2] / file_id
    encrypted.parent.mkdir()
    encrypted.write_bytes(b"synthetic encrypted payload")
    return (
        [
            (
                file_id,
                PRIMARY_DOMAIN,
                "Documents/recovered.bin",
                {"filesize": len(plaintext)},
            )
        ],
        {file_id: plaintext},
    )


def _loader(
    instances: list[_CleanupBackup],
    *,
    rows: list[tuple[Any, ...]],
    plaintext: dict[str, bytes],
    close_fails: bool = False,
    cleanup_fails: bool = False,
    decryption_fails: bool = False,
    mutate_status_path: Path | None = None,
) -> object:
    def load() -> tuple[object, type[_FilePlist]]:
        def factory(*, backup_directory: str, passphrase: str) -> _CleanupBackup:
            instance = _CleanupBackup(
                backup_directory=backup_directory,
                passphrase=passphrase,
                rows=rows,
                plaintext=plaintext,
                close_fails=close_fails,
                cleanup_fails=cleanup_fails,
                decryption_fails=decryption_fails,
                mutate_status_path=mutate_status_path,
            )
            instances.append(instance)
            return instance

        return factory, _FilePlist

    return load


class AtomicAndInputSafetyTests(unittest.TestCase):
    def test_atomic_json_failure_preserves_previous_marker_and_cleans_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "run_state.json"
            write_json_private_atomic(marker, {"status": "incomplete"})

            def stop_before_commit() -> None:
                raise RuntimeError("synthetic interruption")

            with self.assertRaisesRegex(RuntimeError, "synthetic interruption"):
                write_json_private_atomic(
                    marker,
                    {"status": "complete"},
                    before_replace=stop_before_commit,
                )

            self.assertEqual(read_json_regular(marker)["status"], "incomplete")
            self.assertEqual(list(root.glob(".*.partial")), [])

    def test_regular_readers_and_report_csv_refuse_symbolic_links(self) -> None:
        if os.name == "nt":
            self.skipTest("symbolic-link creation varies on Windows")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.csv"
            write_csv_private(target, [{"name": "safe"}], ["name"])
            linked = root / "linked.csv"
            linked.symlink_to(target)
            with self.assertRaises(UnsafePathError), regular_text_reader(linked):
                pass
            with self.assertRaises(UnsafePathError):
                read_csv(linked)

    def test_csv_escape_metadata_round_trips_exact_values_without_guessing(self) -> None:
        originals = [
            "=formula-like title",
            "+plus title",
            "-minus title",
            "@mention title",
            "\ttab title",
            "\rcarriage title",
            "'=genuine apostrophe title",
            "ordinary title",
            "ellipsis… title",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "titles.csv"
            escaped = write_csv_private(path, ({"name": value} for value in originals), ["name"])
            restored = [row["name"] for row in read_csv(path, escaped_cells=escaped)]
            raw = path.read_text(encoding="utf-8")

        self.assertEqual(restored, originals)
        self.assertEqual(len(escaped), 6)
        self.assertIn("'=formula-like title", raw)
        self.assertIn("'=genuine apostrophe title", raw)

    def test_csv_escape_metadata_fails_closed_when_coordinates_do_not_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "titles.csv"
            write_csv_private(path, [{"name": "ordinary"}], ["name"])
            with self.assertRaisesRegex(TVTimeError, "did not match"):
                read_csv(path, escaped_cells=[{"row": 1, "field": "name"}])


class ExtractionLifecycleSecurityTests(unittest.TestCase):
    def test_direct_extract_status_is_byte_bounded_before_output_creation(self) -> None:
        def finished_payload(byte_size: int) -> bytes:
            base = plistlib.dumps({"SnapshotState": "finished"}, fmt=plistlib.FMT_XML)
            marker = b"</plist>"
            available = byte_size - len(base) - len(b"<!---->")
            if available < 2:
                raise AssertionError("synthetic status boundary was too small")
            multibyte_count, ascii_count = divmod(available, 2)
            comment = b"<!--" + ("é" * multibyte_count).encode() + b"x" * ascii_count + b"-->"
            payload = base.replace(marker, comment + marker)
            if len(payload) != byte_size:
                raise AssertionError("synthetic status payload missed its exact byte boundary")
            return payload

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            status = base / "Status.plist"
            exact_bytes = 1024
            exact_payload = finished_payload(exact_bytes)
            status.write_bytes(exact_payload)
            with mock.patch(
                "tvtime_extractor.extract.MAXIMUM_STATUS_PLIST_BYTES",
                exact_bytes,
            ):
                state = _finished_status_state(status)
            self.assertEqual(state.size, exact_bytes)
            self.assertEqual(state.sha256, hashlib.sha256(exact_payload).hexdigest())

            backup = _write_backup(base)
            (backup / "Status.plist").write_bytes(finished_payload(exact_bytes + 1))
            loader = mock.Mock(side_effect=AssertionError("dependency must not load"))
            with (
                mock.patch(
                    "tvtime_extractor.extract.MAXIMUM_STATUS_PLIST_BYTES",
                    exact_bytes,
                ),
                self.assertRaises(BackupUnfinishedError),
            ):
                extract_backup(
                    backup_directory=backup,
                    output_directory=base / "output",
                    passphrase="synthetic password",
                    dependency_loader=loader,
                )
            loader.assert_not_called()
            self.assertFalse((base / "output").exists())

    def test_finished_extraction_disposes_dependency_before_atomic_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_backup(base)
            rows, plaintext = _row(backup)
            instances: list[_CleanupBackup] = []
            output = io.StringIO()
            with (
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(output),
            ):
                result = extract_backup(
                    backup_directory=backup,
                    output_directory=base / "output",
                    passphrase="synthetic password",
                    dependency_loader=_loader(
                        instances,
                        rows=rows,
                        plaintext=plaintext,
                    ),
                )

            instance = instances[0]
            marker = read_json_regular(result.extraction_root / "metadata" / "run_state.json")
            self.assertEqual(marker["status"], "complete")
            self.assertEqual(instance.run_state_at_cleanup, "incomplete")
            self.assertTrue(instance.connection.closed)
            self.assertEqual(instance.cleanup_calls, 1)
            self.assertTrue(instance.decrypted_from_private_snapshot)
            self.assertIsNone(instance._passphrase)
            self.assertIsNone(instance._keybag)
            self.assertFalse((result.extraction_root / ".tmp").exists())
            self.assertEqual(output.getvalue(), "")

    def test_unfinished_status_is_rejected_before_dependency_construction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_backup(base, snapshot_state="running")
            instances: list[_CleanupBackup] = []
            with self.assertRaises(BackupUnfinishedError):
                extract_backup(
                    backup_directory=backup,
                    output_directory=base / "output",
                    passphrase="synthetic password",
                    dependency_loader=_loader(instances, rows=[], plaintext={}),
                )
            self.assertFalse((base / "output").exists())
            self.assertEqual(instances, [])

    def test_negative_declared_size_is_rejected_before_copy_and_remains_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_backup(base)
            rows, plaintext = _row(backup)
            file_id, domain, relative_path, metadata = rows[0]
            rows[0] = (file_id, domain, relative_path, {**metadata, "filesize": -1})
            instances: list[_CleanupBackup] = []

            with self.assertRaisesRegex(TVTimeError, "negative declared size"):
                extract_backup(
                    backup_directory=backup,
                    output_directory=base / "output",
                    passphrase="synthetic password",
                    dependency_loader=_loader(
                        instances,
                        rows=rows,
                        plaintext=plaintext,
                    ),
                )

            extraction = base / "output" / "TVTime-Extraction"
            marker = read_json_regular(extraction / "metadata" / "run_state.json")
            self.assertEqual(marker["status"], "incomplete")
            self.assertEqual(list((extraction / "raw").rglob("*")), [])
            self.assertEqual(len(instances), 1)
            self.assertTrue(instances[0].connection.closed)

    def test_non_integer_declared_sizes_are_rejected_without_coercion(self) -> None:
        for invalid in (None, True, False, 1.5, "9"):
            with self.subTest(value=invalid), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                backup = _write_backup(base)
                rows, plaintext = _row(backup)
                file_id, domain, relative_path, metadata = rows[0]
                rows[0] = (file_id, domain, relative_path, {**metadata, "filesize": invalid})
                instances: list[_CleanupBackup] = []
                with self.assertRaisesRegex(TVTimeError, "invalid declared size type"):
                    extract_backup(
                        backup_directory=backup,
                        output_directory=base / "output",
                        passphrase="synthetic password",
                        dependency_loader=_loader(
                            instances,
                            rows=rows,
                            plaintext=plaintext,
                        ),
                    )
                marker = read_json_regular(
                    base / "output" / "TVTime-Extraction" / "metadata" / "run_state.json"
                )
                self.assertEqual(marker["status"], "incomplete")

    def test_non_string_manifest_relative_paths_are_rejected_without_coercion(self) -> None:
        for invalid in (None, b"Documents/recovered.bin", 17, True):
            with self.subTest(value=invalid), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                backup = _write_backup(base)
                rows, plaintext = _row(backup)
                file_id, domain, _relative_path, metadata = rows[0]
                rows[0] = (file_id, domain, invalid, metadata)
                instances: list[_CleanupBackup] = []
                with self.assertRaisesRegex(TVTimeError, "invalid relative path type"):
                    extract_backup(
                        backup_directory=backup,
                        output_directory=base / "output",
                        passphrase="synthetic password",
                        dependency_loader=_loader(
                            instances,
                            rows=rows,
                            plaintext=plaintext,
                        ),
                    )

    def test_source_hashing_detects_in_place_race_even_when_size_and_mtime_are_restored(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload"
            payload.write_bytes(b"A" * (2 * 1024 * 1024))
            original = payload.stat()
            real_read = os.read
            mutated = False

            def race(descriptor: int, count: int) -> bytes:
                nonlocal mutated
                chunk = real_read(descriptor, count)
                if chunk and not mutated:
                    mutated = True
                    with payload.open("r+b") as handle:
                        handle.seek(0)
                        handle.write(b"B" * len(chunk))
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.utime(
                        payload,
                        ns=(original.st_atime_ns, original.st_mtime_ns),
                    )
                return chunk

            with (
                mock.patch("tvtime_extractor.extract.os.read", side_effect=race),
                self.assertRaises(SourceChangedError),
            ):
                _source_payload_state(payload)
            self.assertTrue(mutated)

    def test_status_change_during_dependency_cleanup_keeps_run_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_backup(base)
            rows, plaintext = _row(backup)
            instances: list[_CleanupBackup] = []
            with self.assertRaises(SourceChangedError):
                extract_backup(
                    backup_directory=backup,
                    output_directory=base / "output",
                    passphrase="synthetic password",
                    dependency_loader=_loader(
                        instances,
                        rows=rows,
                        plaintext=plaintext,
                        mutate_status_path=backup / "Status.plist",
                    ),
                )
            extraction = base / "output" / "TVTime-Extraction"
            self.assertEqual(
                read_json_regular(extraction / "metadata" / "run_state.json")["status"],
                "incomplete",
            )
            self.assertFalse((extraction / ".tmp").exists())

    def test_dependency_close_failure_is_path_free_and_removes_private_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_backup(base)
            rows, plaintext = _row(backup)
            instances: list[_CleanupBackup] = []
            with self.assertRaises(TVTimeError) as raised:
                extract_backup(
                    backup_directory=backup,
                    output_directory=base / "output",
                    passphrase="synthetic password",
                    dependency_loader=_loader(
                        instances,
                        rows=rows,
                        plaintext=plaintext,
                        close_fails=True,
                    ),
                )
            extraction = base / "output" / "TVTime-Extraction"
            self.assertIn("Temporary decrypted recovery data", str(raised.exception))
            self.assertNotIn(str(base), str(raised.exception))
            self.assertEqual(
                read_json_regular(extraction / "metadata" / "run_state.json")["status"],
                "incomplete",
            )
            self.assertFalse((extraction / ".tmp").exists())

    def test_earlier_error_is_retained_while_cleanup_remains_best_effort(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_backup(base)
            instances: list[_CleanupBackup] = []
            with self.assertRaises(TVTimeError) as raised:
                extract_backup(
                    backup_directory=backup,
                    output_directory=base / "output",
                    passphrase="synthetic password",
                    dependency_loader=_loader(
                        instances,
                        rows=[],
                        plaintext={},
                        decryption_fails=True,
                        cleanup_fails=True,
                    ),
                )
            self.assertNotIn("original synthetic decryption failure", str(raised.exception))
            self.assertIn("dependency failed safely", str(raised.exception))
            self.assertIn(
                "original synthetic decryption failure",
                str(raised.exception.__cause__),
            )
            extraction = base / "output" / "TVTime-Extraction"
            self.assertEqual(
                read_json_regular(extraction / "metadata" / "run_state.json")["status"],
                "incomplete",
            )
            self.assertFalse((extraction / ".tmp").exists())


if __name__ == "__main__":
    unittest.main()
