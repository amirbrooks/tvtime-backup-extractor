from __future__ import annotations

import contextlib
import errno
import hashlib
import io
import json
import os
import plistlib
import shutil
import sqlite3
import struct
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

from tvtime_extractor.errors import (
    BackupUnfinishedError,
    InsufficientSpaceError,
    SourceChangedError,
    TVTimeError,
    UnsafePathError,
)
from tvtime_extractor.extract import (
    PRIMARY_DOMAIN,
    _bounded_manifest_rows,
    _close_repository_manifest,
    _create_private_staging_descriptor,
    _decrypt_cbc_to_descriptor,
    _DescriptorDecryptionFailure,
    _finished_status_state,
    _harden_private_staging_descriptor,
    _prepare_repository_owned_manifest,
    _SelectedFileCopyFailure,
    _SelectedFileFailureCategory,
    _sha256_staging_descriptor,
    _source_payload_state,
    _verified_dependency_output_alias,
    extract_backup,
    public_summary_json,
)
from tvtime_extractor.report import read_csv
from tvtime_extractor.safety import (
    read_json_regular,
    regular_text_reader,
    write_csv_private,
    write_json_private_atomic,
)


class _Connection:
    def __init__(self, delegate: sqlite3.Connection, *, fail: bool = False) -> None:
        self.delegate = delegate
        self.fail = fail
        self.closed = False

    def close(self) -> None:
        self.delegate.close()
        self.closed = True
        if self.fail:
            raise OSError("synthetic close failure")


class _Keybag:
    def unwrapKeyForClass(self, _protection_class: object, _wrapped_key: object) -> bytes:
        return b"K" * 32


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
        self.connection: _Connection | None = None
        self._temp_manifest_db_conn = None
        self.cleanup_calls = 0
        self.run_state_at_cleanup = ""
        self.path_writer_called = False

    def _read_and_unlock_keybag(self) -> None:
        self._manifest_plist = {"ManifestKey": struct.pack("<l", 1) + b"wrapped"}

    def test_decryption(self) -> None:
        print("dependency test private path", file=os.sys.stderr)
        if self._temp_manifest_db_conn is None:
            raise AssertionError("repository-owned manifest connection was unavailable")
        self.connection = _Connection(self._temp_manifest_db_conn, fail=self.close_fails)
        self._temp_manifest_db_conn = self.connection
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
        self.path_writer_called = True
        raise AssertionError("the dependency path-only writer must not be called")

    @staticmethod
    def assert_key(key: bytes) -> None:
        if key != b"K" * 32:
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


class DescriptorDecryptionTests(unittest.TestCase):
    @staticmethod
    def _encrypt(plaintext: bytes, *, key: bytes) -> bytes:
        from Crypto.Cipher import AES

        padding_size = 16 - len(plaintext) % 16
        padded = plaintext + bytes([padding_size]) * padding_size
        return AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(padded)

    def test_chunked_cbc_decryption_matches_known_boundaries(self) -> None:
        key = bytes(range(32))
        for size in (0, 1, 15, 16, 17, 1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                plaintext = bytes(index % 251 for index in range(size))
                encrypted = root / "encrypted.bin"
                encrypted.write_bytes(self._encrypt(plaintext, key=key))
                encrypted.chmod(0o600)
                output = root / "decrypted.partial"
                descriptor = os.open(
                    output,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_BINARY", 0),
                    0o600,
                )
                try:
                    _decrypt_cbc_to_descriptor(
                        encrypted,
                        descriptor,
                        key=key,
                        declared_size=size,
                    )
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    actual = bytearray()
                    while True:
                        chunk = os.read(descriptor, 1024 * 1024)
                        if not chunk:
                            break
                        actual.extend(chunk)
                    self.assertEqual(len(actual), size)
                    self.assertEqual(bytes(actual), plaintext)
                finally:
                    os.close(descriptor)

    def test_repository_manifest_session_is_immutable_and_descriptor_locked(self) -> None:
        from Crypto.Cipher import AES

        key = b"M" * 32

        class Keybag:
            def unwrapKeyForClass(self, protection_class: object, wrapped: object) -> bytes:
                if protection_class != 7 or wrapped != b"wrapped-manifest-key":
                    raise AssertionError("unexpected synthetic manifest metadata")
                return key

        class Backup:
            def __init__(self, manifest_path: Path) -> None:
                self._manifest_plist: dict[str, object] | None = None
                self._keybag: Keybag | None = None
                self._temp_decrypted_manifest_db_path = str(manifest_path)
                self._temp_manifest_db_conn = None

            def _read_and_unlock_keybag(self) -> None:
                self._manifest_plist = {
                    "ManifestKey": struct.pack("<l", 7) + b"wrapped-manifest-key"
                }
                self._keybag = Keybag()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plaintext = root / "plaintext.db"
            connection = sqlite3.connect(plaintext)
            connection.execute(
                "CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, "
                "flags INTEGER, file BLOB)"
            )
            connection.execute(
                "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
                ("0" * 40, PRIMARY_DOMAIN, "Documents/synthetic.db", 1, b"synthetic"),
            )
            connection.commit()
            connection.close()
            plaintext_bytes = plaintext.read_bytes()
            self.assertEqual(len(plaintext_bytes) % 16, 0)
            encrypted = root / "Manifest.encrypted.db"
            encrypted.write_bytes(
                AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(plaintext_bytes)
            )
            encrypted.chmod(0o600)
            temp_root = root / "private-temp"
            temp_root.mkdir(mode=0o700)
            manifest_path = temp_root / "Manifest.db"
            backup = Backup(manifest_path)

            _prepare_repository_owned_manifest(
                backup,
                encrypted_manifest=encrypted,
                temp_root=temp_root,
            )
            assert backup._temp_manifest_db_conn is not None
            self.assertEqual(
                backup._temp_manifest_db_conn.execute("SELECT count(*) FROM Files").fetchone(),
                (1,),
            )
            with self.assertRaises(sqlite3.OperationalError):
                backup._temp_manifest_db_conn.execute("DELETE FROM Files")
            if os.name == "nt":
                with self.assertRaises(OSError):
                    manifest_path.write_bytes(b"changed")
            _close_repository_manifest(backup)

    def test_chunked_cbc_decryption_records_fixed_validation_categories(self) -> None:
        from Crypto.Cipher import AES

        key = b"K" * 32
        cases = (
            (
                AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(b"X" * 15 + b"\x00"),
                key,
                15,
                _SelectedFileFailureCategory.PADDING_FAILURE,
            ),
            (
                self._encrypt(b"synthetic", key=key),
                key,
                len(b"synthetic") + 1,
                _SelectedFileFailureCategory.SIZE_MISMATCH,
            ),
            (
                b"not-block-aligned",
                key,
                1,
                _SelectedFileFailureCategory.CIPHERTEXT_INVALID,
            ),
            (
                self._encrypt(b"synthetic", key=key),
                b"invalid",
                len(b"synthetic"),
                _SelectedFileFailureCategory.KEY_UNWRAP_FAILURE,
            ),
        )
        for encrypted_payload, selected_key, declared_size, expected_category in cases:
            with (
                self.subTest(category=expected_category.value),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                encrypted = root / "encrypted.bin"
                encrypted.write_bytes(encrypted_payload)
                encrypted.chmod(0o600)
                output = root / "decrypted.partial"
                descriptor = os.open(
                    output,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_BINARY", 0),
                    0o600,
                )
                try:
                    with self.assertRaises(_DescriptorDecryptionFailure) as raised:
                        _decrypt_cbc_to_descriptor(
                            encrypted,
                            descriptor,
                            key=selected_key,
                            declared_size=declared_size,
                        )
                    self.assertEqual(raised.exception.category, expected_category)
                    self.assertEqual(
                        str(raised.exception),
                        "The selected backup file could not be copied safely.",
                    )
                finally:
                    os.close(descriptor)

    def test_chunked_cbc_decryption_can_return_a_valid_size_warning(self) -> None:
        key = b"K" * 32
        plaintext = b"synthetic"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            encrypted = root / "encrypted.bin"
            encrypted.write_bytes(self._encrypt(plaintext, key=key))
            encrypted.chmod(0o600)
            output = root / "decrypted.partial"
            descriptor = os.open(
                output,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_BINARY", 0),
                0o600,
            )
            try:
                written = _decrypt_cbc_to_descriptor(
                    encrypted,
                    descriptor,
                    key=key,
                    declared_size=len(plaintext) + 1,
                    allow_size_mismatch=True,
                )
                os.lseek(descriptor, 0, os.SEEK_SET)
                self.assertEqual(written, len(plaintext))
                self.assertEqual(os.read(descriptor, len(plaintext)), plaintext)
            finally:
                os.close(descriptor)


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
    from Crypto.Cipher import AES

    backup = base / "backup"
    backup.mkdir()
    (backup / "Manifest.plist").write_bytes(b"synthetic manifest")
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
        plistlib.dump({"SnapshotState": snapshot_state}, handle)
    return backup


def _row(
    backup: Path, *, plaintext: bytes = b"recovered"
) -> tuple[list[tuple[Any, ...]], dict[str, bytes]]:
    from Crypto.Cipher import AES

    file_id = "a" * 40
    encrypted = backup / file_id[:2] / file_id
    encrypted.parent.mkdir()
    padding_size = 16 - len(plaintext) % 16
    encrypted.write_bytes(
        AES.new(b"K" * 32, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(
            plaintext + bytes([padding_size]) * padding_size
        )
    )
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
    file_plist_factory: type[_FilePlist] | Any = _FilePlist,
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

        return factory, file_plist_factory

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
    @staticmethod
    def _single_failure_category(result: Any) -> str:
        summary = result.summary
        failures = summary["failures"]
        if not isinstance(failures, list) or len(failures) != 1:
            raise AssertionError("expected one synthetic selected-file failure")
        return str(failures[0]["category"])

    def test_private_failure_inventory_serializes_every_fixed_category(self) -> None:
        for category in _SelectedFileFailureCategory:
            with self.subTest(category=category.value), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                backup = _write_backup(base)
                rows, plaintext = _row(backup)
                with mock.patch(
                    "tvtime_extractor.extract._extract_one_file",
                    side_effect=_SelectedFileCopyFailure(category),
                ):
                    result = extract_backup(
                        backup_directory=backup,
                        output_directory=base / "output",
                        passphrase="synthetic password",
                        dependency_loader=_loader([], rows=rows, plaintext=plaintext),
                    )

                failure = result.summary["failures"][0]
                self.assertEqual(
                    set(failure),
                    {"file_id", "domain", "relative_path", "error", "category"},
                )
                self.assertEqual(failure["category"], category.value)
                self.assertEqual(
                    failure["error"],
                    "The selected backup file could not be copied safely.",
                )
                self.assertNotIn(category.value, public_summary_json(result))
                marker = read_json_regular(result.extraction_root / "metadata" / "run_state.json")
                self.assertEqual(marker["status"], "incomplete")
                self.assertEqual(
                    [
                        path
                        for path in (result.extraction_root / "raw").rglob("*")
                        if path.is_file()
                    ],
                    [],
                )

    def test_missing_key_and_invalid_metadata_are_classified(self) -> None:
        class MissingKeyPlist(_FilePlist):
            def __init__(self, value: dict[str, Any]) -> None:
                super().__init__(value)
                self.encryption_key = None

        cases: list[tuple[str, Any]] = [
            ("missing_encryption_key", MissingKeyPlist),
        ]

        calls = 0

        def changing_plist(value: dict[str, Any]) -> _FilePlist:
            nonlocal calls
            calls += 1
            parsed = _FilePlist(value)
            if calls > 1:
                parsed.filesize = "synthetic-invalid-size"
            return parsed

        cases.append(("invalid_manifest_metadata", changing_plist))
        for expected, factory in cases:
            with self.subTest(category=expected), tempfile.TemporaryDirectory() as temporary:
                calls = 0
                base = Path(temporary)
                backup = _write_backup(base)
                rows, plaintext = _row(backup)
                result = extract_backup(
                    backup_directory=backup,
                    output_directory=base / "output",
                    passphrase="synthetic password",
                    dependency_loader=_loader(
                        [],
                        rows=rows,
                        plaintext=plaintext,
                        file_plist_factory=factory,
                    ),
                )
                self.assertEqual(self._single_failure_category(result), expected)

    def test_key_unwrap_failure_discards_dependency_output_and_exception_details(self) -> None:
        secret = "synthetic-secret password title path"
        calls = 0

        def unwrap(_keybag: object, _protection_class: object, _wrapped: object) -> bytes:
            nonlocal calls
            calls += 1
            if calls == 1:
                return b"K" * 32
            print(secret)
            print(secret, file=sys.stderr)
            raise RuntimeError(secret)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_backup(base)
            rows, plaintext = _row(backup)
            captured = io.StringIO()
            with (
                mock.patch.object(_Keybag, "unwrapKeyForClass", new=unwrap),
                contextlib.redirect_stdout(captured),
                contextlib.redirect_stderr(captured),
            ):
                result = extract_backup(
                    backup_directory=backup,
                    output_directory=base / "output",
                    passphrase="synthetic password",
                    dependency_loader=_loader([], rows=rows, plaintext=plaintext),
                )
            private_summary = (result.extraction_root / "metadata" / "summary.json").read_text(
                encoding="utf-8"
            )
            self.assertEqual(self._single_failure_category(result), "key_unwrap_failure")
            self.assertNotIn(secret, private_summary)
            self.assertNotIn(secret, public_summary_json(result))
            self.assertNotIn(secret, captured.getvalue())

    def test_source_snapshot_failures_are_classified_without_promoting_plaintext(self) -> None:
        real_source_state = _source_payload_state
        for expected in ("source_unavailable", "source_changed"):
            with self.subTest(category=expected), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                backup = _write_backup(base)
                rows, plaintext = _row(backup)

                def source_state(
                    path: Path,
                    expected_category: str = expected,
                    **kwargs: Any,
                ) -> object:
                    result = real_source_state(path, **kwargs)
                    destination = kwargs.get("snapshot_destination")
                    if destination is not None and "encrypted-source" in Path(destination).parts:
                        if expected_category == "source_unavailable":
                            raise OSError(errno.EIO, "synthetic private source detail")
                        return replace(result, sha256="0" * 64)
                    return result

                with mock.patch(
                    "tvtime_extractor.extract._source_payload_state",
                    side_effect=source_state,
                ):
                    result = extract_backup(
                        backup_directory=backup,
                        output_directory=base / "output",
                        passphrase="synthetic password",
                        dependency_loader=_loader([], rows=rows, plaintext=plaintext),
                    )
                self.assertEqual(self._single_failure_category(result), expected)
                self.assertEqual(
                    [
                        path
                        for path in (result.extraction_root / "raw").rglob("*")
                        if path.is_file()
                    ],
                    [],
                )

    def test_staging_promotion_and_unrecognized_failures_are_classified(self) -> None:
        real_create = _create_private_staging_descriptor
        real_decrypt = _decrypt_cbc_to_descriptor

        def fail_staging(path: Path) -> tuple[int, tuple[int, int]]:
            if path.name.endswith(".partial"):
                raise OSError(errno.EIO, "synthetic private staging detail")
            return real_create(path)

        def fail_selected_decryption(*args: Any, **kwargs: Any) -> None:
            if kwargs.get("strip_padding") is False:
                real_decrypt(*args, **kwargs)
                return
            raise RuntimeError("synthetic private unknown detail")

        cases = (
            (
                "staging_failure",
                mock.patch(
                    "tvtime_extractor.extract._create_private_staging_descriptor",
                    side_effect=fail_staging,
                ),
            ),
            (
                "promotion_failure",
                mock.patch(
                    "tvtime_extractor.extract.promote_open_file_no_replace_atomic",
                    side_effect=OSError(errno.EIO, "synthetic private promotion detail"),
                ),
            ),
            (
                "unrecognized_failure",
                mock.patch(
                    "tvtime_extractor.extract._decrypt_cbc_to_descriptor",
                    side_effect=fail_selected_decryption,
                ),
            ),
        )
        for expected, patcher in cases:
            with (
                self.subTest(category=expected),
                tempfile.TemporaryDirectory() as temporary,
                patcher,
            ):
                base = Path(temporary)
                backup = _write_backup(base)
                rows, plaintext = _row(backup)
                result = extract_backup(
                    backup_directory=backup,
                    output_directory=base / "output",
                    passphrase="synthetic password",
                    dependency_loader=_loader([], rows=rows, plaintext=plaintext),
                )
                self.assertEqual(self._single_failure_category(result), expected)

    def test_disk_exhaustion_remains_a_global_failure(self) -> None:
        real_create = _create_private_staging_descriptor

        def exhaust_staging(path: Path) -> tuple[int, tuple[int, int]]:
            if path.name.endswith(".partial"):
                raise OSError(errno.ENOSPC, "synthetic full destination")
            return real_create(path)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_backup(base)
            rows, plaintext = _row(backup)
            with (
                mock.patch(
                    "tvtime_extractor.extract._create_private_staging_descriptor",
                    side_effect=exhaust_staging,
                ),
                self.assertRaises(InsufficientSpaceError),
            ):
                extract_backup(
                    backup_directory=backup,
                    output_directory=base / "output",
                    passphrase="synthetic password",
                    dependency_loader=_loader([], rows=rows, plaintext=plaintext),
                )

    def test_invalid_padding_remains_a_failure_and_is_never_promoted(self) -> None:
        from Crypto.Cipher import AES

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_backup(base)
            rows, plaintext = _row(backup)
            file_id = str(rows[0][0])
            (backup / file_id[:2] / file_id).write_bytes(
                AES.new(b"K" * 32, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(b"X" * 15 + b"\x00")
            )
            result = extract_backup(
                backup_directory=backup,
                output_directory=base / "output",
                passphrase="synthetic password",
                dependency_loader=_loader([], rows=rows, plaintext=plaintext),
            )

            self.assertEqual(self._single_failure_category(result), "padding_failure")
            self.assertFalse(
                (
                    result.extraction_root / "raw" / PRIMARY_DOMAIN / "Documents" / "recovered.bin"
                ).exists()
            )

    def test_space_preflight_uses_ciphertext_as_the_output_upper_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_backup(base)
            rows, plaintext = _row(backup)
            file_id, domain, relative_path, metadata = rows[0]
            rows[0] = (file_id, domain, relative_path, {**metadata, "filesize": 1})
            minimum_headroom = 64 * 1024 * 1024
            with (
                mock.patch(
                    "tvtime_extractor.extract.shutil.disk_usage",
                    side_effect=(
                        mock.Mock(free=1024 * 1024 * 1024),
                        mock.Mock(free=minimum_headroom + 24),
                    ),
                ),
                self.assertRaises(InsufficientSpaceError),
            ):
                extract_backup(
                    backup_directory=backup,
                    output_directory=base / "output",
                    passphrase="synthetic password",
                    dependency_loader=_loader([], rows=rows, plaintext=plaintext),
                )

    def test_retained_manifest_is_promoted_from_a_held_private_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = _write_backup(base)
            result = extract_backup(
                backup_directory=backup,
                output_directory=base / "output",
                passphrase="synthetic password",
                include_decrypted_manifest=True,
                dependency_loader=_loader([], rows=[], plaintext={}),
            )
            retained = result.extraction_root / "manifest" / "Manifest.decrypted.db"
            retained_bytes = retained.read_bytes()
            self.assertTrue(retained_bytes.startswith(b"SQLite format 3\x00"))
            self.assertEqual(
                result.summary["manifest_sha256"],
                hashlib.sha256(retained_bytes).hexdigest(),
            )

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
            self.assertIsNotNone(instance.connection)
            assert instance.connection is not None
            self.assertTrue(instance.connection.closed)
            self.assertEqual(instance.cleanup_calls, 1)
            self.assertFalse(instance.path_writer_called)
            self.assertEqual(
                (
                    result.extraction_root / "raw" / PRIMARY_DOMAIN / "Documents" / "recovered.bin"
                ).read_bytes(),
                b"recovered",
            )
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
            self.assertIsNotNone(instances[0].connection)
            assert instances[0].connection is not None
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

    @unittest.skipIf(os.name == "nt", "Windows source handles deny concurrent mutation")
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
