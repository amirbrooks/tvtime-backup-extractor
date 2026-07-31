from __future__ import annotations

import io
import sqlite3
import tempfile
import unittest
import zipfile
import zlib
from contextlib import closing, contextmanager
from pathlib import Path
from unittest import mock

from tests.cross_platform_fixtures import (
    create_synthetic_cache_database as _synthetic_cache_database,
)
from tests.cross_platform_fixtures import (
    synthetic_android_backup as _android_backup,
)
from tests.helpers import synthetic_payloads
from tvtime_extractor.acquisition import (
    ANDROID_BACKUP_MAGIC,
    AndroidBackupEncryption,
    RecoverySourceKind,
    _bounded_csv_rows,
    _BoundedDecompressingReader,
    _official_export_members,
    _read_official_export_payloads,
    _write_official_export_cache,
    inspect_android_backup,
    inspect_android_snapshot,
    inspect_official_export,
    parse_android_backup_header,
    recover_acquired_source,
)
from tvtime_extractor.errors import (
    BackupPasswordError,
    SourceChangedError,
    UnsafePathError,
    UnsupportedSchemaError,
    UserInputError,
)


class AndroidBackupHeaderTests(unittest.TestCase):
    def test_parses_standard_and_bounded_vendor_envelope_headers(self) -> None:
        standard = parse_android_backup_header(ANDROID_BACKUP_MAGIC + b"5\n1\nnone\nrest")
        self.assertEqual(standard.version, 5)
        self.assertTrue(standard.compressed)
        self.assertEqual(standard.encryption, AndroidBackupEncryption.NONE)
        self.assertEqual(standard.vendor_prefix_lines, 0)

        vendor = parse_android_backup_header(
            b"SYNTHETIC VENDOR BACKUP\nmetadata\n" + ANDROID_BACKUP_MAGIC + b"4\n0\nnone\n"
        )
        self.assertEqual(vendor.version, 4)
        self.assertFalse(vendor.compressed)
        self.assertEqual(vendor.vendor_prefix_lines, 2)

    def test_rejects_unknown_and_encrypted_headers_fail_closed(self) -> None:
        with self.assertRaises(UserInputError):
            parse_android_backup_header(b"not an android archive\n")
        encrypted = parse_android_backup_header(ANDROID_BACKUP_MAGIC + b"5\n1\nAES-256\nsynthetic")
        self.assertEqual(encrypted.encryption, AndroidBackupEncryption.AES_256)


class AndroidAcquisitionTests(unittest.TestCase):
    def test_destination_parent_is_held_during_source_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "synthetic-android.ab"
            source.write_bytes(ANDROID_BACKUP_MAGIC + b"5\n1\nAES-256\nsynthetic")
            output = root / "private-result"

            from tvtime_extractor import acquisition

            real_hold = acquisition.held_destination_parent
            parent_is_held = False

            @contextmanager
            def observed_hold(path: Path):
                nonlocal parent_is_held
                with real_hold(path) as binding:
                    parent_is_held = True
                    try:
                        yield binding
                    finally:
                        parent_is_held = False

            def inspect_while_held(*args: object, **kwargs: object) -> object:
                self.assertTrue(parent_is_held)
                return inspect_android_backup(*args, **kwargs)

            with (
                mock.patch(
                    "tvtime_extractor.acquisition.held_destination_parent",
                    side_effect=observed_hold,
                ),
                mock.patch(
                    "tvtime_extractor.acquisition.inspect_android_backup",
                    side_effect=inspect_while_held,
                ),
                self.assertRaises(UnsupportedSchemaError),
            ):
                recover_acquired_source(
                    source_kind=RecoverySourceKind.ANDROID_LEGACY_BACKUP,
                    source=source,
                    output_directory=output,
                    acknowledge_sensitive_output=True,
                )
            self.assertFalse(parent_is_held)
            self.assertFalse(output.exists())

    def test_each_compressed_read_is_bounded_before_expansion_allocation(self) -> None:
        compressed = zlib.compress(b"x" * (1024 * 1024))
        with mock.patch(
            "tvtime_extractor.acquisition.ANDROID_BACKUP_MAXIMUM_UNPACKED_BYTES",
            1024,
        ):
            reader = _BoundedDecompressingReader(io.BytesIO(compressed), compressed=True)
            with self.assertRaises(UnsupportedSchemaError):
                reader.readinto(bytearray(2048))

    def test_normalized_official_export_database_is_explicitly_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "synthetic-normalized.sqlite"
            captured: list[sqlite3.Connection] = []
            real_connect = sqlite3.connect

            def capture_connection(*args: object, **kwargs: object) -> sqlite3.Connection:
                connection = real_connect(*args, **kwargs)
                captured.append(connection)
                return connection

            with mock.patch(
                "tvtime_extractor.acquisition.sqlite3.connect",
                side_effect=capture_connection,
            ):
                _write_official_export_cache(
                    target,
                    [("synthetic://record", "normalized", b"{}", 200)],
                )

            self.assertEqual(len(captured), 1)
            for connection in captured:
                with self.assertRaises(sqlite3.ProgrammingError):
                    connection.execute("SELECT 1")

    def test_normalized_official_export_never_reopens_held_target_by_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "synthetic-normalized.sqlite"
            real_connect = sqlite3.connect
            opened: list[object] = []

            def observe_connection(database: object, *args: object, **kwargs: object) -> object:
                opened.append(database)
                return real_connect(database, *args, **kwargs)

            with mock.patch(
                "tvtime_extractor.acquisition.sqlite3.connect",
                side_effect=observe_connection,
            ):
                _write_official_export_cache(
                    target,
                    [("synthetic://record", "normalized", b"{}", 200)],
                )

            self.assertEqual(opened, [":memory:"])
            self.assertGreater(target.stat().st_size, 0)

    def test_normalized_official_export_uses_safe_legacy_sqlite_backup(self) -> None:
        class LegacyConnection:
            def __init__(self, connection: sqlite3.Connection) -> None:
                self.connection = connection

            def execute(self, *args: object) -> object:
                return self.connection.execute(*args)

            def executemany(self, *args: object) -> object:
                return self.connection.executemany(*args)

            def commit(self) -> None:
                self.connection.commit()

            def backup(self, target: sqlite3.Connection) -> None:
                self.connection.backup(target)

            def close(self) -> None:
                self.connection.close()

        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "synthetic-normalized.sqlite"
            real_connect = sqlite3.connect
            connection = LegacyConnection(real_connect(":memory:"))

            def connect(database: object, *args: object, **kwargs: object) -> object:
                if database == ":memory:":
                    return connection
                return real_connect(database, *args, **kwargs)

            with mock.patch(
                "tvtime_extractor.acquisition.sqlite3.connect",
                side_effect=connect,
            ):
                _write_official_export_cache(
                    target,
                    [("synthetic://record", "normalized", b"{}", 200)],
                )

            self.assertGreater(target.stat().st_size, 0)
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.connection.execute("SELECT 1")

    def test_compressed_backup_runs_the_existing_normalized_report_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = _synthetic_cache_database(root / "synthetic-cache.sqlite")
            source = root / "synthetic-android.ab"
            source.write_bytes(_android_backup(database))

            preflight = inspect_android_backup(source)
            self.assertEqual(preflight.source_kind, RecoverySourceKind.ANDROID_LEGACY_BACKUP)
            self.assertTrue(preflight.compressed)
            self.assertFalse(preflight.encrypted)
            self.assertNotIn("source_sha256", preflight.as_dict())
            self.assertNotIn("source_bytes", preflight.as_dict())

            result = recover_acquired_source(
                source_kind=RecoverySourceKind.ANDROID_LEGACY_BACKUP,
                source=source,
                output_directory=root / "private-result",
                acknowledge_sensitive_output=True,
            )
            self.assertEqual(result.analysis["parser_status"], "recognized")
            self.assertEqual(result.analysis["series_library"], 1)
            self.assertEqual(result.analysis["watched_movies"], 1)
            self.assertTrue(Path(result.report["report"]).is_file())
            self.assertTrue(Path(result.report["visual_report"]).is_file())

    def test_archive_ignores_empty_optional_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = _synthetic_cache_database(root / "synthetic-cache.sqlite")
            source = root / "synthetic-android.ab"
            source.write_bytes(_android_backup(database, include_empty_optional_sidecar=True))

            result = recover_acquired_source(
                source_kind=RecoverySourceKind.ANDROID_LEGACY_BACKUP,
                source=source,
                output_directory=root / "private-result",
                acknowledge_sensitive_output=True,
            )

            raw_documents = (
                result.extraction.extraction_root
                / "raw"
                / "AppDomain-com.tozelabs.tvshowtime"
                / "Documents"
            )
            self.assertEqual(
                sorted(path.name for path in raw_documents.iterdir()),
                ["DioCache.db"],
            )
            self.assertEqual(result.analysis["episode_cache_unique"], 1)

    def test_preserved_snapshot_uses_only_allowlisted_database_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot" / "databases"
            snapshot.mkdir(parents=True)
            _synthetic_cache_database(snapshot / "DioCache.db")
            (snapshot / "unrelated-private.sqlite").write_bytes(b"synthetic unrelated")

            result = recover_acquired_source(
                source_kind=RecoverySourceKind.ANDROID_PRESERVED_SNAPSHOT,
                source=snapshot.parent,
                output_directory=root / "private-snapshot-result",
                acknowledge_sensitive_output=True,
            )
            raw = result.extraction.extraction_root / "raw"
            names = sorted(path.name for path in raw.rglob("*") if path.is_file())
            self.assertEqual(names, ["DioCache.db"])
            self.assertEqual(result.analysis["episode_cache_unique"], 1)
            self.assertFalse((result.extraction.extraction_root / ".tmp").exists())
            self.assertEqual(
                list((result.extraction.extraction_root / "manifest").iterdir()),
                [],
            )

    def test_preserved_snapshot_binds_and_copies_committed_wal_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot" / "databases"
            snapshot.mkdir(parents=True)
            database = snapshot / "DioCache.db"
            with closing(sqlite3.connect(database)) as connection:
                self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
                connection.execute(
                    "CREATE TABLE cache_dio "
                    "(key TEXT NOT NULL, subKey TEXT NOT NULL, content BLOB, statusCode INTEGER)"
                )
                connection.executemany(
                    "INSERT INTO cache_dio (key, subKey, content, statusCode) VALUES (?, ?, ?, ?)",
                    synthetic_payloads(),
                )
                connection.commit()
                self.assertTrue((snapshot / "DioCache.db-wal").is_file())
                self.assertTrue((snapshot / "DioCache.db-shm").is_file())

                preflight = inspect_android_snapshot(snapshot.parent)
                self.assertEqual(
                    [item[0] for item in preflight.source_files],
                    ["DioCache.db", "DioCache.db-wal", "DioCache.db-shm"],
                )
                result = recover_acquired_source(
                    source_kind=RecoverySourceKind.ANDROID_PRESERVED_SNAPSHOT,
                    source=snapshot.parent,
                    output_directory=root / "private-wal-result",
                    acknowledge_sensitive_output=True,
                )

            raw_documents = (
                result.extraction.extraction_root
                / "raw"
                / "AppDomain-com.tozelabs.tvshowtime"
                / "Documents"
            )
            self.assertEqual(
                sorted(path.name for path in raw_documents.iterdir()),
                ["DioCache.db", "DioCache.db-shm", "DioCache.db-wal"],
            )
            self.assertEqual(result.analysis["episode_cache_unique"], 1)

    def test_preserved_snapshot_ignores_empty_optional_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot" / "databases"
            snapshot.mkdir(parents=True)
            _synthetic_cache_database(snapshot / "DioCache.db")
            (snapshot / "DioCache.db-wal").touch()

            preflight = inspect_android_snapshot(snapshot.parent)
            self.assertEqual([item[0] for item in preflight.source_files], ["DioCache.db"])
            result = recover_acquired_source(
                source_kind=RecoverySourceKind.ANDROID_PRESERVED_SNAPSHOT,
                source=snapshot.parent,
                output_directory=root / "private-empty-sidecar-result",
                acknowledge_sensitive_output=True,
                source_preflight=preflight,
            )
            self.assertEqual(result.analysis["episode_cache_unique"], 1)

    def test_preserved_snapshot_revalidates_optional_database_after_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot" / "databases"
            snapshot.mkdir(parents=True)
            _synthetic_cache_database(snapshot / "DioCache.db")
            optional = snapshot / "libCachedImageData.db"
            _synthetic_cache_database(optional)
            preflight = inspect_android_snapshot(snapshot.parent)
            self.assertEqual(
                [item[0] for item in preflight.source_files],
                ["DioCache.db", "libCachedImageData.db"],
            )

            from tvtime_extractor import acquisition

            real_copy = acquisition._copy_regular_source_private

            def copy_then_mutate(*args: object, **kwargs: object) -> tuple[int, str]:
                result = real_copy(*args, **kwargs)
                source = Path(args[0])
                if source.name == "libCachedImageData.db":
                    source.write_bytes(source.read_bytes() + b"synthetic mutation")
                return result

            with (
                mock.patch(
                    "tvtime_extractor.acquisition.inspect_android_snapshot",
                    return_value=preflight,
                ),
                mock.patch(
                    "tvtime_extractor.acquisition._copy_regular_source_private",
                    side_effect=copy_then_mutate,
                ),
                self.assertRaises(SourceChangedError),
            ):
                recover_acquired_source(
                    source_kind=RecoverySourceKind.ANDROID_PRESERVED_SNAPSHOT,
                    source=snapshot.parent,
                    output_directory=root / "private-mutated-snapshot-result",
                    acknowledge_sensitive_output=True,
                )

    def test_preserved_snapshot_replacement_with_same_bytes_fails_identity_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot" / "databases"
            snapshot.mkdir(parents=True)
            database = snapshot / "DioCache.db"
            payload = _synthetic_cache_database(database)
            preflight = inspect_android_snapshot(snapshot.parent)
            database.unlink()
            database.write_bytes(payload)
            with (
                mock.patch(
                    "tvtime_extractor.acquisition.inspect_android_snapshot",
                    return_value=preflight,
                ),
                self.assertRaises(SourceChangedError),
            ):
                recover_acquired_source(
                    source_kind=RecoverySourceKind.ANDROID_PRESERVED_SNAPSHOT,
                    source=snapshot.parent,
                    output_directory=root / "private-replaced-snapshot-result",
                    acknowledge_sensitive_output=True,
                )

    def test_preserved_snapshot_rejects_database_through_linked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            outside = root / "outside"
            outside.mkdir()
            _synthetic_cache_database(outside / "DioCache.db")
            (snapshot / "databases").symlink_to(outside, target_is_directory=True)

            with self.assertRaises(UnsafePathError):
                inspect_android_snapshot(snapshot)

    def test_encrypted_backup_is_rejected_before_output_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "synthetic-encrypted.ab"
            source.write_bytes(ANDROID_BACKUP_MAGIC + b"5\n1\nAES-256\nsynthetic")
            output = root / "must-not-exist"
            with self.assertRaises(UnsupportedSchemaError):
                recover_acquired_source(
                    source_kind=RecoverySourceKind.ANDROID_LEGACY_BACKUP,
                    source=source,
                    output_directory=output,
                    acknowledge_sensitive_output=True,
                )
            self.assertFalse(output.exists())

    def test_android_archive_replacement_with_same_bytes_fails_identity_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = _synthetic_cache_database(root / "synthetic-cache.sqlite")
            source = root / "synthetic-android.ab"
            payload = _android_backup(database)
            source.write_bytes(payload)
            preflight = inspect_android_backup(source)
            source.unlink()
            source.write_bytes(payload)
            with (
                mock.patch(
                    "tvtime_extractor.acquisition.inspect_android_backup",
                    return_value=preflight,
                ),
                self.assertRaises(SourceChangedError),
            ):
                recover_acquired_source(
                    source_kind=RecoverySourceKind.ANDROID_LEGACY_BACKUP,
                    source=source,
                    output_directory=root / "private-replaced-archive-result",
                    acknowledge_sensitive_output=True,
                )


class OfficialExportAcquisitionTests(unittest.TestCase):
    def test_rejected_export_password_uses_password_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "synthetic-export.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr(
                    "tracking-prod-records-v2.csv",
                    b"type,show_name\nwatch-episode,Synthetic Series\n",
                )
            preflight = inspect_official_export(source)
            members = _official_export_members(
                source,
                expected_identity=preflight.source_identity,
            )
            with (
                mock.patch.object(
                    zipfile.ZipFile,
                    "open",
                    side_effect=RuntimeError("synthetic bad password"),
                ),
                self.assertRaises(BackupPasswordError),
            ):
                _read_official_export_payloads(
                    source,
                    members,
                    expected_identity=preflight.source_identity,
                    passphrase="synthetic wrong password",
                    cancellation_check=None,
                )

    def test_official_export_rejects_headers_that_collide_after_normalization(self) -> None:
        payload = b"ep_id, ep_id,type\n101,102,watch-episode\n"
        with self.assertRaises(UnsupportedSchemaError):
            _bounded_csv_rows(payload, expected_filename="tracking-prod-records-v2.csv")

    def test_official_export_replacement_with_same_bytes_fails_identity_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "tracking-prod-records-v2.csv"
            payload = b"type,show_name\nwatch-episode,Synthetic Series\n"
            source.write_bytes(payload)
            preflight = inspect_official_export(source)
            source.unlink()
            source.write_bytes(payload)
            with (
                mock.patch(
                    "tvtime_extractor.acquisition.inspect_official_export",
                    return_value=preflight,
                ),
                self.assertRaises(SourceChangedError),
            ):
                recover_acquired_source(
                    source_kind=RecoverySourceKind.TVTIME_OFFICIAL_EXPORT,
                    source=source,
                    output_directory=root / "private-replaced-export-result",
                    acknowledge_sensitive_output=True,
                )

    def test_inspected_official_export_identity_survives_password_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "tracking-prod-records-v2.csv"
            payload = b"type,show_name\nwatch-episode,Synthetic Series\n"
            source.write_bytes(payload)
            preflight = inspect_official_export(source)
            source.unlink()
            source.write_bytes(payload)

            with self.assertRaises(SourceChangedError):
                recover_acquired_source(
                    source_kind=RecoverySourceKind.TVTIME_OFFICIAL_EXPORT,
                    source=source,
                    output_directory=root / "private-password-boundary-result",
                    acknowledge_sensitive_output=True,
                    source_preflight=preflight,
                )

    def test_supported_zip_is_preserved_and_normalized_through_existing_reports(self) -> None:
        episodes = (
            b"type,ep_id,created_at,season_number,episode_number,show_id,show_name,episode_name\n"
            b"watch-episode,101,2025-01-02 03:04:05,1,2,show-1,Synthetic Series,Synthetic Episode\n"
        )
        movies = (
            b"created_at,uuid,type,movie_name,entity_type,imdb_id\n"
            b"2025-02-03 04:05:06,movie-1,watch,Synthetic Movie,movie,tt0000001\n"
            b"2025-03-04 05:06:07,movie-2,towatch,Synthetic Saved Movie,movie,tt0000002\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "synthetic-gdpr.zip"
            with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("tracking-prod-records-v2.csv", episodes)
                archive.writestr("tracking-prod-records.csv", movies)
                archive.writestr("unrelated-profile.csv", b"synthetic,ignored\nvalue,value\n")

            preflight = inspect_official_export(source)
            self.assertEqual(preflight.source_kind, RecoverySourceKind.TVTIME_OFFICIAL_EXPORT)
            self.assertFalse(preflight.encrypted)
            result = recover_acquired_source(
                source_kind=RecoverySourceKind.TVTIME_OFFICIAL_EXPORT,
                source=source,
                output_directory=root / "private-official-result",
                acknowledge_sensitive_output=True,
            )
            self.assertEqual(result.analysis["series_library"], 1)
            self.assertEqual(result.analysis["watched_movies"], 1)
            self.assertEqual(result.analysis["movie_watchlist"], 1)
            self.assertEqual(result.analysis["episode_cache_unique"], 1)
            official = (
                result.extraction.extraction_root
                / "raw"
                / "AppDomain-com.tozelabs.tvshowtime"
                / "Documents"
                / "Official Export"
            )
            self.assertEqual(
                sorted(path.name for path in official.iterdir()),
                ["tracking-prod-records-v2.csv", "tracking-prod-records.csv"],
            )

    def test_unrecognized_export_fails_closed_without_a_successful_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "tracking-prod-records-v2.csv"
            source.write_text("unknown,value\nsynthetic,row\n", encoding="utf-8")
            output = root / "private-unknown-result"
            with self.assertRaises(UnsupportedSchemaError):
                recover_acquired_source(
                    source_kind=RecoverySourceKind.TVTIME_OFFICIAL_EXPORT,
                    source=source,
                    output_directory=output,
                    acknowledge_sensitive_output=True,
                )
            self.assertTrue(output.is_dir())
            self.assertFalse(
                (output / "TVTime-Extraction" / "analysis" / "recovery_state.json").exists()
            )


if __name__ == "__main__":
    unittest.main()
