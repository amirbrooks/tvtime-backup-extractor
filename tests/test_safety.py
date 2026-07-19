from __future__ import annotations

import csv
import ctypes
import errno
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from tvtime_extractor.errors import OutputExistsError, UnsafePathError, UserInputError
from tvtime_extractor.safety import (
    _WINDOWS_FILE_ATTRIBUTE_DIRECTORY,
    _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT,
    _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS,
    _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
    _WINDOWS_FILE_SHARE_DELETE,
    _WINDOWS_FILE_SHARE_READ,
    _WINDOWS_FILE_SHARE_WRITE,
    _WINDOWS_GENERIC_READ,
    EXTRACTION_DIRECTORY_NAME,
    _linux_volume_is_local,
    _windows_close_handle,
    _windows_create_file_directory_handle,
    _windows_create_file_regular_handle,
    _windows_directory_identity,
    _windows_open_locked_directory,
    _windows_regular_file_information,
    anchored_bound_output_root,
    anchored_existing_extraction_root,
    extended_acl_state,
    harden_private_descriptor,
    held_destination_parent,
    is_known_synced_or_shared_path,
    is_within,
    no_link_absolute_path,
    prepare_anchored_extraction_layout,
    prepare_extraction_layout,
    private_source_id,
    promote_directory_no_replace_atomic,
    promote_file_no_replace_atomic,
    read_regular_bytes,
    regular_binary_reader,
    require_bound_destination_parent,
    require_private_local_destination,
    require_private_path,
    safe_domain_component,
    safe_join,
    safe_manifest_relative_path,
    sanitize_public_url,
    secure_directory,
    write_bytes_private,
    write_csv_private,
    write_text_private,
)


@unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL regression")
class DarwinExtendedACLTests(unittest.TestCase):
    @staticmethod
    def _add_inheritable_acl(path: Path) -> None:
        subprocess.run(
            [
                "/bin/chmod",
                "+a",
                "everyone allow read,write,file_inherit,directory_inherit",
                str(path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def _open_directory(path: Path) -> int:
        flags = getattr(os, "O_SEARCH", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        return os.open(path, flags)

    def test_chmod_mode_bits_do_not_remove_inherited_acl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "acl-parent"
            parent.mkdir(mode=0o700)
            self._add_inheritable_acl(parent)
            output = parent / "private.bin"
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)

            output.chmod(0o600)
            descriptor = os.open(output, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                state = extended_acl_state(descriptor)
            finally:
                os.close(descriptor)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertGreater(state.entry_count, 0)
            self.assertGreater(state.inherited_entry_count, 0)

    def test_descriptor_hardening_clears_acl_and_preserves_identity_and_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "acl-parent"
            parent.mkdir(mode=0o700)
            self._add_inheritable_acl(parent)
            directory = parent / "private-directory"
            directory.mkdir(mode=0o700)
            output = parent / "private.bin"
            file_descriptor = os.open(
                output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            directory_descriptor = self._open_directory(directory)

            try:
                for descriptor, expected_type, mode in (
                    (file_descriptor, stat.S_IFREG, 0o600),
                    (directory_descriptor, stat.S_IFDIR, 0o700),
                ):
                    with self.subTest(expected_type=expected_type):
                        before = os.fstat(descriptor)
                        self.assertGreater(extended_acl_state(descriptor).entry_count, 0)
                        after = harden_private_descriptor(
                            descriptor,
                            expected_type=expected_type,
                            mode=mode,
                        )
                        self.assertEqual(
                            (before.st_dev, before.st_ino),
                            (after.st_dev, after.st_ino),
                        )
                        self.assertEqual(stat.S_IMODE(after.st_mode), mode)
                        self.assertEqual(extended_acl_state(descriptor).entry_count, 0)
            finally:
                os.close(file_descriptor)
                os.close(directory_descriptor)

    def test_private_directory_and_writer_clear_inherited_acl_before_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "acl-parent"
            parent.mkdir(mode=0o700)
            self._add_inheritable_acl(parent)

            intermediate = parent / "private-directory"
            directory = secure_directory(intermediate / "nested-directory")
            output = directory / "private.bin"
            write_bytes_private(output, b"synthetic", exclusive=True)

            self.assertEqual(self._path_acl_state(intermediate, directory=True).entry_count, 0)
            self.assertEqual(self._path_acl_state(directory, directory=True).entry_count, 0)
            self.assertEqual(self._path_acl_state(output, directory=False).entry_count, 0)

    def _path_acl_state(self, path: Path, *, directory: bool):
        descriptor = self._open_directory(path) if directory else os.open(path, os.O_RDONLY)
        try:
            return extended_acl_state(descriptor)
        finally:
            os.close(descriptor)

    def test_private_path_validator_rejects_read_acl_despite_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "private.bin"
            output.write_bytes(b"synthetic")
            output.chmod(0o600)
            subprocess.run(
                ["/bin/chmod", "+a", "everyone allow read", str(output)],
                check=True,
                capture_output=True,
                text=True,
            )
            with self.assertRaisesRegex(UserInputError, "extended ACL"):
                require_private_path(output, expected_type=stat.S_IFREG)

    def test_acl_inspection_failure_stops_before_private_bytes_are_written(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = secure_directory(Path(temporary) / "private-output")
            output = parent / "private.bin"
            real_extended_acl_state = extended_acl_state

            def fail_regular_file_acl_inspection(descriptor: int):
                if stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise OSError(errno.EOPNOTSUPP, "synthetic ACL inspection failure")
                return real_extended_acl_state(descriptor)

            with (
                mock.patch(
                    "tvtime_extractor.safety.extended_acl_state",
                    side_effect=fail_regular_file_acl_inspection,
                ),
                self.assertRaisesRegex(UserInputError, "permissions could not be applied safely"),
            ):
                write_bytes_private(output, b"private synthetic payload", exclusive=True)

            self.assertTrue(output.is_file())
            self.assertEqual(output.stat().st_size, 0)


class PortablePathTests(unittest.TestCase):
    def test_accepts_portable_manifest_path_and_domain(self) -> None:
        self.assertEqual(
            safe_manifest_relative_path("Library/Application Support/cache.db"),
            Path("Library", "Application Support", "cache.db"),
        )
        self.assertEqual(
            safe_domain_component("AppDomain-com.example.app"),
            "AppDomain-com.example.app",
        )

    def test_rejects_manifest_traversal_and_windows_hazards(self) -> None:
        unsafe = (
            "../outside",
            "/absolute/path",
            "Library\\Preferences",
            "Library//Preferences",
            "Library/../Preferences",
            "Library/CON",
            "Library/name.",
            "Library/bad:name",
            "Library/has\x00nul",
        )
        for value in unsafe:
            with self.subTest(value=value), self.assertRaises(ValueError):
                safe_manifest_relative_path(value)

    def test_rejects_unsafe_domain_components(self) -> None:
        for value in ("../domain", "domain/name", "domain\\name", "NUL", "bad:name"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                safe_domain_component(value)

    def test_safe_join_cannot_escape_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            with self.assertRaises(ValueError):
                safe_join(root, "..", "outside")

    @unittest.skipIf(os.name == "nt", "symbolic-link creation varies on Windows")
    def test_safe_join_refuses_nested_symbolic_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "linked").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                safe_join(root, "linked", "private.db")


class DestinationSafetyTests(unittest.TestCase):
    @staticmethod
    def _backup(base: Path) -> Path:
        backup = base / "backup"
        backup.mkdir()
        (backup / "Manifest.plist").write_bytes(b"synthetic manifest")
        (backup / "Manifest.db").write_bytes(b"synthetic encrypted manifest database")
        return backup

    def test_creates_private_fresh_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = self._backup(base)
            layout = prepare_extraction_layout(backup, base / "private-output")
            self.assertEqual(layout.extraction_root.name, EXTRACTION_DIRECTORY_NAME)
            self.assertTrue(layout.raw_root.is_dir())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(layout.extraction_root.stat().st_mode), 0o700)

    @unittest.skipUnless(
        sys.platform == "darwin" or sys.platform.startswith("linux"),
        "native atomic no-replace primitive is exercised on macOS and Linux",
    )
    def test_atomic_directory_promotion_never_replaces_an_existing_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            staging = root / "staging"
            destination = root / "destination"
            staging.mkdir(mode=0o700)
            destination.mkdir(mode=0o700)
            staging_identity = (staging.stat().st_dev, staging.stat().st_ino)
            destination_identity = (destination.stat().st_dev, destination.stat().st_ino)

            with self.assertRaises(OutputExistsError):
                promote_directory_no_replace_atomic(staging, destination, durable=True)

            self.assertEqual(
                (staging.stat().st_dev, staging.stat().st_ino),
                staging_identity,
            )
            self.assertEqual(
                (destination.stat().st_dev, destination.stat().st_ino),
                destination_identity,
            )

    @unittest.skipUnless(
        sys.platform == "darwin" or sys.platform.startswith("linux"),
        "native atomic no-replace primitive is exercised on macOS and Linux",
    )
    def test_atomic_directory_promotion_preserves_the_staged_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            staging = root / "staging"
            destination = root / "destination"
            staging.mkdir(mode=0o700)
            staged_identity = (staging.stat().st_dev, staging.stat().st_ino)

            promote_directory_no_replace_atomic(staging, destination, durable=True)

            self.assertFalse(staging.exists())
            self.assertEqual(
                (destination.stat().st_dev, destination.stat().st_ino),
                staged_identity,
            )

    @unittest.skipUnless(
        sys.platform == "darwin" or sys.platform.startswith("linux"),
        "native atomic no-replace primitive is exercised on macOS and Linux",
    )
    def test_atomic_directory_promotion_rejects_destination_created_at_syscall_boundary(
        self,
    ) -> None:
        from tvtime_extractor.safety import _rename_directory_no_replace

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            staging = root / "staging"
            destination = root / "destination"
            staging.mkdir(mode=0o700)
            staging_identity = (staging.stat().st_dev, staging.stat().st_ino)
            raced_identity: tuple[int, int] | None = None

            def race_then_invoke_native_primitive(
                *,
                source_parent_descriptor: int,
                destination_parent_descriptor: int,
                source: Path,
                destination: Path,
            ) -> None:
                nonlocal raced_identity
                os.mkdir(
                    destination.name,
                    mode=0o700,
                    dir_fd=destination_parent_descriptor,
                )
                metadata = os.stat(
                    destination.name,
                    dir_fd=destination_parent_descriptor,
                    follow_symlinks=False,
                )
                raced_identity = (metadata.st_dev, metadata.st_ino)
                _rename_directory_no_replace(
                    source_parent_descriptor=source_parent_descriptor,
                    destination_parent_descriptor=destination_parent_descriptor,
                    source=source,
                    destination=destination,
                )

            with (
                mock.patch(
                    "tvtime_extractor.safety._rename_directory_no_replace",
                    side_effect=race_then_invoke_native_primitive,
                ),
                self.assertRaises(OutputExistsError),
            ):
                promote_directory_no_replace_atomic(staging, destination, durable=True)

            self.assertIsNotNone(raced_identity)
            self.assertEqual(
                (staging.stat().st_dev, staging.stat().st_ino),
                staging_identity,
            )
            self.assertEqual(
                (destination.stat().st_dev, destination.stat().st_ino),
                raced_identity,
            )

    @unittest.skipUnless(
        sys.platform == "darwin" or sys.platform.startswith("linux"),
        "native atomic no-replace primitive is exercised on macOS and Linux",
    )
    def test_atomic_file_promotion_across_private_directories_preserves_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            staging_parent = root / "staging"
            destination_parent = root / "destination"
            staging_parent.mkdir(mode=0o700)
            destination_parent.mkdir(mode=0o700)
            staging = staging_parent / "payload.partial"
            destination = destination_parent / "payload.bin"
            write_bytes_private(staging, b"synthetic plaintext", exclusive=True)
            staged_identity = (staging.stat().st_dev, staging.stat().st_ino)

            promote_file_no_replace_atomic(
                staging,
                destination,
                expected_identity=staged_identity,
                durable=True,
            )

            self.assertFalse(staging.exists())
            self.assertEqual(destination.read_bytes(), b"synthetic plaintext")
            self.assertEqual(
                (destination.stat().st_dev, destination.stat().st_ino),
                staged_identity,
            )

    @unittest.skipUnless(
        sys.platform == "darwin" or sys.platform.startswith("linux"),
        "native atomic no-replace primitive is exercised on macOS and Linux",
    )
    def test_atomic_file_promotion_never_replaces_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            staging_parent = root / "staging"
            destination_parent = root / "destination"
            staging_parent.mkdir(mode=0o700)
            destination_parent.mkdir(mode=0o700)
            staging = staging_parent / "payload.partial"
            destination = destination_parent / "payload.bin"
            write_bytes_private(staging, b"new synthetic plaintext", exclusive=True)
            write_bytes_private(destination, b"existing synthetic plaintext", exclusive=True)
            staged_identity = (staging.stat().st_dev, staging.stat().st_ino)
            destination_identity = (destination.stat().st_dev, destination.stat().st_ino)

            with self.assertRaises(OutputExistsError):
                promote_file_no_replace_atomic(
                    staging,
                    destination,
                    expected_identity=staged_identity,
                    durable=True,
                )

            self.assertEqual(staging.read_bytes(), b"new synthetic plaintext")
            self.assertEqual(destination.read_bytes(), b"existing synthetic plaintext")
            self.assertEqual(
                (destination.stat().st_dev, destination.stat().st_ino),
                destination_identity,
            )

    @unittest.skipUnless(
        sys.platform == "darwin" or sys.platform.startswith("linux"),
        "native atomic no-replace primitive is exercised on macOS and Linux",
    )
    def test_atomic_file_promotion_rejects_unexpected_staged_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            staging_parent = root / "staging"
            destination_parent = root / "destination"
            staging_parent.mkdir(mode=0o700)
            destination_parent.mkdir(mode=0o700)
            staging = staging_parent / "payload.partial"
            destination = destination_parent / "payload.bin"
            write_bytes_private(staging, b"synthetic plaintext", exclusive=True)

            with self.assertRaisesRegex(UnsafePathError, "identity changed"):
                promote_file_no_replace_atomic(
                    staging,
                    destination,
                    expected_identity=(0, 0),
                    durable=True,
                )

            self.assertTrue(staging.is_file())
            self.assertFalse(destination.exists())

    @unittest.skipIf(os.name == "nt", "Descriptor-relative directory creation is POSIX-only")
    def test_bound_parent_creates_full_layout_inside_held_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = self._backup(base)
            destination = base / "destination"
            destination.mkdir(mode=0o700)
            descriptor = os.open(
                destination,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                metadata = os.fstat(descriptor)
                identity = (int(metadata.st_dev), int(metadata.st_ino))
                output = destination / "fresh-output"
                self.assertEqual(
                    require_bound_destination_parent(
                        output,
                        destination_parent_descriptor=descriptor,
                        expected_identity=identity,
                    ),
                    no_link_absolute_path(destination),
                )
                with anchored_bound_output_root(
                    output,
                    destination_parent_descriptor=descriptor,
                    expected_parent_identity=identity,
                ):
                    layout = prepare_anchored_extraction_layout(backup)
                    self.assertEqual(layout.output_root, Path("."))
                    self.assertTrue(layout.raw_root.is_dir())
                self.assertTrue((output / EXTRACTION_DIRECTORY_NAME / "raw").is_dir())
                self.assertTrue(stat.S_ISDIR(os.fstat(descriptor).st_mode))
            finally:
                os.close(descriptor)

    @unittest.skipIf(os.name == "nt", "Descriptor identity binding is POSIX-only")
    def test_bound_parent_rejects_path_substitution_without_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = self._backup(base)
            destination = base / "destination"
            moved = base / "moved-destination"
            destination.mkdir(mode=0o700)
            descriptor = os.open(
                destination,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                metadata = os.fstat(descriptor)
                identity = (int(metadata.st_dev), int(metadata.st_ino))
                destination.rename(moved)
                destination.mkdir(mode=0o700)
                output = destination / "fresh-output"

                with (
                    self.assertRaisesRegex(UserInputError, "parent path changed"),
                    anchored_bound_output_root(
                        output,
                        destination_parent_descriptor=descriptor,
                        expected_parent_identity=identity,
                    ),
                ):
                    prepare_anchored_extraction_layout(backup)
                self.assertFalse(output.exists())
                self.assertFalse((moved / output.name).exists())
            finally:
                os.close(descriptor)

    @unittest.skipIf(os.name == "nt", "Output-root descriptor anchoring is POSIX-only")
    def test_anchored_output_writes_stay_in_original_root_and_substitution_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            destination = base / "destination"
            destination.mkdir(mode=0o700)
            descriptor = os.open(
                destination,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                metadata = os.fstat(descriptor)
                identity = (int(metadata.st_dev), int(metadata.st_ino))
                output = destination / "fresh-output"
                moved = destination / "moved-output"
                cwd_identity = (int(Path(".").stat().st_dev), int(Path(".").stat().st_ino))
                with (
                    self.assertRaisesRegex(UserInputError, "destination identity changed"),
                    anchored_bound_output_root(
                        output,
                        destination_parent_descriptor=descriptor,
                        expected_parent_identity=identity,
                    ),
                ):
                    output.rename(moved)
                    output.mkdir(mode=0o700)
                    write_text_private(Path("private.txt"), "synthetic private payload")

                self.assertEqual(
                    (int(Path(".").stat().st_dev), int(Path(".").stat().st_ino)),
                    cwd_identity,
                )
                self.assertEqual(
                    (moved / "private.txt").read_text(encoding="utf-8"),
                    "synthetic private payload",
                )
                self.assertFalse((output / "private.txt").exists())
            finally:
                os.close(descriptor)

    @unittest.skipIf(os.name == "nt", "Output-root descriptor anchoring is POSIX-only")
    def test_anchored_output_restores_cwd_on_body_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            descriptor = os.open(
                destination,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                metadata = os.fstat(descriptor)
                identity = (int(metadata.st_dev), int(metadata.st_ino))
                cwd_identity = (int(Path(".").stat().st_dev), int(Path(".").stat().st_ino))
                opened_descriptors: list[int] = []
                real_open = os.open

                def tracked_open(*args: object, **kwargs: object) -> int:
                    opened = real_open(*args, **kwargs)
                    opened_descriptors.append(opened)
                    return opened

                with (
                    mock.patch("tvtime_extractor.safety.os.open", side_effect=tracked_open),
                    self.assertRaisesRegex(RuntimeError, "synthetic cancellation"),
                    anchored_bound_output_root(
                        destination / "fresh-output",
                        destination_parent_descriptor=descriptor,
                        expected_parent_identity=identity,
                    ),
                ):
                    raise RuntimeError("synthetic cancellation")
                self.assertEqual(
                    (int(Path(".").stat().st_dev), int(Path(".").stat().st_ino)),
                    cwd_identity,
                )
                self.assertGreaterEqual(len(opened_descriptors), 2)
                for opened in opened_descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(opened)
            finally:
                os.close(descriptor)

    @unittest.skipIf(os.name == "nt", "Output-root descriptor anchoring is POSIX-only")
    def test_anchored_output_closes_every_descriptor_when_cwd_restore_reports_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            descriptor = os.open(
                destination,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                metadata = os.fstat(descriptor)
                identity = (int(metadata.st_dev), int(metadata.st_ino))
                cwd_identity = (int(Path(".").stat().st_dev), int(Path(".").stat().st_ino))
                opened_descriptors: list[int] = []
                real_open = os.open
                real_fchdir = os.fchdir
                fchdir_calls = 0

                def tracked_open(*args: object, **kwargs: object) -> int:
                    opened = real_open(*args, **kwargs)
                    opened_descriptors.append(opened)
                    return opened

                def restore_then_report_failure(opened: int) -> None:
                    nonlocal fchdir_calls
                    fchdir_calls += 1
                    real_fchdir(opened)
                    if fchdir_calls == 2:
                        raise OSError("synthetic cwd restore failure")

                with (
                    mock.patch("tvtime_extractor.safety.os.open", side_effect=tracked_open),
                    mock.patch(
                        "tvtime_extractor.safety.os.fchdir",
                        side_effect=restore_then_report_failure,
                    ),
                    self.assertRaisesRegex(OSError, "synthetic cwd restore failure"),
                    anchored_bound_output_root(
                        destination / "fresh-output",
                        destination_parent_descriptor=descriptor,
                        expected_parent_identity=identity,
                    ),
                ):
                    pass

                self.assertEqual(
                    (int(Path(".").stat().st_dev), int(Path(".").stat().st_ino)),
                    cwd_identity,
                )
                self.assertEqual(fchdir_calls, 2)
                self.assertGreaterEqual(len(opened_descriptors), 2)
                for opened in opened_descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(opened)
            finally:
                os.close(descriptor)

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-root behavior is tested on POSIX")
    def test_existing_root_substitution_receives_no_private_writes_and_fails_final_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            extraction = base / "synthetic-extraction"
            moved = base / "moved-extraction"
            extraction.mkdir(mode=0o700)
            original_cwd = Path(".").stat()

            with (
                self.assertRaisesRegex(UserInputError, "extraction identity changed"),
                anchored_existing_extraction_root(extraction) as anchored,
            ):
                self.assertEqual(anchored, Path("."))
                extraction.rename(moved)
                extraction.mkdir(mode=0o700)
                write_text_private(Path("private-analysis.txt"), "synthetic private payload")

            current_cwd = Path(".").stat()
            self.assertEqual(
                (int(current_cwd.st_dev), int(current_cwd.st_ino)),
                (int(original_cwd.st_dev), int(original_cwd.st_ino)),
            )
            self.assertEqual(
                (moved / "private-analysis.txt").read_text(encoding="utf-8"),
                "synthetic private payload",
            )
            self.assertFalse((extraction / "private-analysis.txt").exists())

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-root behavior is tested on POSIX")
    def test_existing_root_restores_cwd_and_closes_fds_after_body_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = Path(temporary) / "synthetic-extraction"
            extraction.mkdir(mode=0o700)
            original_cwd = Path(".").stat()
            opened_descriptors: list[int] = []
            real_open = os.open

            def tracked_open(*args: object, **kwargs: object) -> int:
                descriptor = real_open(*args, **kwargs)
                opened_descriptors.append(descriptor)
                return descriptor

            with (
                mock.patch("tvtime_extractor.safety.os.open", side_effect=tracked_open),
                self.assertRaisesRegex(RuntimeError, "synthetic body failure"),
                anchored_existing_extraction_root(extraction),
            ):
                raise RuntimeError("synthetic body failure")

            current_cwd = Path(".").stat()
            self.assertEqual(
                (int(current_cwd.st_dev), int(current_cwd.st_ino)),
                (int(original_cwd.st_dev), int(original_cwd.st_ino)),
            )
            self.assertGreaterEqual(len(opened_descriptors), 2)
            for descriptor in opened_descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    @unittest.skipIf(os.name == "nt", "POSIX descriptor closure is tested on POSIX")
    def test_held_parent_preserves_body_oserror_and_closes_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fresh-output"
            held: list[int] = []
            with (
                self.assertRaises(OSError) as raised,
                held_destination_parent(output) as (descriptor, _identity, _visible),
            ):
                held.append(descriptor)
                raise OSError(errno.ENOSPC, "synthetic full destination")
            self.assertEqual(raised.exception.errno, errno.ENOSPC)
            self.assertEqual(len(held), 1)
            with self.assertRaises(OSError):
                os.fstat(held[0])

    @unittest.skipIf(os.name == "nt", "Windows does not change the process cwd")
    def test_existing_root_rejects_unknown_background_threads_before_chdir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = Path(temporary) / "synthetic-extraction"
            extraction.mkdir(mode=0o700)
            stop = threading.Event()
            worker = threading.Thread(
                target=stop.wait,
                name="synthetic-unrelated-worker",
                daemon=True,
            )
            worker.start()
            try:
                with (
                    self.assertRaisesRegex(UserInputError, "dedicated process"),
                    anchored_existing_extraction_root(extraction),
                ):
                    pass
            finally:
                stop.set()
                worker.join(timeout=5)

    @unittest.skipIf(os.name == "nt", "POSIX wrapper anchoring is tested on POSIX")
    def test_public_analyze_wrapper_keeps_writes_in_renamed_original_root(self) -> None:
        from tvtime_extractor.analyze import analyze_extraction

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            extraction = base / "synthetic-extraction"
            moved = base / "moved-extraction"
            extraction.mkdir(mode=0o700)

            def substitute_during_analysis(**kwargs: object) -> dict[str, object]:
                self.assertEqual(kwargs["extraction_directory"], Path("."))
                extraction.rename(moved)
                extraction.mkdir(mode=0o700)
                write_text_private(Path("synthetic-analysis.txt"), "private synthetic analysis")
                return {}

            with (
                mock.patch(
                    "tvtime_extractor.analyze._analyze_extraction",
                    side_effect=substitute_during_analysis,
                ),
                self.assertRaisesRegex(UserInputError, "extraction identity changed"),
            ):
                analyze_extraction(extraction_directory=extraction)

            self.assertEqual(
                (moved / "synthetic-analysis.txt").read_text(encoding="utf-8"),
                "private synthetic analysis",
            )
            self.assertFalse((extraction / "synthetic-analysis.txt").exists())

    @unittest.skipIf(os.name == "nt", "POSIX wrapper anchoring is tested on POSIX")
    def test_public_report_wrapper_anchors_root_and_rebases_visible_paths(self) -> None:
        from tvtime_extractor.report import build_report

        with tempfile.TemporaryDirectory() as temporary:
            extraction = Path(temporary) / "synthetic-extraction"
            extraction.mkdir(mode=0o700)
            synthetic_result = {
                "report": "analysis/synthetic.md",
                "visual_report": "analysis/synthetic.html",
                "pdf_report": "analysis/synthetic.pdf",
            }

            def synthetic_report(**kwargs: object) -> dict[str, object]:
                self.assertEqual(kwargs["extraction_directory"], Path("."))
                return dict(synthetic_result)

            with mock.patch(
                "tvtime_extractor.report._build_report",
                side_effect=synthetic_report,
            ):
                result = build_report(extraction_directory=extraction)

            visible_extraction = no_link_absolute_path(extraction)
            self.assertEqual(result["report"], str(visible_extraction / "analysis/synthetic.md"))
            self.assertEqual(
                result["visual_report"],
                str(visible_extraction / "analysis/synthetic.html"),
            )
            self.assertEqual(
                result["pdf_report"],
                str(visible_extraction / "analysis/synthetic.pdf"),
            )
            with (
                mock.patch(
                    "tvtime_extractor.report._build_report",
                    return_value={"report": str(Path(temporary) / "escaped.md")},
                ),
                self.assertRaisesRegex(UserInputError, "escaped its held extraction root"),
            ):
                build_report(extraction_directory=extraction)

    def test_refuses_overlap_existing_output_and_git_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = self._backup(base)
            with self.assertRaises(UserInputError):
                prepare_extraction_layout(backup, backup / "output")

            output = base / "private-output"
            (output / EXTRACTION_DIRECTORY_NAME).mkdir(parents=True)
            with self.assertRaises(UserInputError):
                prepare_extraction_layout(backup, output)

            repository = base / "repository"
            (repository / ".git").mkdir(parents=True)
            with self.assertRaises(UserInputError):
                prepare_extraction_layout(backup, repository / "private-output")

    def test_refuses_case_variant_backup_alias_before_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = base / "BackupCase"
            backup.mkdir()
            (backup / "Manifest.plist").write_bytes(b"synthetic manifest")
            (backup / "Manifest.db").write_bytes(b"synthetic encrypted manifest database")
            output = base / "backupcase" / "FreshOutput"

            with self.assertRaisesRegex(UserInputError, "must not overlap"):
                prepare_extraction_layout(backup, output)

            self.assertFalse(output.exists())

    def test_physical_ancestor_identity_detects_bind_mount_style_alias(self) -> None:
        output = Path("/synthetic-alias/backup/fresh-output")
        backup = Path("/synthetic-source/backup")
        output_ancestry = (
            ((7, 21), ("fresh-output",)),
            ((7, 10), ("backup", "fresh-output")),
        )
        backup_ancestry = (
            ((7, 21), ()),
            ((7, 10), ("backup",)),
        )
        with mock.patch(
            "tvtime_extractor.safety._path_ancestry_tails",
            side_effect=(output_ancestry, backup_ancestry),
        ):
            self.assertTrue(is_within(output, backup))

    def test_refuses_existing_output_without_changing_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = self._backup(base)
            output = base / "existing-output"
            output.mkdir(mode=0o755)
            sentinel = output / "synthetic-sentinel.txt"
            sentinel.write_text("unchanged", encoding="utf-8")
            before_mode = stat.S_IMODE(output.stat().st_mode)

            with self.assertRaisesRegex(UserInputError, "already exists"):
                prepare_extraction_layout(backup, output)

            self.assertEqual(stat.S_IMODE(output.stat().st_mode), before_mode)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")

    @unittest.skipIf(os.name == "nt", "symbolic-link permissions vary on Windows")
    def test_refuses_symbolic_link_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = self._backup(base)
            actual = base / "actual-output"
            actual.mkdir()
            linked = base / "linked-output"
            linked.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(UserInputError):
                prepare_extraction_layout(backup, linked)

    @unittest.skipIf(os.name == "nt", "symbolic-link creation varies on Windows")
    def test_refuses_symbolic_link_ancestor_for_fresh_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backup = self._backup(base)
            actual_parent = base / "actual-parent"
            actual_parent.mkdir()
            linked_parent = base / "linked-parent"
            linked_parent.symlink_to(actual_parent, target_is_directory=True)

            with self.assertRaisesRegex(UserInputError, "symbolic link"):
                prepare_extraction_layout(backup, linked_parent / "fresh-output")

            self.assertFalse((actual_parent / "fresh-output").exists())

    @unittest.skipIf(os.name == "nt", "symbolic-link creation varies on Windows")
    def test_refuses_symbolic_link_ancestor_for_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            actual_parent = base / "actual-parent"
            actual_parent.mkdir()
            backup = self._backup(actual_parent)
            linked_parent = base / "linked-parent"
            linked_parent.symlink_to(actual_parent, target_is_directory=True)

            with self.assertRaisesRegex(UserInputError, "symbolic link"):
                prepare_extraction_layout(
                    linked_parent / backup.name,
                    base / "fresh-output",
                )

            self.assertFalse((base / "fresh-output").exists())

    def test_rejects_known_cloud_shared_and_nonlocal_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            home = base / "home"
            home.mkdir()
            safe = home / "Documents" / "Private Recovery"
            cloud_candidates = (
                home / "Library" / "CloudStorage" / "Provider" / "Recovery",
                home / "Library" / "Mobile Documents" / "com~apple~CloudDocs" / "Recovery",
                home / "Library" / "Application Support" / "FileProvider" / "Recovery",
                home / "OneDrive - Example" / "Recovery",
                home / "Dropbox" / "Recovery",
                home / "Public" / "Recovery",
            )
            for candidate in cloud_candidates:
                with self.subTest(candidate=candidate.name):
                    self.assertTrue(
                        is_known_synced_or_shared_path(
                            candidate,
                            home_directory=home,
                            environment={},
                        )
                    )
            self.assertFalse(
                is_known_synced_or_shared_path(
                    safe,
                    home_directory=home,
                    environment={},
                )
            )

            local_parent = base / "local"
            local_parent.mkdir()
            with mock.patch("tvtime_extractor.safety._volume_is_local", return_value=True):
                self.assertEqual(
                    require_private_local_destination(local_parent / "fresh-output"),
                    no_link_absolute_path(local_parent),
                )
            with (
                mock.patch("tvtime_extractor.safety._volume_is_local", return_value=False),
                self.assertRaisesRegex(UserInputError, "confirmed as local"),
            ):
                require_private_local_destination(local_parent / "fresh-output")

    @unittest.skipIf(os.name == "nt", "synthetic Linux mount paths require POSIX paths")
    def test_linux_local_filesystem_allowlist_and_untrusted_mounts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            destination = base / "private" / "new-run"
            destination.parent.mkdir()
            mountinfo = base / "mountinfo"
            for filesystem_type in (
                "bcachefs",
                "btrfs",
                "ecryptfs",
                "ext2",
                "ext3",
                "ext4",
                "f2fs",
                "jfs",
                "xfs",
                "zfs",
            ):
                with self.subTest(filesystem_type=filesystem_type):
                    source = "private-pool/dataset" if filesystem_type == "zfs" else "/dev/dm-0"
                    mountinfo.write_text(
                        f"24 1 0:24 / {base} rw,relatime - {filesystem_type} {source} rw\n",
                        encoding="utf-8",
                    )
                    self.assertTrue(_linux_volume_is_local(destination, mountinfo_path=mountinfo))

            rejected_types = (
                "9p",
                "drvfs",
                "fuse",
                "fuse.local-example",
                "fuse.sshfs",
                "hgfs",
                "mysteryfs",
                "nfs",
                "overlay",
                "prl_fs",
                "tmpfs",
                "vboxsf",
                "virtiofs",
            )
            for filesystem_type in rejected_types:
                with self.subTest(filesystem_type=filesystem_type):
                    mountinfo.write_text(
                        f"24 1 0:24 / {base} rw,relatime - {filesystem_type} /dev/synthetic rw\n",
                        encoding="utf-8",
                    )
                    self.assertFalse(_linux_volume_is_local(destination, mountinfo_path=mountinfo))

            mountinfo.write_text(
                f"24 1 0:24 / {base} rw,relatime - ext4 host:/private rw\n",
                encoding="utf-8",
            )
            self.assertFalse(_linux_volume_is_local(destination, mountinfo_path=mountinfo))

            mountinfo.write_text("malformed synthetic record\n", encoding="utf-8")
            self.assertFalse(_linux_volume_is_local(destination, mountinfo_path=mountinfo))

    @unittest.skipIf(os.name == "nt", "synthetic Linux mount paths require POSIX paths")
    def test_linux_stacked_mountpoints_are_rejected_regardless_of_record_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            destination = base / "new-run"
            mountinfo = base / "mountinfo"
            local = f"24 1 0:24 / {base} rw,relatime - ext4 /dev/dm-0 rw"
            remote = f"25 1 0:25 / {base} rw,relatime - nfs host:/private rw"
            for records in ((local, remote), (remote, local)):
                with self.subTest(records=records):
                    mountinfo.write_text("\n".join(records) + "\n", encoding="utf-8")
                    self.assertFalse(_linux_volume_is_local(destination, mountinfo_path=mountinfo))


class WindowsDirectoryHandleContractTests(unittest.TestCase):
    class _Kernel32:
        def __init__(self, *, reparse: bool = False, directory: bool = True) -> None:
            self.reparse = reparse
            self.directory = directory
            self.create_calls: list[tuple[object, ...]] = []
            self.closed: list[int] = []

        def CreateFileW(self, *arguments: object) -> int:
            self.create_calls.append(arguments)
            return 101

        def GetFileInformationByHandle(self, _handle: object, pointer: object) -> int:
            information = pointer._obj  # type: ignore[attr-defined]
            information.file_attributes = _WINDOWS_FILE_ATTRIBUTE_DIRECTORY if self.directory else 0
            if self.reparse:
                information.file_attributes |= _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
            information.volume_serial_number = 7
            information.file_index_high = 1
            information.file_index_low = 11
            information.file_size_high = 2
            information.file_size_low = 17
            information.last_write_time.high = 3
            information.last_write_time.low = 19
            return 1

        def CloseHandle(self, handle: object) -> int:
            value = ctypes.cast(handle, ctypes.c_void_p).value
            assert value is not None
            self.closed.append(int(value))
            return 1

    def test_createfile_contract_denies_delete_sharing_and_binds_stable_identity(self) -> None:
        kernel32 = self._Kernel32()
        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch("tvtime_extractor.safety._windows_kernel32", return_value=kernel32),
        ):
            handle = _windows_create_file_directory_handle(Path("C:/Synthetic/Private"))
            identity = _windows_directory_identity(handle)
            _windows_close_handle(handle)

        self.assertEqual(identity, (7, (1 << 32) | 11))
        self.assertEqual(kernel32.closed, [101])
        self.assertEqual(len(kernel32.create_calls), 1)
        call = kernel32.create_calls[0]
        share_mode = int(call[2])
        flags = int(call[5])
        self.assertEqual(share_mode, _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE)
        self.assertFalse(share_mode & _WINDOWS_FILE_SHARE_DELETE)
        self.assertTrue(flags & _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS)
        self.assertTrue(flags & _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT)

    def test_reparse_directory_fails_closed_and_closes_the_opened_handle(self) -> None:
        kernel32 = self._Kernel32(reparse=True)
        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch("tvtime_extractor.safety._windows_kernel32", return_value=kernel32),
            self.assertRaisesRegex(UserInputError, "reparse point"),
        ):
            _windows_open_locked_directory(Path("C:/Synthetic/Reparse"))
        self.assertEqual(kernel32.closed, [101])

    def test_regular_file_contract_denies_write_delete_and_reparse_traversal(self) -> None:
        kernel32 = self._Kernel32(directory=False)
        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch("tvtime_extractor.safety._windows_kernel32", return_value=kernel32),
        ):
            handle = _windows_create_file_regular_handle(Path("C:/Synthetic/private.bin"))
            information = _windows_regular_file_information(handle)
            _windows_close_handle(handle)

        self.assertEqual(information.identity, (7, (1 << 32) | 11))
        self.assertEqual(information.byte_size, (2 << 32) | 17)
        self.assertEqual(information.last_write_time, (3 << 32) | 19)
        self.assertEqual(kernel32.closed, [101])
        call = kernel32.create_calls[0]
        self.assertEqual(int(call[1]), _WINDOWS_GENERIC_READ)
        self.assertEqual(int(call[2]), _WINDOWS_FILE_SHARE_READ)
        self.assertFalse(int(call[2]) & _WINDOWS_FILE_SHARE_WRITE)
        self.assertFalse(int(call[2]) & _WINDOWS_FILE_SHARE_DELETE)
        self.assertTrue(int(call[5]) & _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT)
        self.assertFalse(int(call[5]) & _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS)

    def test_regular_file_information_rejects_reparse_and_directory_attributes(self) -> None:
        for label, kernel32 in (
            ("reparse", self._Kernel32(reparse=True, directory=False)),
            ("directory", self._Kernel32(directory=True)),
        ):
            with (
                self.subTest(label=label),
                mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
                mock.patch("tvtime_extractor.safety._windows_kernel32", return_value=kernel32),
                self.assertRaises(UnsafePathError),
            ):
                _windows_regular_file_information(101)

    @unittest.skipUnless(os.name == "nt", "real Win32 locked-file regression")
    def test_windows_regular_reader_locks_identity_and_denies_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "private.bin"
            replacement = root / "replacement.bin"
            payload = b"synthetic-private-payload"
            target.write_bytes(payload)
            replacement.write_bytes(b"replacement")
            with regular_binary_reader(target) as (handle, metadata):
                self.assertEqual(handle.read(), payload)
                self.assertEqual(metadata.st_size, len(payload))
                with self.assertRaises(OSError):
                    target.write_bytes(b"changed")
                with self.assertRaises(OSError):
                    os.replace(replacement, target)
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(
                read_regular_bytes(target, maximum_bytes=len(payload)),
                payload,
            )
            with self.assertRaisesRegex(UnsafePathError, "unsafe file type or byte size"):
                read_regular_bytes(target, maximum_bytes=len(payload) - 1)

    def test_regular_reader_normalizes_body_read_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "synthetic-private.bin"
            target.write_bytes(b"synthetic-private-payload")
            with (
                self.assertRaisesRegex(UnsafePathError, "could not be read safely"),
                regular_binary_reader(target),
            ):
                raise OSError(errno.EIO, "synthetic read failure")

    def test_windows_parent_handle_is_held_through_body_and_closed_on_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fresh-output"
            closed: list[int] = []
            with (
                mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
                mock.patch(
                    "tvtime_extractor.safety._windows_open_locked_directory",
                    return_value=(101, (7, 11)),
                ),
                mock.patch(
                    "tvtime_extractor.safety.require_bound_destination_parent",
                    return_value=output.parent,
                ),
                mock.patch(
                    "tvtime_extractor.safety._windows_close_handle",
                    side_effect=closed.append,
                ),
                self.assertRaisesRegex(RuntimeError, "synthetic body failure"),
                held_destination_parent(output) as (handle, identity, visible),
            ):
                self.assertEqual(
                    (handle, identity, visible),
                    (101, (7, 11), no_link_absolute_path(output)),
                )
                self.assertEqual(closed, [])
                raise RuntimeError("synthetic body failure")
            self.assertEqual(closed, [101])

    def test_windows_fresh_output_fails_before_create_or_handle_open(self) -> None:
        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch("tvtime_extractor.safety.os.mkdir") as mkdir,
            mock.patch("tvtime_extractor.safety._windows_open_locked_directory") as open_root,
            self.assertRaisesRegex(UserInputError, "not supported on Windows"),
            anchored_bound_output_root(
                Path("/synthetic/private/fresh-output"),
                destination_parent_descriptor=99,
                expected_parent_identity=(5, 6),
            ),
        ):
            pass
        mkdir.assert_not_called()
        open_root.assert_not_called()

    def test_windows_existing_root_is_held_validated_and_closed_on_body_failure(self) -> None:
        identity = (7, 11)
        closed: list[int] = []
        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch(
                "tvtime_extractor.safety._windows_open_locked_directory",
                return_value=(101, identity),
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_directory_identity",
                return_value=identity,
            ),
            mock.patch(
                "tvtime_extractor.safety._require_visible_existing_directory_identity"
            ) as visible,
            mock.patch(
                "tvtime_extractor.safety._windows_close_handle",
                side_effect=closed.append,
            ),
            self.assertRaisesRegex(RuntimeError, "synthetic body failure"),
            anchored_existing_extraction_root(
                Path("/synthetic/private/TVTime-Extraction")
            ) as bound,
        ):
            self.assertTrue(bound.is_absolute())
            self.assertEqual(closed, [])
            raise RuntimeError("synthetic body failure")

        visible.assert_called_once()
        self.assertEqual(closed, [101])


class SanitizationTests(unittest.TestCase):
    def test_source_ids_are_stable_and_do_not_reveal_cache_keys(self) -> None:
        source_id = private_source_id("private-account-key", "private-account-subkey")
        self.assertEqual(
            source_id,
            private_source_id("private-account-key", "private-account-subkey"),
        )
        self.assertRegex(source_id, r"^[0-9a-f]{24}$")
        self.assertNotIn("private", source_id)

    def test_public_url_removes_private_components(self) -> None:
        self.assertEqual(
            sanitize_public_url("https://www.youtube.com/watch?v=demo-video&token=secret#fragment"),
            "https://www.youtube.com/watch?v=demo-video",
        )
        self.assertEqual(
            sanitize_public_url("https://cdn.example.invalid/image.jpg?token=secret#fragment"),
            "https://cdn.example.invalid/image.jpg",
        )
        self.assertEqual(
            sanitize_public_url("https://username:password@example.invalid/private"),
            "",
        )
        self.assertEqual(sanitize_public_url("file:///private/export"), "")

    def test_private_writer_uses_private_file_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "private.txt"
            write_text_private(output, "synthetic\nportable\n")
            self.assertEqual(output.read_bytes(), b"synthetic\nportable\n")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_csv_writer_neutralizes_spreadsheet_formulas(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "private.csv"
            write_csv_private(
                output,
                [
                    {"title": '=WEBSERVICE("https://example.invalid")'},
                    {"title": "普通の番組"},
                ],
                ["title"],
            )
            with output.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[0]["title"], '\'=WEBSERVICE("https://example.invalid")')
            self.assertEqual(rows[1]["title"], "普通の番組")


if __name__ == "__main__":
    unittest.main()
