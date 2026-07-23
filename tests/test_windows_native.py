from __future__ import annotations

import contextlib
import ctypes
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from tvtime_extractor import windows_native
from tvtime_extractor.safety import _windows_close_handle, _windows_open_locked_directory


class WindowsNativeUnitTests(unittest.TestCase):
    def test_component_validation_rejects_traversal_and_reserved_separators(self) -> None:
        for value in ("", ".", "..", "nested/name", "nested\\name", "bad:name", "bad\x00name"):
            with self.subTest(value=value), self.assertRaises(windows_native.WindowsNativeError):
                windows_native.validate_component(value)
        self.assertEqual(windows_native.validate_component("synthetic-output"), "synthetic-output")

    def test_collision_status_is_sanitized_without_loading_windows_libraries(self) -> None:
        error = windows_native._ntstatus_error(
            ctypes.c_long(windows_native.STATUS_OBJECT_NAME_COLLISION).value,
            "synthetic collision",
        )
        self.assertIsInstance(error, windows_native.WindowsObjectExistsError)
        self.assertEqual(error.ntstatus, windows_native.STATUS_OBJECT_NAME_COLLISION)

    def test_rename_structure_places_variable_name_at_the_documented_field_offset(self) -> None:
        self.assertLess(
            windows_native._FILE_RENAME_INFO.FileName.offset,
            ctypes.sizeof(windows_native._FILE_RENAME_INFO),
        )

    def test_private_volume_probe_rejects_non_ntfs_and_missing_acl_support(self) -> None:
        for capabilities in (
            windows_native.WindowsVolumeCapabilities(
                filesystem_name="exFAT",
                filesystem_flags=windows_native.FILE_PERSISTENT_ACLS,
            ),
            windows_native.WindowsVolumeCapabilities(
                filesystem_name="ReFS",
                filesystem_flags=windows_native.FILE_PERSISTENT_ACLS,
            ),
            windows_native.WindowsVolumeCapabilities(
                filesystem_name="NTFS",
                filesystem_flags=0,
            ),
        ):
            with (
                self.subTest(capabilities=capabilities),
                mock.patch.object(
                    windows_native,
                    "volume_capabilities",
                    return_value=capabilities,
                ),
                self.assertRaises(windows_native.WindowsUnsupportedError),
            ):
                windows_native.require_private_ntfs_volume(123)


@unittest.skipUnless(os.name == "nt", "real NTFS capability regression")
class WindowsNativeNtfsTests(unittest.TestCase):
    def setUp(self) -> None:
        windows_native.require_supported_runtime()

    def test_atomic_fresh_root_has_one_winner_and_blocks_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent_handle = -1
            winner_handle = -1
            try:
                parent_handle, _identity = _windows_open_locked_directory(parent, writable=True)
                try:
                    windows_native.require_private_ntfs_volume(parent_handle)
                except windows_native.WindowsUnsupportedError as exc:
                    self.skipTest(str(exc))

                outcomes: list[tuple[str, int]] = []
                outcome_lock = threading.Lock()

                def create() -> None:
                    try:
                        handle = windows_native.create_fresh_directory(
                            parent_handle,
                            "synthetic-fresh-root",
                        )
                    except windows_native.WindowsObjectExistsError:
                        result = ("collision", -1)
                    else:
                        result = ("created", handle)
                    with outcome_lock:
                        outcomes.append(result)

                threads = [threading.Thread(target=create) for _index in range(2)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()

                self.assertEqual(
                    sorted(label for label, _handle in outcomes), ["collision", "created"]
                )
                winner_handle = next(handle for label, handle in outcomes if label == "created")
                fresh = parent / "synthetic-fresh-root"
                visible_handle, visible_identity = _windows_open_locked_directory(fresh)
                try:
                    self.assertEqual(
                        windows_native.handle_information(winner_handle).identity,
                        visible_identity,
                    )
                finally:
                    _windows_close_handle(visible_handle)
                windows_native.validate_private_acl(winner_handle)
                with self.assertRaises(OSError):
                    fresh.rmdir()
                with self.assertRaises(OSError):
                    fresh.rename(parent / "renamed-root")
                with self.assertRaises(OSError):
                    parent.rename(parent.with_name(f"{parent.name}-renamed"))
            finally:
                if winner_handle >= 0:
                    windows_native.close_handle(winner_handle)
                if parent_handle >= 0:
                    _windows_close_handle(parent_handle)

    def test_staging_file_denies_mutation_and_promotes_without_replace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent_handle = -1
            root_handle = -1
            descriptor = -1
            collision_descriptor = -1
            try:
                parent_handle, _identity = _windows_open_locked_directory(parent, writable=True)
                try:
                    windows_native.require_private_ntfs_volume(parent_handle)
                except windows_native.WindowsUnsupportedError as exc:
                    self.skipTest(str(exc))
                root_handle = windows_native.create_fresh_directory(
                    parent_handle,
                    "synthetic-root",
                )
                staging_handle = windows_native.create_relative_regular_file_path(
                    root_handle,
                    ("stage.partial",),
                    temporary=True,
                )
                descriptor = windows_native.handle_to_file_descriptor(
                    staging_handle,
                    flags=os.O_RDWR | getattr(os, "O_BINARY", 0),
                )
                payload = b"synthetic descriptor payload"
                os.write(descriptor, payload)
                os.fsync(descriptor)
                with self.assertRaises(OSError):
                    (parent / "synthetic-root" / "stage.partial").write_bytes(b"changed")
                with self.assertRaises(OSError):
                    (parent / "synthetic-root" / "stage.partial").unlink()

                native_handle = int(__import__("msvcrt").get_osfhandle(descriptor))
                windows_native.rename_handle_relative(
                    native_handle,
                    root_handle,
                    ("final.bin",),
                    replace=False,
                )
                os.lseek(descriptor, 0, os.SEEK_SET)
                self.assertEqual(os.read(descriptor, len(payload) + 1), payload)
                os.close(descriptor)
                descriptor = -1
                self.assertEqual((parent / "synthetic-root" / "final.bin").read_bytes(), payload)

                collision_handle = windows_native.create_relative_regular_file_path(
                    root_handle,
                    ("collision.partial",),
                    temporary=True,
                )
                collision_descriptor = windows_native.handle_to_file_descriptor(
                    collision_handle,
                    flags=os.O_RDWR | getattr(os, "O_BINARY", 0),
                )
                collision_native = int(__import__("msvcrt").get_osfhandle(collision_descriptor))
                with self.assertRaises(windows_native.WindowsObjectExistsError):
                    windows_native.rename_handle_relative(
                        collision_native,
                        root_handle,
                        ("final.bin",),
                        replace=False,
                    )
            finally:
                for file_descriptor in (collision_descriptor, descriptor):
                    if file_descriptor >= 0:
                        with contextlib.suppress(OSError):
                            os.close(file_descriptor)
                if root_handle >= 0:
                    windows_native.close_handle(root_handle)
                if parent_handle >= 0:
                    _windows_close_handle(parent_handle)

    def test_reparse_component_is_rejected_when_symlink_creation_is_available(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent_handle = -1
            root_handle = -1
            try:
                parent_handle, _identity = _windows_open_locked_directory(parent, writable=True)
                try:
                    windows_native.require_private_ntfs_volume(parent_handle)
                except windows_native.WindowsUnsupportedError as exc:
                    self.skipTest(str(exc))
                root_handle = windows_native.create_fresh_directory(
                    parent_handle,
                    "synthetic-root",
                )
                target = parent / "synthetic-target"
                target.mkdir()
                link = parent / "synthetic-root" / "synthetic-link"
                try:
                    os.symlink(target, link, target_is_directory=True)
                except OSError as exc:
                    self.skipTest(f"directory symlink creation is unavailable: {exc.winerror}")
                with self.assertRaises(windows_native.WindowsNativeError):
                    windows_native.open_relative_directory(
                        root_handle,
                        "synthetic-link",
                        writable=False,
                    )
            finally:
                if root_handle >= 0:
                    windows_native.close_handle(root_handle)
                if parent_handle >= 0:
                    _windows_close_handle(parent_handle)


if __name__ == "__main__":
    unittest.main()
