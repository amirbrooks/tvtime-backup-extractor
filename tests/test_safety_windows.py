from __future__ import annotations

import ctypes
import errno
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from tvtime_extractor.errors import UnsafePathError, UserInputError
from tvtime_extractor.safety import (
    _WINDOWS_DELETE,
    _WINDOWS_DIRECTORY_CHILD_CREATION_ACCESS,
    _WINDOWS_FILE_ATTRIBUTE_DIRECTORY,
    _WINDOWS_FILE_ATTRIBUTE_OFFLINE,
    _WINDOWS_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    _WINDOWS_FILE_ATTRIBUTE_RECALL_ON_OPEN,
    _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT,
    _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS,
    _WINDOWS_FILE_FLAG_OPEN_NO_RECALL,
    _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
    _WINDOWS_FILE_LIST_DIRECTORY,
    _WINDOWS_FILE_SHARE_DELETE,
    _WINDOWS_FILE_SHARE_READ,
    _WINDOWS_FILE_SHARE_WRITE,
    _WINDOWS_GENERIC_READ,
    _WINDOWS_READ_CONTROL,
    MAXIMUM_WINDOWS_RETAINED_DESCENDANT_DIRECTORIES,
    _casefolded_path,
    _open_bound_fresh_output_root,
    _require_windows_visible_directory_identity,
    _safe_directory_entries,
    _windows_close_handle,
    _windows_create_file_directory_handle,
    _windows_create_file_regular_handle,
    _windows_create_private_directory_relative,
    _windows_directory_identity,
    _windows_enumerated_child,
    _windows_enumerated_path_metadata,
    _windows_hold_existing_descendant_directories,
    _windows_locked_relative_regular_file_descriptor,
    _windows_open_locked_directory,
    _windows_pinned_absolute_directory_handle,
    _windows_pinned_relative_parent,
    _windows_regular_file_information,
    _windows_rename_handle_no_replace,
    _windows_resume_bound_descendants,
    _windows_suspend_bound_descendants,
    _WindowsBoundOutputState,
    _WindowsRegularFileInformation,
    anchored_existing_extraction_root,
    held_destination_parent,
    no_link_absolute_path,
    private_temporary_directory,
    read_regular_bytes,
    regular_binary_reader,
    require_encrypted_ios_source_platform_support,
)
from tvtime_extractor.windows_native import (
    WindowsDirectoryEntryInformation,
    WindowsNativeError,
    WindowsObjectExistsError,
    WindowsUnsupportedError,
)


class WindowsDirectoryHandleContractTests(unittest.TestCase):
    @staticmethod
    def _native_entry(
        name: str,
        *,
        identity: tuple[int, int],
        directory: bool = False,
        attributes: int = 0,
        byte_size: int = 0,
    ) -> WindowsDirectoryEntryInformation:
        if directory:
            attributes |= _WINDOWS_FILE_ATTRIBUTE_DIRECTORY
        return WindowsDirectoryEntryInformation(
            name=name,
            attributes=attributes,
            identity=identity,
            byte_size=byte_size,
            last_write_time=116_444_736_000_000_000,
        )

    def test_windows_relative_parent_pins_and_identity_binds_every_component(self) -> None:
        first = self._native_entry("Synthetic", identity=(7, 11), directory=True)
        second = self._native_entry("LocalRoot", identity=(7, 12), directory=True)
        final = self._native_entry("private.bin", identity=(7, 13), byte_size=9)
        entries_by_handle = {91: (first,), 101: (second,), 102: (final,)}
        closed: list[int] = []

        with (
            mock.patch(
                "tvtime_extractor.safety._windows_native.directory_entries",
                side_effect=lambda handle: entries_by_handle[handle],
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_native.open_relative_directory",
                side_effect=(101, 102),
            ) as open_directory,
            mock.patch(
                "tvtime_extractor.safety._windows_directory_identity",
                side_effect=((7, 11), (7, 12)),
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_close_handle",
                side_effect=closed.append,
            ),
            _windows_pinned_relative_parent(
                91,
                ("Synthetic", "LocalRoot", "private.bin"),
            ) as (parent_handle, entry),
        ):
            self.assertEqual(parent_handle, 102)
            self.assertIs(entry, final)
            self.assertEqual(closed, [])

        self.assertEqual(
            open_directory.call_args_list,
            [
                mock.call(91, "Synthetic", writable=False),
                mock.call(101, "LocalRoot", writable=False),
            ],
        )
        self.assertEqual(closed, [102, 101])

    def test_windows_relative_parent_attempts_every_close_and_preserves_body_failure(self) -> None:
        first = self._native_entry("Synthetic", identity=(7, 11), directory=True)
        second = self._native_entry("LocalRoot", identity=(7, 12), directory=True)
        final = self._native_entry("private.bin", identity=(7, 13), byte_size=9)
        entries_by_handle = {91: (first,), 101: (second,), 102: (final,)}
        closed: list[int] = []

        def close_with_first_failure(handle: int) -> None:
            closed.append(handle)
            if handle == 102:
                raise UnsafePathError("synthetic close failure")

        with (
            mock.patch(
                "tvtime_extractor.safety._windows_native.directory_entries",
                side_effect=lambda handle: entries_by_handle[handle],
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_native.open_relative_directory",
                side_effect=(101, 102),
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_directory_identity",
                side_effect=((7, 11), (7, 12)),
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_close_handle",
                side_effect=close_with_first_failure,
            ),
            self.assertRaisesRegex(RuntimeError, "synthetic body failure"),
            _windows_pinned_relative_parent(
                91,
                ("Synthetic", "LocalRoot", "private.bin"),
            ),
        ):
            raise RuntimeError("synthetic body failure")

        self.assertEqual(closed, [102, 101])

    def test_absolute_directory_pin_holds_root_and_final_through_the_body(self) -> None:
        target = Path("/Synthetic/Private")
        final = self._native_entry("Private", identity=(7, 13), directory=True)
        parent_binding = mock.MagicMock()
        parent_binding.__enter__.return_value = (101, final)
        closed: list[int] = []

        with (
            mock.patch(
                "tvtime_extractor.safety._windows_open_locked_directory",
                return_value=(91, (7, 1)),
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_pinned_relative_parent",
                return_value=parent_binding,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_native.open_relative_retained_directory",
                return_value=102,
            ) as open_directory,
            mock.patch(
                "tvtime_extractor.safety._windows_directory_identity",
                return_value=(7, 13),
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_enumerated_child",
                return_value=final,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_close_handle",
                side_effect=closed.append,
            ),
            _windows_pinned_absolute_directory_handle(target, writable=True) as handle,
        ):
            self.assertEqual(handle, 102)
            self.assertEqual(closed, [])
            parent_binding.__exit__.assert_not_called()

        open_directory.assert_called_once_with(101, "Private", writable=True)
        parent_binding.__exit__.assert_called_once()
        self.assertEqual(closed, [102, 91])

    def test_windows_path_metadata_preserves_enumerated_identity(self) -> None:
        target = Path("/Synthetic/private.bin")
        final = self._native_entry("private.bin", identity=(7, 13), byte_size=9)
        binding = mock.MagicMock()
        binding.__enter__.return_value = (91, final)

        with mock.patch(
            "tvtime_extractor.safety._windows_pinned_absolute_parent",
            return_value=binding,
        ):
            metadata = _windows_enumerated_path_metadata(target)

        self.assertEqual((metadata.st_dev, metadata.st_ino), (7, 13))
        self.assertEqual(metadata.st_size, 9)

    def test_windows_path_metadata_rejects_enumeration_only_recall_attribute(self) -> None:
        cloud_entry = self._native_entry(
            "private.bin",
            identity=(7, 13),
            attributes=_WINDOWS_FILE_ATTRIBUTE_RECALL_ON_OPEN,
        )

        with (
            mock.patch(
                "tvtime_extractor.safety._windows_native.directory_entries",
                return_value=(cloud_entry,),
            ),
            self.assertRaisesRegex(UnsafePathError, "not fully present on local storage"),
        ):
            _windows_enumerated_child(91, "private.bin")

    def test_windows_no_link_path_uses_native_ancestor_validation_without_lstat(self) -> None:
        candidate = Path("/Synthetic/LocalRoot/private.bin")
        expected = Path(os.path.abspath(candidate))

        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch(
                "tvtime_extractor.safety._windows_require_safe_existing_ancestors"
            ) as validate,
            mock.patch.object(
                Path,
                "lstat",
                side_effect=AssertionError("ordinary path stat is forbidden"),
            ),
        ):
            result = no_link_absolute_path(candidate)

        self.assertEqual(result, expected)
        validate.assert_called_once_with(expected)

    def test_safe_directory_classifier_never_uses_following_direntry_queries(self) -> None:
        root = Path("/Synthetic/LocalRoot")
        entry = self._native_entry("Nested", identity=(7, 12), directory=True)
        binding = mock.MagicMock()
        binding.__enter__.return_value = 91

        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch(
                "tvtime_extractor.safety._windows_pinned_absolute_directory_handle",
                return_value=binding,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_native.iter_directory_entries",
                return_value=(entry,),
            ),
            mock.patch("tvtime_extractor.safety.os.scandir") as scandir,
        ):
            directories, files = _safe_directory_entries(root)

        self.assertEqual([item.path for item in directories], [root / "Nested"])
        self.assertEqual(files, ())
        scandir.assert_not_called()

    def test_safe_directory_classifier_rejects_cloud_entry_before_queueing_it(self) -> None:
        root = Path("/Synthetic/LocalRoot")
        entry = self._native_entry(
            "Virtualized",
            identity=(7, 12),
            directory=True,
            attributes=_WINDOWS_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        )
        binding = mock.MagicMock()
        binding.__enter__.return_value = 91

        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch(
                "tvtime_extractor.safety._windows_pinned_absolute_directory_handle",
                return_value=binding,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_native.iter_directory_entries",
                return_value=(entry,),
            ),
            self.assertRaisesRegex(UnsafePathError, "not fully present on local storage"),
        ):
            _safe_directory_entries(root)

    def test_safe_directory_classifier_checks_cancellation_during_flat_enumeration(self) -> None:
        root = Path("/Synthetic/LocalRoot")
        binding = mock.MagicMock()
        binding.__enter__.return_value = 91
        entries = (
            self._native_entry(f"Synthetic-{index}", identity=(7, index), byte_size=1)
            for index in range(1, 2_001)
        )
        cancel = mock.Mock(side_effect=RuntimeError("synthetic cancellation"))

        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch(
                "tvtime_extractor.safety._windows_pinned_absolute_directory_handle",
                return_value=binding,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_native.iter_directory_entries",
                return_value=entries,
            ),
            self.assertRaisesRegex(RuntimeError, "synthetic cancellation"),
        ):
            _safe_directory_entries(root, cancellation_check=cancel)

        cancel.assert_called_once_with()

    def test_windows_existing_tree_retention_has_a_global_handle_bound(self) -> None:
        root = Path("/Synthetic/LocalRoot")
        directories = tuple(
            types.SimpleNamespace(path=root / f"Synthetic-{index:05d}")
            for index in range(MAXIMUM_WINDOWS_RETAINED_DESCENDANT_DIRECTORIES + 1)
        )
        with (
            mock.patch(
                "tvtime_extractor.safety._safe_directory_entries",
                return_value=(directories, ()),
            ),
            mock.patch("tvtime_extractor.safety._windows_hold_bound_descendant_directory") as hold,
            self.assertRaisesRegex(UnsafePathError, "too many directories"),
        ):
            _windows_hold_existing_descendant_directories(root)

        self.assertEqual(hold.call_count, MAXIMUM_WINDOWS_RETAINED_DESCENDANT_DIRECTORIES)

    def test_windows_existing_tree_retention_checks_cancellation_between_directories(self) -> None:
        root = Path("/Synthetic/LocalRoot")
        child = types.SimpleNamespace(path=root / "Synthetic-Child")
        cancel = mock.Mock(side_effect=(None, RuntimeError("synthetic cancellation")))
        with (
            mock.patch(
                "tvtime_extractor.safety._safe_directory_entries",
                side_effect=(((child,), ()), ((), ())),
            ),
            mock.patch("tvtime_extractor.safety._windows_hold_bound_descendant_directory") as hold,
            self.assertRaisesRegex(RuntimeError, "synthetic cancellation"),
        ):
            _windows_hold_existing_descendant_directories(
                root,
                cancellation_check=cancel,
            )

        hold.assert_called_once_with(child.path)

    def test_windows_volume_capabilities_are_checked_before_root_identity(self) -> None:
        events: list[str] = []
        rejected = WindowsNativeError("synthetic ReFS rejection")

        def reject_volume(_handle: int) -> None:
            events.append("capabilities")
            raise rejected

        with (
            mock.patch(
                "tvtime_extractor.safety._windows_create_file_directory_handle",
                return_value=91,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_native.require_source_ntfs_volume",
                side_effect=reject_volume,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_directory_identity",
                side_effect=lambda _handle: events.append("identity"),
            ) as identity,
            mock.patch("tvtime_extractor.safety._windows_close_handle") as close,
            self.assertRaisesRegex(UnsafePathError, "private local NTFS storage"),
        ):
            _windows_open_locked_directory(Path("C:/"))

        self.assertEqual(events, ["capabilities"])
        identity.assert_not_called()
        close.assert_called_once_with(91)

    @unittest.skipUnless(os.name == "nt", "real Win32 temporary-capability regression")
    def test_private_temporary_directory_releases_its_capability_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with anchored_existing_extraction_root(root):
                with private_temporary_directory(
                    parent=root,
                    prefix=".tvtime-sqlite-",
                ) as staging:
                    staged_path = staging
                    (staging / "synthetic.sqlite").write_bytes(b"synthetic")
                self.assertFalse(staged_path.exists())

    def test_windows_ios_gate_requires_reviewed_runtime_before_password(self) -> None:
        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch(
                "tvtime_extractor.safety._windows_native.require_supported_runtime"
            ) as require_runtime,
        ):
            require_encrypted_ios_source_platform_support()
        require_runtime.assert_called_once_with()

        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch(
                "tvtime_extractor.safety._windows_native.require_supported_runtime",
                side_effect=WindowsUnsupportedError("synthetic unsupported runtime"),
            ),
            self.assertRaisesRegex(UnsafePathError, "64-bit Windows 11"),
        ):
            require_encrypted_ios_source_platform_support()

    class _Kernel32:
        def __init__(
            self,
            *,
            reparse: bool = False,
            directory: bool = True,
            cloud_attributes: int = 0,
        ) -> None:
            self.reparse = reparse
            self.directory = directory
            self.cloud_attributes = cloud_attributes
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
            information.file_attributes |= self.cloud_attributes
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
        desired_access = int(call[1])
        share_mode = int(call[2])
        flags = int(call[5])
        self.assertEqual(share_mode, _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE)
        self.assertFalse(share_mode & _WINDOWS_FILE_SHARE_DELETE)
        self.assertFalse(desired_access & _WINDOWS_DELETE)
        self.assertFalse(desired_access & _WINDOWS_DIRECTORY_CHILD_CREATION_ACCESS)
        self.assertTrue(desired_access & _WINDOWS_FILE_LIST_DIRECTORY)
        self.assertTrue(desired_access & _WINDOWS_READ_CONTROL)
        self.assertTrue(flags & _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS)
        self.assertTrue(flags & _WINDOWS_FILE_FLAG_OPEN_NO_RECALL)
        self.assertTrue(flags & _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT)

    def test_relative_private_directory_creation_uses_the_single_native_authority(self) -> None:
        with mock.patch(
            "tvtime_extractor.safety._windows_native.create_fresh_directory",
            return_value=101,
        ) as create:
            self.assertEqual(
                _windows_create_private_directory_relative(99, "Synthetic"),
                101,
            )
        create.assert_called_once_with(99, "Synthetic")

    def test_relative_private_directory_collision_is_safely_translated(self) -> None:
        failure = WindowsObjectExistsError("synthetic collision")
        with (
            mock.patch(
                "tvtime_extractor.safety._windows_native.create_fresh_directory",
                side_effect=failure,
            ),
            self.assertRaisesRegex(UserInputError, "destination already exists"),
        ):
            _windows_create_private_directory_relative(99, "Synthetic")

    def test_output_directory_handle_can_create_relative_private_children(self) -> None:
        kernel32 = self._Kernel32()
        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch("tvtime_extractor.safety._windows_kernel32", return_value=kernel32),
        ):
            handle, _identity = _windows_open_locked_directory(
                Path("C:/Synthetic/Private"),
                allow_child_creation=True,
            )
            _windows_close_handle(handle)

        desired_access = int(kernel32.create_calls[0][1])
        self.assertEqual(
            desired_access & _WINDOWS_DIRECTORY_CHILD_CREATION_ACCESS,
            _WINDOWS_DIRECTORY_CHILD_CREATION_ACCESS,
        )
        self.assertFalse(int(kernel32.create_calls[0][2]) & _WINDOWS_FILE_SHARE_DELETE)

    def test_promotion_capable_directory_handle_requests_delete_access_once(self) -> None:
        kernel32 = self._Kernel32()
        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch("tvtime_extractor.safety._windows_kernel32", return_value=kernel32),
        ):
            handle, _identity = _windows_open_locked_directory(
                Path("C:/Synthetic/Private"),
                allow_rename=True,
            )
            _windows_close_handle(handle)

        self.assertEqual(len(kernel32.create_calls), 1)
        desired_access = int(kernel32.create_calls[0][1])
        share_mode = int(kernel32.create_calls[0][2])
        self.assertTrue(desired_access & _WINDOWS_DELETE)
        self.assertFalse(share_mode & _WINDOWS_FILE_SHARE_DELETE)

    def test_handle_promotion_uses_the_isolated_windows_backend(self) -> None:
        destination = Path("C:/Synthetic/Private/Analysis")
        closed: list[int] = []
        with (
            mock.patch(
                "tvtime_extractor.safety._windows_open_locked_directory",
                return_value=(101, (7, 11)),
            ) as open_parent,
            mock.patch("tvtime_extractor.safety._windows_native.rename_handle_relative") as rename,
            mock.patch(
                "tvtime_extractor.safety._windows_close_handle",
                side_effect=closed.append,
            ),
        ):
            _windows_rename_handle_no_replace(202, destination)

        open_parent.assert_called_once_with(
            destination.parent,
            allow_child_creation=True,
        )
        rename.assert_called_once_with(
            202,
            101,
            ("Analysis",),
            replace=False,
        )
        self.assertEqual(closed, [101])

    def test_parent_promotion_suspends_and_rebinds_child_capabilities(self) -> None:
        root = Path("/synthetic/private")
        source = root / "Analysis.incomplete"
        child = source / "raw-cache"
        destination = root / "Analysis"
        source_identity = (7, 11)
        child_identity = (7, 12)
        state = _WindowsBoundOutputState(
            handle=99,
            identity=(7, 10),
            visible_root=root,
            descendant_handles={
                _casefolded_path(source): (source, 101, source_identity),
                _casefolded_path(child): (child, 102, child_identity),
            },
        )
        closed: list[int] = []
        with (
            mock.patch(
                "tvtime_extractor.safety._windows_directory_identity",
                side_effect=lambda handle: {101: source_identity, 102: child_identity}[handle],
            ),
            mock.patch(
                "tvtime_extractor.safety._require_windows_visible_directory_identity"
            ) as visible,
            mock.patch(
                "tvtime_extractor.safety._windows_close_handle",
                side_effect=closed.append,
            ),
        ):
            suspended = _windows_suspend_bound_descendants(state, source)

        self.assertEqual(suspended, [(Path("raw-cache"), child_identity)])
        self.assertEqual(closed, [102])
        self.assertNotIn(_casefolded_path(child), state.descendant_handles)
        visible.assert_called_once_with(child, expected_identity=child_identity)

        with (
            mock.patch(
                "tvtime_extractor.safety._windows_open_locked_directory",
                return_value=(202, child_identity),
            ) as reopen,
            mock.patch(
                "tvtime_extractor.safety._require_windows_visible_directory_identity"
            ) as visible,
            mock.patch("tvtime_extractor.safety._windows_require_private_acl") as require_acl,
        ):
            _windows_resume_bound_descendants(state, destination, suspended)

        rebound = destination / "raw-cache"
        reopen.assert_called_once_with(
            rebound,
            allow_rename=True,
            allow_child_creation=True,
        )
        visible.assert_called_once_with(rebound, expected_identity=child_identity)
        require_acl.assert_called_once_with(202)
        self.assertEqual(
            state.descendant_handles[_casefolded_path(rebound)],
            (rebound, 202, child_identity),
        )

    def test_visible_identity_reopen_shares_delete_with_retained_handle(self) -> None:
        kernel32 = self._Kernel32()
        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch("tvtime_extractor.safety._windows_kernel32", return_value=kernel32),
        ):
            _require_windows_visible_directory_identity(
                Path("C:/Synthetic/Private"),
                expected_identity=(7, (1 << 32) | 11),
            )

        self.assertEqual(len(kernel32.create_calls), 1)
        desired_access = int(kernel32.create_calls[0][1])
        share_mode = int(kernel32.create_calls[0][2])
        self.assertFalse(desired_access & _WINDOWS_DELETE)
        self.assertTrue(share_mode & _WINDOWS_FILE_SHARE_DELETE)

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
        self.assertTrue(int(call[5]) & _WINDOWS_FILE_FLAG_OPEN_NO_RECALL)
        self.assertFalse(int(call[5]) & _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS)

    def test_relative_regular_file_rejects_same_size_identity_substitution(self) -> None:
        entry = self._native_entry("private.bin", identity=(7, 13), byte_size=9)
        binding = mock.MagicMock()
        binding.__enter__.return_value = (91, entry)
        closed: list[int] = []
        substituted = _WindowsRegularFileInformation(
            identity=(7, 99),
            byte_size=9,
            last_write_time=entry.last_write_time,
        )

        with (
            mock.patch(
                "tvtime_extractor.safety._windows_pinned_relative_parent",
                return_value=binding,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_native.open_relative_regular_file",
                return_value=201,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_regular_file_information",
                return_value=substituted,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_enumerated_child",
                return_value=entry,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_close_handle",
                side_effect=closed.append,
            ),
            self.assertRaisesRegex(UnsafePathError, "changed while it was opened"),
            _windows_locked_relative_regular_file_descriptor(
                77,
                ("private.bin",),
            ),
        ):
            self.fail("an identity-substituted source must not be yielded")

        self.assertEqual(closed, [201])

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

    def test_directory_and_file_handles_reject_every_cloud_hydration_attribute(self) -> None:
        for attribute in (
            _WINDOWS_FILE_ATTRIBUTE_OFFLINE,
            _WINDOWS_FILE_ATTRIBUTE_RECALL_ON_OPEN,
            _WINDOWS_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        ):
            directory_kernel32 = self._Kernel32(cloud_attributes=attribute)
            with (
                self.subTest(kind="directory", attribute=attribute),
                mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
                mock.patch(
                    "tvtime_extractor.safety._windows_kernel32",
                    return_value=directory_kernel32,
                ),
                self.assertRaisesRegex(UnsafePathError, "not fully present on local storage"),
            ):
                _windows_open_locked_directory(Path("C:/Synthetic/CloudDirectory"))
            self.assertEqual(directory_kernel32.closed, [101])

            file_kernel32 = self._Kernel32(directory=False, cloud_attributes=attribute)
            with (
                self.subTest(kind="file", attribute=attribute),
                mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
                mock.patch(
                    "tvtime_extractor.safety._windows_kernel32",
                    return_value=file_kernel32,
                ),
                self.assertRaisesRegex(UnsafePathError, "not fully present on local storage"),
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
            visible_output = no_link_absolute_path(output)
            binding = mock.MagicMock()
            binding.__enter__.return_value = 101
            with (
                mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
                mock.patch("tvtime_extractor.safety._windows_require_safe_existing_ancestors"),
                mock.patch(
                    "tvtime_extractor.safety._windows_pinned_absolute_directory_handle",
                    return_value=binding,
                ) as pinned,
                mock.patch(
                    "tvtime_extractor.safety._windows_directory_identity",
                    return_value=(7, 11),
                ),
                mock.patch(
                    "tvtime_extractor.safety._windows_native.require_recovery_capabilities"
                ) as require_capabilities,
                mock.patch(
                    "tvtime_extractor.safety.require_bound_destination_parent",
                    return_value=output.parent,
                ),
                self.assertRaisesRegex(RuntimeError, "synthetic body failure"),
                held_destination_parent(output) as (handle, identity, visible),
            ):
                self.assertEqual(
                    (handle, identity, visible),
                    (101, (7, 11), visible_output),
                )
                binding.__exit__.assert_not_called()
                raise RuntimeError("synthetic body failure")
            pinned.assert_called_once_with(visible_output.parent, writable=True)
            require_capabilities.assert_called_once_with(101)
            binding.__exit__.assert_called_once()

    @unittest.skipUnless(os.name == "nt", "real Win32 destination-parent regression")
    def test_held_windows_destination_parent_blocks_rename_and_removal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "synthetic-destination-parent"
            parent.mkdir()
            output = parent / "synthetic-fresh-output"
            moved = root / "synthetic-moved-parent"

            with held_destination_parent(output) as (_handle, _identity, visible):
                self.assertEqual(visible, output)
                self.assertFalse(output.exists())
                with self.assertRaises(OSError):
                    parent.rename(moved)
                with self.assertRaises(OSError):
                    parent.rmdir()

            parent.rename(moved)
            moved.rmdir()

    def test_windows_parent_requires_acl_capabilities_before_binding_or_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fresh-output"
            binding = mock.MagicMock()
            binding.__enter__.return_value = 101
            with (
                mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
                mock.patch("tvtime_extractor.safety._windows_require_safe_existing_ancestors"),
                mock.patch(
                    "tvtime_extractor.safety._windows_pinned_absolute_directory_handle",
                    return_value=binding,
                ),
                mock.patch(
                    "tvtime_extractor.safety._windows_directory_identity",
                    return_value=(7, 11),
                ),
                mock.patch(
                    "tvtime_extractor.safety._windows_native.require_recovery_capabilities",
                    side_effect=WindowsUnsupportedError("synthetic unsupported filesystem"),
                ) as require_capabilities,
                mock.patch(
                    "tvtime_extractor.safety.require_bound_destination_parent"
                ) as require_binding,
                self.assertRaisesRegex(UnsafePathError, "local NTFS destination"),
                held_destination_parent(output),
            ):
                self.fail("unsupported Windows output must fail before entering the body")
            require_capabilities.assert_called_once_with(101)
            require_binding.assert_not_called()
            binding.__exit__.assert_called_once()

    def test_windows_fresh_output_uses_atomic_relative_native_creation(self) -> None:
        output = Path("/synthetic/private/fresh-output")
        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch("tvtime_extractor.safety.require_fresh_output_platform_support"),
            mock.patch("tvtime_extractor.safety.os.mkdir") as mkdir,
            mock.patch(
                "tvtime_extractor.safety.require_bound_destination_parent",
                return_value=output.parent,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_create_private_directory_relative",
                return_value=101,
            ) as create_relative,
            mock.patch(
                "tvtime_extractor.safety._windows_directory_identity",
                return_value=(7, 11),
            ),
            mock.patch(
                "tvtime_extractor.safety._require_windows_visible_directory_identity"
            ) as visible,
        ):
            handle, identity = _open_bound_fresh_output_root(
                output,
                destination_parent_descriptor=99,
                expected_identity=(5, 6),
            )
        self.assertEqual((handle, identity), (101, (7, 11)))
        create_relative.assert_called_once_with(99, "fresh-output")
        visible.assert_called_once_with(output, expected_identity=(7, 11))
        mkdir.assert_not_called()

    def test_windows_existing_root_is_held_validated_and_closed_on_body_failure(self) -> None:
        identity = (7, 11)
        extraction = Path("/synthetic/private/TVTime-Extraction")
        pin_context = mock.MagicMock()
        pin_context.__enter__.return_value = 101
        with (
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch(
                "tvtime_extractor.safety.require_local_recovery_source",
                return_value=extraction,
            ) as require_source,
            mock.patch(
                "tvtime_extractor.safety._windows_pinned_absolute_directory_handle",
                return_value=pin_context,
            ) as pin,
            mock.patch(
                "tvtime_extractor.safety._windows_directory_identity",
                return_value=identity,
            ),
            mock.patch(
                "tvtime_extractor.safety._windows_require_private_acl"
            ) as require_private_acl,
            mock.patch(
                "tvtime_extractor.safety._require_visible_existing_directory_identity"
            ) as visible,
            mock.patch(
                "tvtime_extractor.safety._windows_hold_existing_descendant_directories"
            ) as hold_descendants,
            self.assertRaisesRegex(RuntimeError, "synthetic body failure"),
            anchored_existing_extraction_root(extraction) as bound,
        ):
            self.assertTrue(bound.is_absolute())
            pin_context.__exit__.assert_not_called()
            raise RuntimeError("synthetic body failure")

        require_source.assert_called_once_with(extraction)
        pin.assert_called_once_with(extraction, writable=True)
        require_private_acl.assert_called_once_with(101)
        visible.assert_called_once()
        hold_descendants.assert_called_once_with(extraction, cancellation_check=None)
        pin_context.__exit__.assert_called_once()
