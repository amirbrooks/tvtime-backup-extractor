from __future__ import annotations

import contextlib
import ctypes
import json
import os
import sqlite3
import stat
import subprocess
import tempfile
import threading
import types
import unittest
from ctypes import wintypes
from pathlib import Path
from unittest import mock

from tvtime_extractor import windows_native
from tvtime_extractor.analyze import readonly_sqlite
from tvtime_extractor.errors import UnsafePathError
from tvtime_extractor.safety import (
    _require_windows_visible_directory_identity,
    _windows_close_handle,
    _windows_create_private_directory_relative,
    _windows_open_locked_directory,
    anchored_existing_extraction_root,
    private_temporary_directory,
    require_private_descriptor,
    require_private_path,
    secure_directory,
    windows_create_private_staging_descriptor,
    write_bytes_private,
    write_json_private_atomic,
    write_text_private,
)


class WindowsNativeUnitTests(unittest.TestCase):
    @staticmethod
    def _directory_record(
        name: str,
        *,
        file_id: int,
        attributes: int = windows_native.FILE_ATTRIBUTE_NORMAL,
        byte_size: int = 0,
        last_write_time: int = 19,
        last_access_time: int = 17,
        short_name: str | None = None,
        continued: bool = False,
    ) -> bytes:
        encoded_name = name.encode("utf-16-le")
        header = windows_native._FILE_ID_BOTH_DIR_INFO_HEADER()
        header.file_attributes = attributes
        header.file_name_length = len(encoded_name)
        header.end_of_file = byte_size
        header.last_write_time = last_write_time
        header.last_access_time = last_access_time
        header.file_id = file_id
        if short_name is not None:
            encoded_short_name = short_name.encode("utf-16-le")
            if len(encoded_short_name) > ctypes.sizeof(header.short_name):
                raise ValueError("synthetic short name exceeded FILE_ID_BOTH_DIR_INFO")
            header.short_name_length = len(encoded_short_name)
            ctypes.memmove(
                ctypes.addressof(header)
                + windows_native._FILE_ID_BOTH_DIR_INFO_HEADER.short_name.offset,
                encoded_short_name,
                len(encoded_short_name),
            )
        record_size = ctypes.sizeof(header) + len(encoded_name)
        padded_size = (record_size + 7) & ~7
        header.next_entry_offset = padded_size if continued else 0
        return bytes(header) + encoded_name + (b"\x00" * (padded_size - record_size))

    def test_directory_record_layout_matches_the_win32_contract(self) -> None:
        header = windows_native._FILE_ID_BOTH_DIR_INFO_HEADER
        self.assertEqual(ctypes.sizeof(header), 104)
        self.assertEqual(header.file_attributes.offset, 56)
        self.assertEqual(header.file_name_length.offset, 60)
        self.assertEqual(header.short_name_length.offset, 68)
        self.assertEqual(header.short_name.offset, 70)
        self.assertEqual(header.file_id.offset, 96)

    def test_directory_record_parser_preserves_attributes_and_64_bit_identity(self) -> None:
        first = self._directory_record(
            "Synthetic",
            file_id=11,
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            short_name="SYNTH~1",
            continued=True,
        )
        second = self._directory_record(
            "private.bin",
            file_id=-1,
            attributes=windows_native.FILE_ATTRIBUTE_RECALL_ON_OPEN,
            byte_size=37,
            last_write_time=29,
            last_access_time=23,
        )

        entries = windows_native._directory_entries_from_buffer(
            first + second,
            volume_serial_number=7,
        )

        self.assertEqual([entry.name for entry in entries], ["Synthetic", "private.bin"])
        self.assertEqual(entries[0].short_name, "SYNTH~1")
        self.assertIsNone(entries[1].short_name)
        self.assertEqual(entries[0].identity, (7, 11))
        self.assertTrue(entries[0].is_directory)
        self.assertEqual(entries[1].identity, (7, (1 << 64) - 1))
        self.assertEqual(entries[1].byte_size, 37)
        self.assertEqual(entries[1].last_write_time, 29)
        self.assertEqual(entries[1].last_access_time, 23)
        self.assertTrue(entries[1].is_cloud_hydrated)

    def test_directory_record_parser_rejects_malformed_name_and_offset(self) -> None:
        odd_name = windows_native._FILE_ID_BOTH_DIR_INFO_HEADER()
        odd_name.file_name_length = 1
        with self.assertRaises(windows_native.WindowsNativeError):
            windows_native._directory_entries_from_buffer(
                bytes(odd_name) + b"x",
                volume_serial_number=7,
            )

        unsafe_short_name = windows_native._FILE_ID_BOTH_DIR_INFO_HEADER()
        unsafe_short_name.file_name_length = 2
        unsafe_short_name.short_name_length = 1
        with self.assertRaises(windows_native.WindowsNativeError):
            windows_native._directory_entries_from_buffer(
                bytes(unsafe_short_name) + b"x\x00",
                volume_serial_number=7,
            )

        unsafe_offset = windows_native._FILE_ID_BOTH_DIR_INFO_HEADER()
        unsafe_offset.file_name_length = 2
        unsafe_offset.next_entry_offset = 7
        with self.assertRaises(windows_native.WindowsNativeError):
            windows_native._directory_entries_from_buffer(
                bytes(unsafe_offset) + b"x\x00",
                volume_serial_number=7,
            )

    def test_timestamp_restore_uses_pinned_handle_and_exact_filetimes(self) -> None:
        calls: list[tuple[int, int, int]] = []

        class Setter:
            def __init__(self) -> None:
                self.argtypes: object = None
                self.restype: object = None

            def __call__(
                self,
                handle: object,
                creation_time: object,
                access_time: object,
                write_time: object,
            ) -> int:
                self_handle = getattr(handle, "value", handle)
                access = access_time._obj
                write = write_time._obj
                assert creation_time is None
                calls.append(
                    (
                        int(self_handle),
                        (int(access.high) << 32) | int(access.low),
                        (int(write.high) << 32) | int(write.low),
                    )
                )
                return 1

        setter = Setter()
        with (
            mock.patch.object(windows_native, "_require_windows"),
            mock.patch.object(
                windows_native,
                "_dll",
                return_value=types.SimpleNamespace(SetFileTime=setter),
            ),
        ):
            windows_native.restore_handle_times(
                91,
                access_time_filetime=0,
                write_time_filetime=windows_native.WINDOWS_FILETIME_UNIX_EPOCH - 1,
            )

        epoch = windows_native.WINDOWS_FILETIME_UNIX_EPOCH
        self.assertEqual(calls, [(91, 0, epoch - 1)])

    def test_timestamp_restore_rejects_out_of_range_filetime(self) -> None:
        with self.assertRaisesRegex(
            windows_native.WindowsNativeError,
            "supported range",
        ):
            windows_native._filetime_from_ticks(-1)

    def test_held_directory_enumeration_restarts_then_resumes(self) -> None:
        payload = self._directory_record("private.bin", file_id=12, byte_size=17)

        class Enumerator:
            def __init__(self) -> None:
                self.argtypes: object = None
                self.restype: object = None
                self.classes: list[int] = []

            def __call__(
                self,
                _handle: object,
                information_class: int,
                buffer: object,
                _buffer_size: int,
            ) -> int:
                self.classes.append(information_class)
                if len(self.classes) == 1:
                    ctypes.memmove(buffer, payload, len(payload))
                    return 1
                return 0

        enumerator = Enumerator()
        kernel32 = types.SimpleNamespace(GetFileInformationByHandleEx=enumerator)
        directory = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            identity=(7, 11),
            byte_size=0,
            last_write_time=19,
        )
        with (
            mock.patch.object(windows_native, "handle_information", return_value=directory),
            mock.patch.object(windows_native, "_dll", return_value=kernel32),
            mock.patch.object(ctypes, "set_last_error", create=True),
            mock.patch.object(
                ctypes,
                "get_last_error",
                return_value=windows_native.ERROR_NO_MORE_FILES,
                create=True,
            ),
        ):
            entries = windows_native.directory_entries(91)

        self.assertEqual(entries[0].identity, (7, 12))
        self.assertEqual(
            enumerator.classes,
            [
                windows_native.FILE_ID_BOTH_DIRECTORY_RESTART_INFO,
                windows_native.FILE_ID_BOTH_DIRECTORY_INFO,
            ],
        )

    def test_held_directory_enumeration_enforces_the_entry_bound(self) -> None:
        payload = self._directory_record("private.bin", file_id=12, byte_size=17)

        class Enumerator:
            def __init__(self) -> None:
                self.argtypes: object = None
                self.restype: object = None
                self.called = False

            def __call__(
                self,
                _handle: object,
                _information_class: int,
                buffer: object,
                _buffer_size: int,
            ) -> int:
                if self.called:
                    return 0
                self.called = True
                ctypes.memmove(buffer, payload, len(payload))
                return 1

        enumerator = Enumerator()
        kernel32 = types.SimpleNamespace(GetFileInformationByHandleEx=enumerator)
        directory = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            identity=(7, 11),
            byte_size=0,
            last_write_time=19,
        )
        with (
            mock.patch.object(windows_native, "handle_information", return_value=directory),
            mock.patch.object(windows_native, "_dll", return_value=kernel32),
            mock.patch.object(windows_native, "MAXIMUM_DIRECTORY_ENTRIES", 0),
            mock.patch.object(ctypes, "set_last_error", create=True),
            self.assertRaisesRegex(windows_native.WindowsNativeError, "entry limit"),
        ):
            tuple(windows_native.iter_directory_entries(91))

    def test_relative_source_file_open_is_no_recall_and_all_handles_reject_cloud(self) -> None:
        directory_information = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            identity=(7, 11),
            byte_size=0,
            last_write_time=19,
        )
        file_information = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_NORMAL,
            identity=(7, 12),
            byte_size=17,
            last_write_time=23,
        )
        with (
            mock.patch.object(
                windows_native,
                "_nt_create_relative",
                side_effect=((101, windows_native.FILE_OPENED), (102, windows_native.FILE_OPENED)),
            ) as create,
            mock.patch.object(
                windows_native,
                "handle_information",
                side_effect=(directory_information, file_information),
            ),
        ):
            self.assertEqual(
                windows_native.open_relative_directory(99, "Synthetic", writable=False),
                101,
            )
            self.assertEqual(windows_native.open_relative_regular_file(101, "private.bin"), 102)

        self.assertFalse(
            create.call_args_list[0].kwargs["options"] & windows_native.FILE_OPEN_NO_RECALL
        )
        self.assertTrue(
            create.call_args_list[1].kwargs["options"] & windows_native.FILE_OPEN_NO_RECALL
        )
        self.assertTrue(
            create.call_args_list[0].kwargs["share_access"] & windows_native.FILE_SHARE_DELETE
        )

        for attribute in (
            windows_native.FILE_ATTRIBUTE_OFFLINE,
            windows_native.FILE_ATTRIBUTE_RECALL_ON_OPEN,
            windows_native.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        ):
            for directory in (False, True):
                hydrated = windows_native.WindowsHandleInformation(
                    attributes=attribute
                    | (
                        windows_native.FILE_ATTRIBUTE_DIRECTORY
                        if directory
                        else windows_native.FILE_ATTRIBUTE_NORMAL
                    ),
                    identity=(7, 13),
                    byte_size=0,
                    last_write_time=29,
                )
                with (
                    self.subTest(attribute=attribute, directory=directory),
                    mock.patch.object(
                        windows_native,
                        "_nt_create_relative",
                        return_value=(103, windows_native.FILE_OPENED),
                    ),
                    mock.patch.object(
                        windows_native,
                        "handle_information",
                        return_value=hydrated,
                    ),
                    mock.patch.object(windows_native, "close_handle") as close,
                    self.assertRaises(windows_native.WindowsNativeError),
                ):
                    if directory:
                        windows_native.open_relative_directory(99, "Synthetic", writable=False)
                    else:
                        windows_native.open_relative_regular_file(99, "private.bin")
                close.assert_called_once_with(103)

    def test_retained_relative_directory_open_denies_delete_sharing(self) -> None:
        directory_information = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            identity=(7, 11),
            byte_size=0,
            last_write_time=19,
        )
        with (
            mock.patch.object(
                windows_native,
                "_nt_create_relative",
                return_value=(101, windows_native.FILE_OPENED),
            ) as create,
            mock.patch.object(
                windows_native,
                "handle_information",
                return_value=directory_information,
            ),
        ):
            self.assertEqual(
                windows_native.open_relative_retained_directory(
                    99,
                    "Synthetic",
                    writable=True,
                ),
                101,
            )

        share_access = create.call_args.kwargs["share_access"]
        self.assertEqual(
            share_access,
            windows_native.FILE_SHARE_READ | windows_native.FILE_SHARE_WRITE,
        )
        self.assertFalse(share_access & windows_native.FILE_SHARE_DELETE)

    def test_acl_repair_regular_file_open_requests_metadata_writes_only(self) -> None:
        file_information = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_NORMAL,
            identity=(7, 12),
            byte_size=17,
            last_write_time=23,
        )
        with (
            mock.patch.object(
                windows_native,
                "_nt_create_relative",
                return_value=(101, windows_native.FILE_OPENED),
            ) as create,
            mock.patch.object(
                windows_native,
                "handle_information",
                return_value=file_information,
            ),
        ):
            self.assertEqual(
                windows_native.open_relative_retained_regular_file(
                    99,
                    "private.bin",
                    owner_rebind=True,
                ),
                101,
            )

        desired_access = create.call_args.kwargs["desired_access"]
        share_access = create.call_args.kwargs["share_access"]
        self.assertTrue(desired_access & windows_native.WRITE_DAC)
        self.assertTrue(desired_access & windows_native.WRITE_OWNER)
        self.assertFalse(desired_access & windows_native.FILE_READ_DATA)
        self.assertFalse(desired_access & windows_native.FILE_WRITE_DATA)
        self.assertFalse(desired_access & windows_native.FILE_APPEND_DATA)
        self.assertFalse(desired_access & windows_native.FILE_WRITE_ATTRIBUTES)
        self.assertFalse(desired_access & windows_native.DELETE)
        self.assertEqual(
            share_access,
            windows_native.FILE_SHARE_READ | windows_native.FILE_SHARE_WRITE,
        )
        self.assertFalse(share_access & windows_native.FILE_SHARE_DELETE)

    def test_acl_repair_directory_open_requests_only_dacl_write_access(self) -> None:
        directory_information = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            identity=(7, 11),
            byte_size=0,
            last_write_time=19,
        )
        with (
            mock.patch.object(
                windows_native,
                "_nt_create_relative",
                return_value=(101, windows_native.FILE_OPENED),
            ) as create,
            mock.patch.object(
                windows_native,
                "handle_information",
                return_value=directory_information,
            ),
        ):
            self.assertEqual(
                windows_native.open_relative_acl_repair_directory(
                    99,
                    "Synthetic",
                ),
                101,
            )

        desired_access = create.call_args.kwargs["desired_access"]
        self.assertTrue(desired_access & windows_native.WRITE_DAC)
        self.assertFalse(desired_access & windows_native.WRITE_OWNER)
        self.assertFalse(desired_access & windows_native.FILE_LIST_DIRECTORY)
        self.assertFalse(desired_access & windows_native.FILE_ADD_FILE)
        self.assertFalse(desired_access & windows_native.FILE_ADD_SUBDIRECTORY)
        self.assertFalse(desired_access & windows_native.FILE_WRITE_ATTRIBUTES)

    def test_owner_rebind_directory_open_adds_only_owner_write_access(self) -> None:
        directory_information = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            identity=(7, 11),
            byte_size=0,
            last_write_time=19,
        )
        with (
            mock.patch.object(
                windows_native,
                "_nt_create_relative",
                return_value=(101, 0),
            ) as create,
            mock.patch.object(
                windows_native,
                "handle_information",
                return_value=directory_information,
            ),
        ):
            self.assertEqual(
                windows_native.open_relative_acl_repair_directory(
                    99,
                    "Synthetic",
                    owner_rebind=True,
                ),
                101,
            )

        desired_access = create.call_args.kwargs["desired_access"]
        self.assertTrue(desired_access & windows_native.WRITE_DAC)
        self.assertTrue(desired_access & windows_native.WRITE_OWNER)
        self.assertFalse(desired_access & windows_native.FILE_LIST_DIRECTORY)
        self.assertFalse(desired_access & windows_native.FILE_ADD_FILE)
        self.assertFalse(desired_access & windows_native.FILE_ADD_SUBDIRECTORY)
        self.assertFalse(desired_access & windows_native.FILE_WRITE_ATTRIBUTES)

    def test_acl_repair_directory_can_share_delete_only_for_an_existing_pin(self) -> None:
        directory_information = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            identity=(7, 11),
            byte_size=0,
            last_write_time=19,
        )
        with (
            mock.patch.object(
                windows_native,
                "_nt_create_relative",
                return_value=(101, windows_native.FILE_OPENED),
            ) as create,
            mock.patch.object(
                windows_native,
                "handle_information",
                return_value=directory_information,
            ),
        ):
            windows_native.open_relative_acl_repair_directory(
                99,
                "Synthetic",
                coexist_with_retained_delete=True,
            )

        desired_access = create.call_args.kwargs["desired_access"]
        share_access = create.call_args.kwargs["share_access"]
        self.assertTrue(desired_access & windows_native.WRITE_DAC)
        self.assertFalse(desired_access & windows_native.DELETE)
        self.assertTrue(share_access & windows_native.FILE_SHARE_DELETE)

    def test_existing_output_is_validated_before_held_handle_truncation(self) -> None:
        information = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_NORMAL,
            identity=(7, 12),
            byte_size=17,
            last_write_time=23,
        )
        events: list[str] = []
        with (
            mock.patch.object(
                windows_native,
                "private_security_descriptor",
                return_value=contextlib.nullcontext(301),
            ),
            mock.patch.object(
                windows_native,
                "_nt_create_relative",
                return_value=(101, windows_native.FILE_OPENED),
            ) as create,
            mock.patch.object(
                windows_native,
                "handle_information",
                return_value=information,
            ),
            mock.patch.object(
                windows_native,
                "validate_private_acl",
                side_effect=lambda _handle: events.append("validate"),
            ),
            mock.patch.object(
                windows_native,
                "_truncate_regular_file",
                side_effect=lambda _handle: events.append("truncate"),
            ),
        ):
            self.assertEqual(
                windows_native.create_or_replace_regular_file(
                    99,
                    "private.bin",
                    exclusive=False,
                ),
                101,
            )

        self.assertEqual(events, ["validate", "truncate"])
        self.assertEqual(create.call_args.kwargs["disposition"], windows_native.FILE_OPEN_IF)
        self.assertTrue(create.call_args.kwargs["desired_access"] & windows_native.DELETE)
        self.assertEqual(create.call_args.kwargs["share_access"], 0)
        self.assertTrue(create.call_args.kwargs["options"] & windows_native.FILE_OPEN_NO_RECALL)

    def test_private_writer_rejects_cloud_backed_handle_before_truncation(self) -> None:
        information = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
            identity=(7, 12),
            byte_size=17,
            last_write_time=23,
        )
        with (
            mock.patch.object(
                windows_native,
                "private_security_descriptor",
                return_value=contextlib.nullcontext(301),
            ),
            mock.patch.object(
                windows_native,
                "_nt_create_relative",
                return_value=(101, windows_native.FILE_OPENED),
            ),
            mock.patch.object(
                windows_native,
                "handle_information",
                return_value=information,
            ),
            mock.patch.object(windows_native, "validate_private_acl") as validate_acl,
            mock.patch.object(windows_native, "_truncate_regular_file") as truncate,
            mock.patch.object(windows_native, "close_handle") as close,
            self.assertRaises(windows_native.WindowsNativeError),
        ):
            windows_native.create_or_replace_regular_file(
                99,
                "private.bin",
                exclusive=False,
            )

        validate_acl.assert_not_called()
        truncate.assert_not_called()
        close.assert_called_once_with(101)

    def test_nested_private_writer_uses_delete_sharing_traversal(self) -> None:
        with (
            mock.patch.object(
                windows_native,
                "open_relative_directory",
                side_effect=(101, 102),
            ) as open_directory,
            mock.patch.object(windows_native, "validate_private_acl") as validate_acl,
            mock.patch.object(
                windows_native,
                "create_or_replace_regular_file",
                return_value=103,
            ) as create_file,
            mock.patch.object(windows_native, "close_handle") as close,
        ):
            self.assertEqual(
                windows_native.create_relative_regular_file_path(
                    99,
                    ("one", "two", "private.bin"),
                ),
                103,
            )

        self.assertEqual(
            open_directory.call_args_list,
            [
                mock.call(99, "one", writable=True),
                mock.call(101, "two", writable=True),
            ],
        )
        self.assertEqual(validate_acl.call_args_list, [mock.call(101), mock.call(102)])
        create_file.assert_called_once_with(
            102,
            "private.bin",
            exclusive=True,
            temporary=False,
            allow_path_reopen=False,
        )
        self.assertEqual(close.call_args_list, [mock.call(102), mock.call(101)])

    def test_traversal_close_failure_closes_final_result_and_remaining_ancestors(self) -> None:
        failure = windows_native.WindowsNativeError("synthetic close failure")
        with (
            mock.patch.object(
                windows_native,
                "open_relative_directory",
                side_effect=(101, 102),
            ),
            mock.patch.object(windows_native, "validate_private_acl"),
            mock.patch.object(
                windows_native,
                "create_or_replace_regular_file",
                return_value=103,
            ),
            mock.patch.object(
                windows_native,
                "close_handle",
                side_effect=(failure, None, None),
            ) as close,
            self.assertRaisesRegex(
                windows_native.WindowsNativeError,
                "synthetic close failure",
            ),
        ):
            windows_native.create_relative_regular_file_path(
                99,
                ("one", "two", "private.bin"),
            )

        self.assertEqual(close.call_args_list, [mock.call(102), mock.call(101), mock.call(103)])

    def test_private_tree_cleanup_deletes_only_identity_bound_relative_handles(self) -> None:
        root = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            identity=(7, 10),
            byte_size=0,
            last_write_time=19,
        )
        directory = self._directory_record(
            "nested",
            file_id=11,
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            continued=True,
        )
        reparse = self._directory_record(
            "redirect",
            file_id=12,
            attributes=(
                windows_native.FILE_ATTRIBUTE_DIRECTORY
                | windows_native.FILE_ATTRIBUTE_REPARSE_POINT
            ),
            continued=True,
        )
        file_entry = self._directory_record("payload.bin", file_id=13)
        nested_file = self._directory_record("nested.bin", file_id=14)
        root_entries = windows_native._directory_entries_from_buffer(
            directory + reparse + file_entry,
            volume_serial_number=7,
        )
        nested_entries = windows_native._directory_entries_from_buffer(
            nested_file,
            volume_serial_number=7,
        )
        opened = {
            201: windows_native.WindowsHandleInformation(
                attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
                identity=(7, 11),
                byte_size=0,
                last_write_time=19,
            ),
            202: windows_native.WindowsHandleInformation(
                attributes=windows_native.FILE_ATTRIBUTE_NORMAL,
                identity=(7, 14),
                byte_size=0,
                last_write_time=19,
            ),
            203: windows_native.WindowsHandleInformation(
                attributes=(
                    windows_native.FILE_ATTRIBUTE_DIRECTORY
                    | windows_native.FILE_ATTRIBUTE_REPARSE_POINT
                ),
                identity=(7, 12),
                byte_size=0,
                last_write_time=19,
            ),
            204: windows_native.WindowsHandleInformation(
                attributes=windows_native.FILE_ATTRIBUTE_NORMAL,
                identity=(7, 13),
                byte_size=0,
                last_write_time=19,
            ),
        }
        with (
            mock.patch.object(
                windows_native,
                "handle_information",
                side_effect=lambda handle: root if handle == 100 else opened[handle],
            ),
            mock.patch.object(
                windows_native,
                "directory_entries",
                side_effect=lambda handle: root_entries if handle == 100 else nested_entries,
            ),
            mock.patch.object(
                windows_native,
                "_open_relative_for_delete",
                side_effect=(201, 202, 203, 204),
            ) as open_relative,
            mock.patch.object(windows_native, "_mark_handle_for_deletion") as mark,
            mock.patch.object(windows_native, "close_handle") as close,
        ):
            windows_native.delete_private_tree(100)

        self.assertEqual(
            [call.args[0] for call in mark.call_args_list],
            [202, 201, 203, 204, 100],
        )
        self.assertEqual([call.args[0] for call in close.call_args_list], [202, 201, 203, 204])
        self.assertEqual(
            [(call.args[0], call.args[1]) for call in open_relative.call_args_list],
            [(100, "nested"), (201, "nested.bin"), (100, "redirect"), (100, "payload.bin")],
        )
        self.assertEqual(
            [call.kwargs["directory"] for call in open_relative.call_args_list],
            [True, False, True, False],
        )

    def test_empty_directory_cleanup_refuses_contents_before_disposition(self) -> None:
        information = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            identity=(7, 10),
            byte_size=0,
            last_write_time=19,
        )
        entry = windows_native.WindowsDirectoryEntryInformation(
            name="unexpected.bin",
            attributes=windows_native.FILE_ATTRIBUTE_NORMAL,
            identity=(7, 11),
            byte_size=9,
            last_write_time=19,
            last_access_time=17,
            short_name=None,
        )
        with (
            mock.patch.object(windows_native, "handle_information", return_value=information),
            mock.patch.object(windows_native, "directory_entries", return_value=(entry,)),
            mock.patch.object(windows_native, "_mark_handle_for_deletion") as mark,
            self.assertRaisesRegex(windows_native.WindowsNativeError, "not empty"),
        ):
            windows_native.delete_empty_directory(100)

        mark.assert_not_called()

    def test_empty_directory_cleanup_marks_the_exact_handle_for_deletion(self) -> None:
        information = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            identity=(7, 10),
            byte_size=0,
            last_write_time=19,
        )
        with (
            mock.patch.object(windows_native, "handle_information", return_value=information),
            mock.patch.object(windows_native, "directory_entries", return_value=()),
            mock.patch.object(windows_native, "_mark_handle_for_deletion") as mark,
        ):
            windows_native.delete_empty_directory(100)

        mark.assert_called_once_with(100)

    def test_cleanup_child_handle_blocks_rename_and_opens_the_reparse_itself(self) -> None:
        information = windows_native.WindowsHandleInformation(
            attributes=(
                windows_native.FILE_ATTRIBUTE_DIRECTORY
                | windows_native.FILE_ATTRIBUTE_REPARSE_POINT
            ),
            identity=(7, 12),
            byte_size=0,
            last_write_time=19,
        )
        with (
            mock.patch.object(
                windows_native,
                "_nt_create_relative",
                return_value=(101, windows_native.FILE_OPENED),
            ) as create,
            mock.patch.object(
                windows_native,
                "handle_information",
                return_value=information,
            ),
        ):
            self.assertEqual(
                windows_native._open_relative_for_delete(
                    99,
                    "redirect",
                    directory=True,
                ),
                101,
            )

        self.assertEqual(
            create.call_args.kwargs["share_access"],
            windows_native.FILE_SHARE_READ | windows_native.FILE_SHARE_WRITE,
        )
        self.assertFalse(create.call_args.kwargs["share_access"] & windows_native.FILE_SHARE_DELETE)
        self.assertTrue(create.call_args.kwargs["options"] & windows_native.FILE_OPEN_REPARSE_POINT)

    def test_private_directory_creator_retains_delete_authority_for_exact_cleanup(self) -> None:
        information = windows_native.WindowsHandleInformation(
            attributes=windows_native.FILE_ATTRIBUTE_DIRECTORY,
            identity=(7, 12),
            byte_size=0,
            last_write_time=19,
        )
        with (
            mock.patch.object(
                windows_native,
                "private_security_descriptor",
                return_value=contextlib.nullcontext(301),
            ),
            mock.patch.object(
                windows_native,
                "_nt_create_relative",
                return_value=(101, windows_native.FILE_CREATED),
            ) as create,
            mock.patch.object(
                windows_native,
                "handle_information",
                return_value=information,
            ),
            mock.patch.object(windows_native, "validate_private_acl"),
        ):
            self.assertEqual(windows_native.create_fresh_directory(99, "private"), 101)

        self.assertTrue(create.call_args.kwargs["desired_access"] & windows_native.DELETE)
        self.assertEqual(
            create.call_args.kwargs["share_access"],
            windows_native.FILE_SHARE_READ | windows_native.FILE_SHARE_WRITE,
        )

    def test_private_acl_replaces_acl_through_the_pinned_handle(self) -> None:
        advapi32 = mock.Mock()

        def provide_owner(
            _descriptor: object,
            owner: object,
            _defaulted: object,
        ) -> bool:
            ctypes.cast(owner, ctypes.POINTER(wintypes.LPVOID))[0] = wintypes.LPVOID(303)
            return True

        def provide_dacl(
            _descriptor: object,
            present: object,
            dacl: object,
            _defaulted: object,
        ) -> bool:
            ctypes.cast(present, ctypes.POINTER(wintypes.BOOL))[0] = wintypes.BOOL(True)
            ctypes.cast(dacl, ctypes.POINTER(wintypes.LPVOID))[0] = wintypes.LPVOID(302)
            return True

        advapi32.GetSecurityDescriptorDacl.side_effect = provide_dacl
        advapi32.GetSecurityDescriptorOwner.side_effect = provide_owner
        advapi32.SetSecurityInfo.return_value = 0
        with (
            mock.patch.object(windows_native, "_dll", return_value=advapi32),
            mock.patch.object(
                windows_native,
                "private_security_descriptor",
                return_value=contextlib.nullcontext(wintypes.LPVOID(301)),
            ),
            mock.patch.object(windows_native, "validate_private_acl") as validate_acl,
        ):
            windows_native.apply_private_acl(101, owner_rebind=True)

        arguments = advapi32.SetSecurityInfo.call_args.args
        self.assertEqual(arguments[0].value, 101)
        self.assertEqual(arguments[1], windows_native.SE_FILE_OBJECT)
        self.assertEqual(
            arguments[2],
            windows_native.OWNER_SECURITY_INFORMATION
            | windows_native.DACL_SECURITY_INFORMATION
            | windows_native.PROTECTED_DACL_SECURITY_INFORMATION,
        )
        self.assertEqual(arguments[3].value, 303)
        self.assertEqual(arguments[5].value, 302)
        validate_acl.assert_called_once_with(101)

    def test_private_acl_preserves_an_already_correct_owner(self) -> None:
        advapi32 = mock.Mock()

        def provide_owner(
            _descriptor: object,
            owner: object,
            _defaulted: object,
        ) -> bool:
            ctypes.cast(owner, ctypes.POINTER(wintypes.LPVOID))[0] = wintypes.LPVOID(303)
            return True

        def provide_dacl(
            _descriptor: object,
            present: object,
            dacl: object,
            _defaulted: object,
        ) -> bool:
            ctypes.cast(present, ctypes.POINTER(wintypes.BOOL))[0] = wintypes.BOOL(True)
            ctypes.cast(dacl, ctypes.POINTER(wintypes.LPVOID))[0] = wintypes.LPVOID(302)
            return True

        advapi32.GetSecurityDescriptorDacl.side_effect = provide_dacl
        advapi32.GetSecurityDescriptorOwner.side_effect = provide_owner
        advapi32.SetSecurityInfo.return_value = 0
        with (
            mock.patch.object(windows_native, "_dll", return_value=advapi32),
            mock.patch.object(
                windows_native,
                "private_security_descriptor",
                return_value=contextlib.nullcontext(wintypes.LPVOID(301)),
            ),
            mock.patch.object(windows_native, "_handle_has_owner", return_value=True),
            mock.patch.object(windows_native, "validate_private_acl") as validate_acl,
        ):
            windows_native.apply_private_acl(101)

        arguments = advapi32.SetSecurityInfo.call_args.args
        self.assertEqual(
            arguments[2],
            windows_native.DACL_SECURITY_INFORMATION
            | windows_native.PROTECTED_DACL_SECURITY_INFORMATION,
        )
        self.assertIsNone(arguments[3])
        self.assertEqual(arguments[5].value, 302)
        validate_acl.assert_called_once_with(101)

    def test_private_acl_requires_owner_rebind_before_mutating_a_mismatched_owner(self) -> None:
        advapi32 = mock.Mock()

        def provide_owner(
            _descriptor: object,
            owner: object,
            _defaulted: object,
        ) -> bool:
            ctypes.cast(owner, ctypes.POINTER(wintypes.LPVOID))[0] = wintypes.LPVOID(303)
            return True

        advapi32.GetSecurityDescriptorOwner.side_effect = provide_owner
        with (
            mock.patch.object(windows_native, "_dll", return_value=advapi32),
            mock.patch.object(
                windows_native,
                "private_security_descriptor",
                return_value=contextlib.nullcontext(wintypes.LPVOID(301)),
            ),
            mock.patch.object(windows_native, "_handle_has_owner", return_value=False),
            self.assertRaises(windows_native.WindowsPrivateOwnerRebindRequired),
        ):
            windows_native.apply_private_acl(101)

        advapi32.SetSecurityInfo.assert_not_called()

    def test_every_relative_open_closes_when_immediate_handle_inspection_fails(self) -> None:
        cases = (
            lambda: windows_native.create_fresh_directory(99, "private"),
            lambda: windows_native.open_relative_directory(99, "private", writable=False),
            lambda: windows_native.open_relative_regular_file(99, "private.bin"),
            lambda: windows_native._open_relative_for_delete(
                99,
                "private.bin",
                directory=False,
            ),
            lambda: windows_native.create_or_replace_regular_file(
                99,
                "private.bin",
                exclusive=True,
            ),
        )
        failure = windows_native.WindowsNativeError("synthetic inspection failure")
        for open_handle in cases:
            with (
                self.subTest(open_handle=open_handle),
                mock.patch.object(
                    windows_native,
                    "private_security_descriptor",
                    return_value=contextlib.nullcontext(301),
                ),
                mock.patch.object(
                    windows_native,
                    "_nt_create_relative",
                    return_value=(101, windows_native.FILE_CREATED),
                ),
                mock.patch.object(
                    windows_native,
                    "handle_information",
                    side_effect=failure,
                ),
                mock.patch.object(windows_native, "close_handle") as close,
                self.assertRaisesRegex(
                    windows_native.WindowsNativeError,
                    "synthetic inspection failure",
                ),
            ):
                open_handle()
            close.assert_called_once_with(101)

    def test_filesystem_runtime_accepts_windows_10_while_ios_requires_windows_11(self) -> None:
        windows_10 = types.SimpleNamespace(major=10, build=19045)
        with (
            mock.patch.object(windows_native, "_require_windows"),
            mock.patch.object(windows_native.platform, "machine", return_value="AMD64"),
            mock.patch.object(
                windows_native.sys,
                "getwindowsversion",
                return_value=windows_10,
                create=True,
            ),
        ):
            windows_native.require_filesystem_runtime()
            with self.assertRaisesRegex(
                windows_native.WindowsUnsupportedError,
                "Encrypted iOS recovery requires Windows 11",
            ):
                windows_native.require_supported_runtime()

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

    def test_source_volume_probe_rejects_refs_and_requires_persistent_acls(self) -> None:
        for capabilities in (
            windows_native.WindowsVolumeCapabilities(
                filesystem_name="ReFS",
                filesystem_flags=windows_native.FILE_PERSISTENT_ACLS,
            ),
            windows_native.WindowsVolumeCapabilities(
                filesystem_name="exFAT",
                filesystem_flags=0,
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
                windows_native.require_source_ntfs_volume(123)

        supported = windows_native.WindowsVolumeCapabilities(
            filesystem_name="NTFS",
            filesystem_flags=windows_native.FILE_PERSISTENT_ACLS,
        )
        with mock.patch.object(
            windows_native,
            "volume_capabilities",
            return_value=supported,
        ):
            windows_native.require_source_ntfs_volume(123)

    def test_general_capability_probe_uses_the_windows_10_filesystem_gate(self) -> None:
        rejected = windows_native.WindowsUnsupportedError("synthetic filesystem runtime")
        with (
            mock.patch.object(
                windows_native,
                "require_filesystem_runtime",
                side_effect=rejected,
            ) as require_filesystem,
            mock.patch.object(windows_native, "require_supported_runtime") as require_ios_runtime,
            self.assertRaisesRegex(
                windows_native.WindowsUnsupportedError,
                "synthetic filesystem runtime",
            ),
        ):
            windows_native.require_recovery_capabilities(123)
        require_filesystem.assert_called_once_with()
        require_ios_runtime.assert_not_called()


@unittest.skipUnless(os.name == "nt", "real NTFS capability regression")
class WindowsNativeNtfsTests(unittest.TestCase):
    def setUp(self) -> None:
        windows_native.require_filesystem_runtime()

    def test_safety_acl_creator_matches_validator_for_directories_and_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "synthetic-safety-acl-root"
            child = root / "nested"
            private_file = root / "synthetic.partial"
            parent_handle = -1
            root_handle = -1
            child_handle = -1
            descriptor = -1
            try:
                parent_handle, _identity = _windows_open_locked_directory(
                    parent,
                    allow_child_creation=True,
                )
                try:
                    windows_native.require_private_ntfs_volume(parent_handle)
                except windows_native.WindowsUnsupportedError as exc:
                    self.skipTest(str(exc))

                root_handle = _windows_create_private_directory_relative(
                    parent_handle,
                    root.name,
                )
                windows_native.validate_private_acl(root_handle)
                child_handle = _windows_create_private_directory_relative(root_handle, child.name)
                windows_native.validate_private_acl(child_handle)

                windows_native.close_handle(child_handle)
                child_handle = -1
                windows_native.close_handle(root_handle)
                root_handle = -1

                descriptor = windows_create_private_staging_descriptor(private_file)
                os.write(descriptor, b"synthetic private payload")
                os.fsync(descriptor)
                require_private_descriptor(descriptor, expected_type=stat.S_IFREG)

                os.close(descriptor)
                descriptor = -1
                require_private_path(child, expected_type=stat.S_IFDIR)
                require_private_path(private_file, expected_type=stat.S_IFREG)
                with anchored_existing_extraction_root(root):
                    text_path = root / "synthetic.txt"
                    bytes_path = root / "synthetic.bin"
                    json_path = root / "synthetic.json"
                    write_text_private(text_path, "first\n")
                    write_text_private(text_path, "second\n")
                    write_bytes_private(bytes_path, b"first")
                    write_bytes_private(bytes_path, b"second")
                    write_json_private_atomic(json_path, {"state": "first"})
                    write_json_private_atomic(json_path, {"state": "second"})
                    for output in (text_path, bytes_path, json_path):
                        require_private_path(output, expected_type=stat.S_IFREG)
                    self.assertEqual(text_path.read_text(encoding="utf-8"), "second\n")
                    self.assertEqual(bytes_path.read_bytes(), b"second")
                    self.assertEqual(
                        json.loads(json_path.read_text(encoding="utf-8")),
                        {"state": "second"},
                    )

                    with private_temporary_directory(
                        parent=root,
                        prefix=".synthetic-private-",
                    ) as temporary_root:
                        staged_temporary = temporary_root
                        nested_temporary = secure_directory(temporary_root / "nested")
                        temporary_file = nested_temporary / "payload.bin"
                        write_bytes_private(temporary_file, b"temporary")
                        require_private_path(temporary_file, expected_type=stat.S_IFREG)
                    self.assertFalse(staged_temporary.exists())

                    database = root / "synthetic.sqlite"
                    database_descriptor = windows_create_private_staging_descriptor(database)
                    os.close(database_descriptor)
                    with (
                        contextlib.closing(sqlite3.connect(database)) as connection,
                        connection,
                    ):
                        connection.execute("PRAGMA journal_mode=OFF")
                        connection.execute("CREATE TABLE synthetic (value TEXT NOT NULL)")
                        connection.execute("INSERT INTO synthetic VALUES ('private')")
                    require_private_path(database, expected_type=stat.S_IFREG)
                    with readonly_sqlite(
                        database,
                        require_private_source=True,
                    ) as connection:
                        self.assertEqual(
                            connection.execute("SELECT value FROM synthetic").fetchone(),
                            ("private",),
                        )
            finally:
                if descriptor >= 0:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)
                if child_handle >= 0:
                    windows_native.close_handle(child_handle)
                if root_handle >= 0:
                    windows_native.close_handle(root_handle)
                if parent_handle >= 0:
                    _windows_close_handle(parent_handle)

    def test_atomic_fresh_root_has_one_winner_and_blocks_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent_handle = -1
            winner_handle = -1
            try:
                parent_handle, _identity = _windows_open_locked_directory(
                    parent,
                    allow_child_creation=True,
                )
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
                winner_identity = windows_native.handle_information(winner_handle).identity
                _require_windows_visible_directory_identity(
                    fresh,
                    expected_identity=winner_identity,
                )
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

    def test_traversal_reopens_delete_capabilities_without_sharing_violation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent_handle = -1
            root_handle = -1
            child_handle = -1
            reopened_root = -1
            reopened_child = -1
            try:
                parent_handle, _identity = _windows_open_locked_directory(
                    parent,
                    allow_child_creation=True,
                )
                try:
                    windows_native.require_private_ntfs_volume(parent_handle)
                except windows_native.WindowsUnsupportedError as exc:
                    self.skipTest(str(exc))

                root_handle = _windows_create_private_directory_relative(
                    parent_handle,
                    "synthetic-retained-root",
                )
                reopened_root = windows_native.open_relative_directory(
                    parent_handle,
                    "synthetic-retained-root",
                    writable=False,
                )
                child_handle = _windows_create_private_directory_relative(
                    root_handle,
                    "nested",
                )
                reopened_child = windows_native.open_relative_directory(
                    root_handle,
                    "nested",
                    writable=False,
                )
                self.assertEqual(
                    windows_native.handle_information(root_handle).identity,
                    windows_native.handle_information(reopened_root).identity,
                )
                self.assertEqual(
                    windows_native.handle_information(child_handle).identity,
                    windows_native.handle_information(reopened_child).identity,
                )
            finally:
                for handle in (
                    reopened_child,
                    reopened_root,
                    child_handle,
                    root_handle,
                ):
                    if handle >= 0:
                        windows_native.close_handle(handle)
                if parent_handle >= 0:
                    _windows_close_handle(parent_handle)

    def test_retained_existing_root_blocks_rename_and_removal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent_handle = -1
            root_handle = -1
            try:
                parent_handle, _identity = _windows_open_locked_directory(
                    parent,
                    allow_child_creation=True,
                )
                try:
                    windows_native.require_private_ntfs_volume(parent_handle)
                except windows_native.WindowsUnsupportedError as exc:
                    self.skipTest(str(exc))

                root_handle = windows_native.create_fresh_directory(
                    parent_handle,
                    "synthetic-retained-existing-root",
                )
                root = parent / "synthetic-retained-existing-root"
                windows_native.close_handle(root_handle)
                root_handle = -1
                with anchored_existing_extraction_root(root):
                    with self.assertRaises(OSError):
                        root.rename(parent / "synthetic-replaced-root")
                    with self.assertRaises(OSError):
                        root.rmdir()
            finally:
                if root_handle >= 0:
                    windows_native.close_handle(root_handle)
                if parent_handle >= 0:
                    _windows_close_handle(parent_handle)

    def test_existing_extraction_rejects_acl_readable_by_everyone(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent_handle = -1
            root_handle = -1
            try:
                parent_handle, _identity = _windows_open_locked_directory(
                    parent,
                    allow_child_creation=True,
                )
                try:
                    windows_native.require_private_ntfs_volume(parent_handle)
                except windows_native.WindowsUnsupportedError as exc:
                    self.skipTest(str(exc))
                root_handle = windows_native.create_fresh_directory(
                    parent_handle,
                    "synthetic-existing-extraction",
                )
                root = parent / "synthetic-existing-extraction"
                windows_native.close_handle(root_handle)
                root_handle = -1
                with anchored_existing_extraction_root(root):
                    pass
                result = subprocess.run(
                    ["icacls", os.fspath(root), "/grant", "*S-1-1-0:(R)"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    self.skipTest("icacls could not create the synthetic loose-ACL fixture")
                with (
                    self.assertRaisesRegex(UnsafePathError, "owner-only"),
                    anchored_existing_extraction_root(root),
                ):
                    pass
            finally:
                if root_handle >= 0:
                    windows_native.close_handle(root_handle)
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
                parent_handle, _identity = _windows_open_locked_directory(
                    parent,
                    allow_child_creation=True,
                )
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
                parent_handle, _identity = _windows_open_locked_directory(
                    parent,
                    allow_child_creation=True,
                )
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

    def test_private_tree_cleanup_removes_only_a_synthetic_reparse_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent_handle = -1
            root_handle = -1
            try:
                parent_handle, _identity = _windows_open_locked_directory(
                    parent,
                    allow_child_creation=True,
                )
                try:
                    windows_native.require_private_ntfs_volume(parent_handle)
                except windows_native.WindowsUnsupportedError as exc:
                    self.skipTest(str(exc))
                root_handle = windows_native.create_fresh_directory(
                    parent_handle,
                    "synthetic-cleanup-parent",
                )
                root = parent / "synthetic-cleanup-parent"
                windows_native.close_handle(root_handle)
                root_handle = -1
                external = secure_directory(root / "synthetic-cleanup-target")
                external_file = external / "must-remain.bin"
                write_bytes_private(external_file, b"must remain")
                with (
                    anchored_existing_extraction_root(root),
                    private_temporary_directory(
                        parent=root,
                        prefix=".synthetic-reparse-",
                    ) as temporary_root,
                ):
                    staged_temporary = temporary_root
                    redirect = temporary_root / "redirect"
                    try:
                        os.symlink(external, redirect, target_is_directory=True)
                    except OSError as exc:
                        self.skipTest(
                            "directory symlink creation is unavailable: "
                            f"{getattr(exc, 'winerror', None)}"
                        )
                self.assertFalse(staged_temporary.exists())
                self.assertEqual(external_file.read_bytes(), b"must remain")
            finally:
                if root_handle >= 0:
                    windows_native.close_handle(root_handle)
                if parent_handle >= 0:
                    _windows_close_handle(parent_handle)


if __name__ == "__main__":
    unittest.main()
