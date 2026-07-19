from __future__ import annotations

import os
import plistlib
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import tvtime_extractor.analyze as analyze_module
from tests.helpers import create_synthetic_extraction
from tvtime_extractor.analyze import analyze_extraction
from tvtime_extractor.errors import UnsafePathError
from tvtime_extractor.safety import (
    iter_regular_files,
    read_regular_bytes,
    regular_binary_reader,
    write_bytes_private,
)


class AnalyzerNoFollowTests(unittest.TestCase):
    def test_plist_parse_uses_one_held_identity_across_a_visible_swap_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extraction = create_synthetic_extraction(root)
            preferences = (
                extraction
                / "raw"
                / "AppDomain-com.tozelabs.tvshowtime"
                / "Library"
                / "Preferences.plist"
            )
            replacement = root / "synthetic-replacement.plist"
            parked = root / "synthetic-original.plist"
            write_bytes_private(
                replacement,
                plistlib.dumps({"SyntheticReplacementValue": True}),
                exclusive=True,
            )
            original_payload = preferences.read_bytes()
            real_reader = regular_binary_reader
            preference_opens = 0
            swapped = False
            held_payload = bytearray()

            class SwapBeforeRead:
                def __init__(self, handle) -> None:
                    self.handle = handle

                def read(self, byte_count: int) -> bytes:
                    nonlocal swapped
                    if not swapped:
                        os.replace(preferences, parked)
                        os.replace(replacement, preferences)
                        swapped = True
                    payload = self.handle.read(byte_count)
                    held_payload.extend(payload)
                    return payload

            @contextmanager
            def swap_before_plist_read(path: Path, *, require_private: bool = False):
                nonlocal preference_opens
                with real_reader(path, require_private=require_private) as (handle, metadata):
                    is_preferences = path.name == preferences.name
                    use_proxy = is_preferences and preference_opens == 1
                    if is_preferences:
                        preference_opens += 1
                    try:
                        yield (SwapBeforeRead(handle) if use_proxy else handle), metadata
                    finally:
                        if use_proxy and swapped:
                            os.replace(preferences, replacement)
                            os.replace(parked, preferences)

            with (
                mock.patch.object(
                    analyze_module,
                    "regular_binary_reader",
                    side_effect=swap_before_plist_read,
                ),
                self.assertRaises(UnsafePathError),
            ):
                analyze_extraction(extraction_directory=extraction)

            self.assertTrue(swapped)
            self.assertEqual(bytes(held_payload), original_payload)
            self.assertEqual(plistlib.loads(bytes(held_payload)), {"SyntheticFeatureEnabled": True})
            self.assertFalse((extraction / "analysis").exists())

    def test_sqlite_snapshot_rejects_boundary_swap_even_when_path_is_restored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extraction = create_synthetic_extraction(root)
            image_database = (
                extraction
                / "raw"
                / "AppDomain-com.tozelabs.tvshowtime"
                / "Library"
                / "Application Support"
                / "libCachedImageData.db"
            )
            replacement = root / "synthetic-replacement.db"
            parked = root / "synthetic-original.db"
            write_bytes_private(replacement, image_database.read_bytes(), exclusive=True)
            real_snapshot_sources = analyze_module._sqlite_snapshot_sources
            swapped = False
            binding_rejected = False

            def swap_before_snapshot(
                path: Path,
                *,
                expected_main_metadata=None,
                require_private_source: bool = False,
            ):
                nonlocal binding_rejected, swapped
                if path.name != image_database.name or expected_main_metadata is None or swapped:
                    return real_snapshot_sources(
                        path,
                        expected_main_metadata=expected_main_metadata,
                        require_private_source=require_private_source,
                    )
                os.replace(image_database, parked)
                os.replace(replacement, image_database)
                swapped = True
                try:
                    try:
                        return real_snapshot_sources(
                            path,
                            expected_main_metadata=expected_main_metadata,
                            require_private_source=require_private_source,
                        )
                    except UnsafePathError:
                        binding_rejected = True
                        raise
                finally:
                    os.replace(image_database, replacement)
                    os.replace(parked, image_database)

            with (
                mock.patch.object(
                    analyze_module,
                    "_sqlite_snapshot_sources",
                    side_effect=swap_before_snapshot,
                ),
                self.assertRaises(UnsafePathError),
            ):
                analyze_extraction(extraction_directory=extraction)

            self.assertTrue(swapped)
            self.assertTrue(binding_rejected)
            self.assertFalse((extraction / "analysis").exists())

    @unittest.skipIf(os.name == "nt", "POSIX private-mode regression")
    def test_sqlite_snapshot_preserves_unsafe_path_for_nonprivate_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = create_synthetic_extraction(Path(temporary))
            image_database = (
                extraction
                / "raw"
                / "AppDomain-com.tozelabs.tvshowtime"
                / "Library"
                / "Application Support"
                / "libCachedImageData.db"
            )
            sidecar = image_database.with_name(image_database.name + "-wal")
            write_bytes_private(sidecar, b"synthetic-private-sidecar", exclusive=True)
            sidecar.chmod(0o644)

            with self.assertRaises(UnsafePathError):
                analyze_module._sqlite_snapshot_sources(
                    image_database,
                    require_private_source=True,
                )

    @unittest.skipIf(os.name == "nt", "symbolic-link creation varies on Windows")
    def test_analyzer_never_parses_plist_symlink_swapped_after_enumeration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extraction = create_synthetic_extraction(root)
            preferences = (
                extraction
                / "raw"
                / "AppDomain-com.tozelabs.tvshowtime"
                / "Library"
                / "Preferences.plist"
            )
            external = root / "external-private.plist"
            write_bytes_private(
                external,
                plistlib.dumps({"SyntheticExternalValue": "must-not-be-read"}),
                exclusive=True,
            )

            def enumerate_then_swap(raw: Path):
                paths = list(iter_regular_files(raw))
                yield from paths
                preferences.unlink()
                preferences.symlink_to(external)

            with (
                mock.patch.object(
                    analyze_module,
                    "iter_regular_files",
                    side_effect=enumerate_then_swap,
                ),
                mock.patch.object(
                    analyze_module.plistlib,
                    "loads",
                    wraps=plistlib.loads,
                ) as plist_loads,
                self.assertRaises(UnsafePathError),
            ):
                analyze_extraction(extraction_directory=extraction)

            plist_loads.assert_not_called()
            self.assertFalse((extraction / "analysis").exists())

    def test_bounded_binary_readers_reject_preopen_replacement(self) -> None:
        readers = {
            "complete": lambda path: read_regular_bytes(
                path,
                maximum_bytes=64,
                require_private=True,
            ),
            "held": self._read_held_prefix,
        }
        for label, reader in readers.items():
            with self.subTest(reader=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "source.bin"
                replacement = root / "replacement.bin"
                write_bytes_private(source, b"synthetic-original", exclusive=True)
                write_bytes_private(replacement, b"synthetic-replacement", exclusive=True)
                original_open = os.open
                replaced = False

                def replace_before_open(
                    candidate,
                    *args,
                    _source: Path = source,
                    _replacement: Path = replacement,
                    _original_open=original_open,
                    **kwargs,
                ):
                    nonlocal replaced
                    if not replaced and Path(candidate) == _source:
                        os.replace(_replacement, _source)
                        replaced = True
                    return _original_open(candidate, *args, **kwargs)

                with (
                    mock.patch(
                        "tvtime_extractor.safety.os.open",
                        side_effect=replace_before_open,
                    ),
                    self.assertRaises(UnsafePathError),
                ):
                    reader(source)
                self.assertTrue(replaced)

    def test_held_binary_reader_rejects_visible_replacement_before_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            replacement = root / "replacement.bin"
            write_bytes_private(source, b"synthetic-original", exclusive=True)
            write_bytes_private(replacement, b"synthetic-replacement", exclusive=True)

            with (
                self.assertRaises(UnsafePathError),
                regular_binary_reader(
                    source,
                    require_private=True,
                ) as (handle, _metadata),
            ):
                self.assertEqual(handle.read(4), b"synt")
                os.replace(replacement, source)

    @staticmethod
    def _read_held_prefix(path: Path) -> bytes:
        with regular_binary_reader(path, require_private=True) as (handle, _metadata):
            return handle.read(4)


if __name__ == "__main__":
    unittest.main()
