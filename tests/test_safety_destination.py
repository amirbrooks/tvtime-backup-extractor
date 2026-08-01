from __future__ import annotations

import errno
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from tvtime_extractor.errors import OutputExistsError, UnsafePathError, UserInputError
from tvtime_extractor.safety import (
    _WINDOWS_FILE_ATTRIBUTE_OFFLINE,
    _WINDOWS_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    _WINDOWS_FILE_ATTRIBUTE_RECALL_ON_OPEN,
    EXTRACTION_DIRECTORY_NAME,
    _darwin_volume_is_local,
    _linux_volume_is_local,
    anchored_bound_output_root,
    anchored_existing_extraction_root,
    held_destination_parent,
    is_known_synced_or_shared_path,
    is_within,
    iter_regular_files,
    no_link_absolute_path,
    prepare_anchored_extraction_layout,
    prepare_extraction_layout,
    promote_directory_no_replace_atomic,
    promote_file_no_replace_atomic,
    require_bound_destination_parent,
    require_local_recovery_source,
    require_private_local_destination,
    write_bytes_private,
    write_text_private,
)


class DestinationSafetyTests(unittest.TestCase):
    class _DarwinStatFSFunction:
        def __init__(self, flags: int) -> None:
            self.flags = flags
            self.calls = 0
            self.argtypes: object = None
            self.restype: object = None

        def __call__(self, _path: bytes, filesystem_pointer: object) -> int:
            self.calls += 1
            filesystem_pointer._obj.f_flags = self.flags  # type: ignore[attr-defined]
            return 0

    def test_darwin_local_volume_prefers_current_inode64_statfs_abi(self) -> None:
        legacy = self._DarwinStatFSFunction(0)
        current = self._DarwinStatFSFunction(0x00001000)
        libc = type("SyntheticDarwinLibC", (), {"statfs": legacy})()
        setattr(libc, "statfs$INODE64", current)

        with mock.patch("tvtime_extractor.safety.ctypes.CDLL", return_value=libc):
            self.assertTrue(_darwin_volume_is_local(Path("/synthetic/private")))

        self.assertEqual(current.calls, 1)
        self.assertEqual(legacy.calls, 0)

    def test_darwin_local_volume_uses_bare_statfs_when_modern_symbol_is_absent(self) -> None:
        current = self._DarwinStatFSFunction(0x00001000)
        libc = type("SyntheticDarwinLibC", (), {"statfs": current})()

        with mock.patch("tvtime_extractor.safety.ctypes.CDLL", return_value=libc):
            self.assertTrue(_darwin_volume_is_local(Path("/synthetic/private")))

        self.assertEqual(current.calls, 1)

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

    def test_recovery_source_rejects_cloud_shared_and_nonlocal_storage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "synthetic-source"
            source.write_bytes(b"synthetic")
            with (
                mock.patch(
                    "tvtime_extractor.safety.is_known_synced_or_shared_path",
                    return_value=True,
                ),
                mock.patch("tvtime_extractor.safety._volume_is_local") as volume_is_local,
                self.assertRaisesRegex(UnsafePathError, "cloud-synced or shared recovery source"),
            ):
                require_local_recovery_source(source)
            volume_is_local.assert_not_called()

            with (
                mock.patch(
                    "tvtime_extractor.safety.is_known_synced_or_shared_path",
                    return_value=False,
                ),
                mock.patch("tvtime_extractor.safety._volume_is_local", return_value=False),
                self.assertRaisesRegex(UnsafePathError, "confirmed as local storage"),
            ):
                require_local_recovery_source(source)

    def test_sync_policy_remains_fail_closed_without_a_helper_home_environment(self) -> None:
        minimal_helper_environment = {
            "SystemRoot": "C:/Windows",
            "WINDIR": "C:/Windows",
            "TEMP": "C:/Synthetic/Temp",
            "TMP": "C:/Synthetic/Temp",
            "TVTIME_SECRET_HANDLE": "3",
            "TVTIME_DESTINATION_HANDLE": "4",
        }
        with mock.patch.object(
            Path,
            "home",
            side_effect=RuntimeError("synthetic missing profile environment"),
        ):
            self.assertFalse(
                is_known_synced_or_shared_path(
                    Path("C:/Users/Synthetic/Documents/Private Recovery"),
                    environment=minimal_helper_environment,
                )
            )
            self.assertTrue(
                is_known_synced_or_shared_path(
                    Path("C:/Users/Synthetic/OneDrive - Example/Recovery"),
                    environment=minimal_helper_environment,
                )
            )

    def test_windows_recovery_source_rejects_cloud_hydration_attributes(self) -> None:
        source = Path("C:/Synthetic/local-source")
        for attribute in (
            _WINDOWS_FILE_ATTRIBUTE_OFFLINE,
            _WINDOWS_FILE_ATTRIBUTE_RECALL_ON_OPEN,
            _WINDOWS_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        ):
            metadata = mock.Mock(st_mode=stat.S_IFREG, st_file_attributes=attribute)
            with (
                self.subTest(attribute=attribute),
                mock.patch(
                    "tvtime_extractor.safety.no_link_absolute_path",
                    return_value=source,
                ),
                mock.patch(
                    "tvtime_extractor.safety.is_known_synced_or_shared_path",
                    return_value=False,
                ),
                mock.patch(
                    "tvtime_extractor.safety._windows_enumerated_path_metadata",
                    return_value=metadata,
                ),
                mock.patch("tvtime_extractor.safety._volume_is_local", return_value=True),
                mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
                mock.patch("tvtime_extractor.safety._windows_require_source_ntfs_volume"),
                self.assertRaisesRegex(UnsafePathError, "not fully present on local storage"),
            ):
                require_local_recovery_source(source)

    def test_windows_recovery_source_rejects_non_ntfs_before_file_metadata(self) -> None:
        source = Path("C:/Synthetic/local-source")
        rejected = UnsafePathError(
            "Windows recovery sources must be on private local NTFS storage."
        )
        with (
            mock.patch(
                "tvtime_extractor.safety.no_link_absolute_path",
                return_value=source,
            ),
            mock.patch(
                "tvtime_extractor.safety.is_known_synced_or_shared_path",
                return_value=False,
            ),
            mock.patch("tvtime_extractor.safety._volume_is_local", return_value=True),
            mock.patch("tvtime_extractor.safety._running_on_windows", return_value=True),
            mock.patch(
                "tvtime_extractor.safety._windows_require_source_ntfs_volume",
                side_effect=rejected,
            ) as require_ntfs,
            mock.patch("tvtime_extractor.safety._windows_enumerated_path_metadata") as metadata,
            self.assertRaisesRegex(UnsafePathError, "private local NTFS storage"),
        ):
            require_local_recovery_source(source)

        require_ntfs.assert_called_once_with(source)
        metadata.assert_not_called()

    def test_regular_tree_rejects_nested_cloud_metadata_before_yielding_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private-tree"
            nested = root / "nested"
            nested.mkdir(parents=True, mode=0o700)
            payload = nested / "synthetic.bin"
            payload.write_bytes(b"synthetic")
            root.chmod(0o700)
            nested.chmod(0o700)
            payload.chmod(0o600)

            for blocked in (nested, payload):
                blocked_inode = blocked.lstat().st_ino

                def reject_blocked(
                    metadata: os.stat_result,
                    *,
                    expected_inode: int = blocked_inode,
                ) -> None:
                    if metadata.st_ino == expected_inode:
                        raise UnsafePathError(
                            "Refusing a cloud-backed file or directory that is not fully present "
                            "on local storage."
                        )

                with (
                    self.subTest(blocked=blocked.name),
                    mock.patch(
                        "tvtime_extractor.safety.require_non_hydrated_windows_metadata",
                        side_effect=reject_blocked,
                    ),
                    self.assertRaisesRegex(UnsafePathError, "not fully present on local storage"),
                ):
                    list(iter_regular_files(root))

    def test_existing_extraction_is_rejected_before_opening_a_nonlocal_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            extraction = Path(temporary) / "Synthetic-Extraction"
            extraction.mkdir()
            with (
                mock.patch("tvtime_extractor.safety._volume_is_local", return_value=False),
                mock.patch(
                    "tvtime_extractor.safety._windows_open_locked_directory"
                ) as open_windows_root,
                self.assertRaisesRegex(UnsafePathError, "confirmed as local storage"),
                anchored_existing_extraction_root(extraction),
            ):
                self.fail("A nonlocal extraction root must never be opened.")
            open_windows_root.assert_not_called()

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
