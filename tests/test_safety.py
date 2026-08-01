from __future__ import annotations

import csv
import errno
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tvtime_extractor.errors import UserInputError
from tvtime_extractor.safety import (
    extended_acl_state,
    harden_private_descriptor,
    private_source_id,
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
            formula_like_values = (
                '=WEBSERVICE("https://example.invalid")',
                "+SYNTHETIC()",
                "-SYNTHETIC()",
                "@SYNTHETIC()",
                "\tSYNTHETIC()",
                "\rSYNTHETIC()",
                "\nSYNTHETIC()",
            )
            input_rows = [{"title": value} for value in formula_like_values]
            input_rows.append({"title": "普通の番組"})
            write_csv_private(
                output,
                input_rows,
                ["title"],
            )
            with output.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(
                [row["title"] for row in rows[:-1]],
                [f"'{value}" for value in formula_like_values],
            )
            self.assertEqual(rows[-1]["title"], "普通の番組")


if __name__ == "__main__":
    unittest.main()
