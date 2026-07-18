from __future__ import annotations

import csv
import os
import stat
import tempfile
import unittest
from pathlib import Path

from tvtime_extractor.errors import UserInputError
from tvtime_extractor.safety import (
    EXTRACTION_DIRECTORY_NAME,
    prepare_extraction_layout,
    private_source_id,
    safe_domain_component,
    safe_join,
    safe_manifest_relative_path,
    sanitize_public_url,
    write_csv_private,
    write_text_private,
)


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
            write_text_private(output, "synthetic")
            self.assertEqual(output.read_text(encoding="utf-8"), "synthetic")
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
