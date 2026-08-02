from __future__ import annotations

import unittest

from script.release_version import marketing_version, python_version


class ReleaseVersionTests(unittest.TestCase):
    def test_stable_version_is_unchanged(self) -> None:
        self.assertEqual(marketing_version("0.3.0"), "0.3.0")
        self.assertEqual(python_version("0.3.0"), "0.3.0")

    def test_prerelease_has_platform_safe_versions(self) -> None:
        self.assertEqual(marketing_version("0.3.0-alpha.1"), "0.3.0")
        self.assertEqual(python_version("0.3.0-alpha.1"), "0.3.0a1")
        self.assertEqual(marketing_version("0.3.1-alpha.1"), "0.3.1")
        self.assertEqual(python_version("0.3.1-alpha.1"), "0.3.1a1")
        self.assertEqual(python_version("1.4.2-beta.3"), "1.4.2b3")
        self.assertEqual(python_version("2.0.0-rc.4"), "2.0.0rc4")

    def test_invalid_or_ambiguous_versions_fail_closed(self) -> None:
        for value in (
            "v0.3.0-alpha.1",
            "0.3",
            "0.3.0-alpha.0",
            "0.3.0-preview.1",
            "0.3.0+local",
            "01.2.3-alpha.1",
            "1.02.3-alpha.1",
            "1.2.03-alpha.1",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                python_version(value)


if __name__ == "__main__":
    unittest.main()
