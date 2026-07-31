from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from script.collect_windows_licenses import (
    BUILD_ONLY_NUGET_PACKAGES,
    PRIVATE_WINDOWS_VERSION,
    REVIEWED_CPYTHON_VERSION,
    _collect_nuget,
    _nuget_bindings,
)


class WindowsLicenseCollectionTests(unittest.TestCase):
    def test_controlled_versions_match_private_windows_build_inputs(self) -> None:
        self.assertEqual(REVIEWED_CPYTHON_VERSION, "3.13.12")
        self.assertEqual(PRIVATE_WINDOWS_VERSION, "0.3.0")
        self.assertEqual(
            BUILD_ONLY_NUGET_PACKAGES,
            {("Microsoft.Windows.SDK.BuildTools", "10.0.26100.4948")},
        )

    def synthetic_package(self, root: Path) -> tuple[Path, Path]:
        package_root = root / "fake.package" / "1.2.3"
        package_root.mkdir(parents=True)
        package = package_root / "fake.package.1.2.3.nupkg"
        payload = b"synthetic-nuget-package"
        package.write_bytes(payload)
        package_hash = base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
        (package_root / "fake.package.1.2.3.nupkg.sha512").write_text(
            package_hash, encoding="ascii"
        )
        content_hash = base64.b64encode(hashlib.sha512(b"synthetic-content").digest()).decode(
            "ascii"
        )
        (package_root / ".nupkg.metadata").write_text(
            json.dumps({"version": 2, "contentHash": content_hash, "source": "synthetic"}),
            encoding="utf-8",
        )
        (package_root / "fake.package.nuspec").write_text(
            """<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Fake.Package</id><version>1.2.3</version>
    <license type="expression">MIT</license>
  </metadata>
</package>
""",
            encoding="utf-8",
        )
        lock = root / "packages.lock.json"
        lock.write_text(
            json.dumps(
                {
                    "version": 1,
                    "dependencies": {
                        "net8.0-windows": {
                            "Fake.Package": {
                                "type": "Transitive",
                                "resolved": "1.2.3",
                                "contentHash": content_hash,
                            }
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        return lock, package

    def test_nuget_collection_binds_package_hash_metadata_and_license(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, _package = self.synthetic_package(root)
            output = root / "notices"
            output.mkdir()
            components = _collect_nuget(output, lock, root)
            self.assertEqual(len(components), 1)
            self.assertEqual(components[0]["name"], "Fake.Package")
            license_path = output / "nuget" / "Fake.Package" / "license-expression.txt"
            self.assertEqual(license_path.read_text(encoding="utf-8"), "MIT\n")

    def test_nuget_collection_rejects_package_byte_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, package = self.synthetic_package(root)
            package.write_bytes(b"tampered-synthetic-package")
            output = root / "notices"
            output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "downloaded hash"):
                _collect_nuget(output, lock, root)

    def test_lock_parser_rejects_conflicting_target_hashes(self) -> None:
        lock = {
            "version": 1,
            "dependencies": {
                "target-a": {
                    "Fake.Package": {
                        "resolved": "1.2.3",
                        "contentHash": "synthetic-a",
                    }
                },
                "target-b": {
                    "Fake.Package": {
                        "resolved": "1.2.3",
                        "contentHash": "synthetic-b",
                    }
                },
            },
        }
        with self.assertRaisesRegex(RuntimeError, "conflicting content hashes"):
            _nuget_bindings(lock)


if __name__ == "__main__":
    unittest.main()
