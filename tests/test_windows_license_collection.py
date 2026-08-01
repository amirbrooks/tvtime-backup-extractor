from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path

from script.collect_windows_licenses import (
    BUILD_ONLY_NUGET_PACKAGES,
    PRIVATE_WINDOWS_VERSION,
    REVIEWED_CPYTHON_VERSION,
    _collect_nuget,
    _nuget_bindings,
    _validate_distribution_record,
    collect,
)


class WindowsLicenseCollectionTests(unittest.TestCase):
    def test_collector_requires_a_caller_owned_empty_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = types.SimpleNamespace(output=root / "missing")
            with self.assertRaisesRegex(RuntimeError, "caller-owned empty directory"):
                collect(missing)

            occupied = root / "occupied"
            occupied.mkdir()
            (occupied / "synthetic.txt").write_text("synthetic", encoding="ascii")
            existing = types.SimpleNamespace(output=occupied)
            with self.assertRaisesRegex(RuntimeError, "caller-owned empty directory"):
                collect(existing)

    def test_environment_verifier_loads_its_sibling_under_isolated_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copyfile(
                Path(__file__).parents[1] / "script" / "verify_windows_python_environment.py",
                root / "verify_windows_python_environment.py",
            )
            (root / "collect_windows_licenses.py").write_text(
                "def verify_python_installation():\n    print('synthetic-verifier-pass')\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, "-I", str(root / "verify_windows_python_environment.py")],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "synthetic-verifier-pass")

    def test_python_record_validation_rejects_installed_module_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installed = root / "synthetic_module.py"
            installed.write_bytes(b"synthetic = True\n")
            digest = (
                base64.urlsafe_b64encode(hashlib.sha256(installed.read_bytes()).digest())
                .rstrip(b"=")
                .decode("ascii")
            )
            entry = types.SimpleNamespace(
                name=installed.name,
                parent=types.SimpleNamespace(name="synthetic"),
                hash=types.SimpleNamespace(mode="sha256", value=digest),
                size=installed.stat().st_size,
            )
            distribution = types.SimpleNamespace(
                files=(entry,),
                locate_file=lambda _entry: installed,
            )
            _validate_distribution_record(distribution)
            installed.write_bytes(b"synthetic = False\n")
            with self.assertRaisesRegex(RuntimeError, "changed after installation"):
                _validate_distribution_record(distribution)

    def test_controlled_versions_match_private_windows_build_inputs(self) -> None:
        self.assertEqual(REVIEWED_CPYTHON_VERSION, "3.13.12")
        self.assertEqual(PRIVATE_WINDOWS_VERSION, "0.3.0-alpha.1")
        self.assertEqual(
            BUILD_ONLY_NUGET_PACKAGES,
            {("Microsoft.Windows.SDK.BuildTools", "10.0.26100.4948")},
        )

    def synthetic_package(self, root: Path) -> tuple[Path, Path]:
        package_root = root / "fake.package" / "1.2.3"
        package_root.mkdir(parents=True)
        package = package_root / "fake.package.1.2.3.nupkg"
        nuspec = """<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Fake.Package</id><version>1.2.3</version>
    <license type="expression">MIT</license>
  </metadata>
</package>
"""
        expanded_asset = b"synthetic-expanded-asset"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("[Content_Types].xml", b"synthetic-content-types")
            archive.writestr("_rels/.rels", b"synthetic-package-relationships")
            archive.writestr(
                "package/services/metadata/core-properties/synthetic.psmdcp",
                b"synthetic-core-properties",
            )
            archive.writestr("fake.package.nuspec", nuspec)
            archive.writestr("lib/net8.0/synthetic.dll", expanded_asset)
        payload = package.read_bytes()
        package_hash = base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
        (package_root / "fake.package.1.2.3.nupkg.sha512").write_text(
            package_hash, encoding="ascii"
        )
        content_hash = package_hash
        (package_root / ".nupkg.metadata").write_text(
            json.dumps({"version": 2, "contentHash": content_hash, "source": "synthetic"}),
            encoding="utf-8",
        )
        (package_root / "fake.package.nuspec").write_text(nuspec, encoding="utf-8")
        expanded = package_root / "lib" / "net8.0" / "synthetic.dll"
        expanded.parent.mkdir(parents=True)
        expanded.write_bytes(expanded_asset)
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

    def test_nuget_collection_rejects_expanded_asset_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, _package = self.synthetic_package(root)
            expanded = root / "fake.package" / "1.2.3" / "lib" / "net8.0" / "synthetic.dll"
            expanded.write_bytes(b"tampered-expanded-asset")
            output = root / "notices"
            output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "expanded NuGet asset"):
                _collect_nuget(output, lock, root)

    def test_nuget_collection_rejects_missing_required_archive_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, _package = self.synthetic_package(root)
            (root / "fake.package" / "1.2.3" / "lib" / "net8.0" / "synthetic.dll").unlink()
            output = root / "notices"
            output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "required package archive member"):
                _collect_nuget(output, lock, root)

    def test_nuget_collection_rejects_unarchived_expanded_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, _package = self.synthetic_package(root)
            (root / "fake.package" / "1.2.3" / "synthetic-extra.bin").write_bytes(
                b"synthetic-unarchived-asset"
            )
            output = root / "notices"
            output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "not bound to its package archive"):
                _collect_nuget(output, lock, root)

    def test_nuget_collection_rejects_coordinated_cache_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, package = self.synthetic_package(root)
            package_root = package.parent
            nuspec = (package_root / "fake.package.nuspec").read_text(encoding="utf-8")
            replacement_asset = b"synthetic-coordinated-replacement"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("fake.package.nuspec", nuspec)
                archive.writestr("lib/net8.0/synthetic.dll", replacement_asset)
            replacement_hash = base64.b64encode(
                hashlib.sha512(package.read_bytes()).digest()
            ).decode("ascii")
            (package_root / "fake.package.1.2.3.nupkg.sha512").write_text(
                replacement_hash,
                encoding="ascii",
            )
            (package_root / "lib" / "net8.0" / "synthetic.dll").write_bytes(replacement_asset)
            output = root / "notices"
            output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "committed lock hash"):
                _collect_nuget(output, lock, root)

    def test_nuget_collection_rejects_linked_expanded_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, _package = self.synthetic_package(root)
            package_root = root / "fake.package" / "1.2.3"
            (package_root / "linked-asset").symlink_to(
                package_root / "lib" / "net8.0" / "synthetic.dll"
            )
            output = root / "notices"
            output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "linked asset"):
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
