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
from unittest import mock

from script import collect_windows_licenses as windows_licenses
from script.collect_windows_licenses import (
    BUILD_ONLY_NUGET_PACKAGES,
    DOTNET_RUNTIME_PACKAGE,
    DOTNET_SDK_VERSION,
    PRIVATE_WINDOWS_VERSION,
    REVIEWED_CPYTHON_VERSION,
    REVIEWED_NUGET_PACKAGE_SHA512,
    _candidate_scope,
    _collect_dotnet_runtime,
    _collect_nuget,
    _nuget_bindings,
    _validate_distribution_record,
    collect,
)


class WindowsLicenseCollectionTests(unittest.TestCase):
    def test_source_bound_alpha_keeps_final_binary_inventory_gap_open(self) -> None:
        scope = _candidate_scope("1" * 40, "2" * 40)
        self.assertEqual(scope["distribution_status"], "public-experimental-alpha")
        self.assertTrue(scope["source_commit_bound"])
        self.assertFalse(scope["final_msix_inventory_complete"])
        self.assertEqual(
            scope["known_release_gaps"],
            ["final-msix-binary-to-component-inventory"],
        )

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
        self.assertEqual(PRIVATE_WINDOWS_VERSION, "0.3.1-alpha.1")
        self.assertEqual(DOTNET_SDK_VERSION, "8.0.423")
        self.assertEqual(
            DOTNET_RUNTIME_PACKAGE[:2],
            (
                "Microsoft.NETCore.App.Runtime.win-x64",
                "8.0.29",
            ),
        )
        self.assertEqual(
            BUILD_ONLY_NUGET_PACKAGES,
            {("Microsoft.Windows.SDK.BuildTools", "10.0.26100.4948")},
        )
        expected_nuget_packages = {
            ("Microsoft.Web.WebView2", "1.0.3719.77"),
            ("Microsoft.Windows.SDK.BuildTools", "10.0.26100.4948"),
            ("Microsoft.Windows.SDK.BuildTools.MSIX", "1.7.251221100"),
            ("Microsoft.WindowsAppSDK.Base", "2.0.4"),
            ("Microsoft.WindowsAppSDK.Foundation", "2.1.0"),
            ("Microsoft.WindowsAppSDK.InteractiveExperiences", "2.0.15"),
            ("Microsoft.WindowsAppSDK.Runtime", "2.2.0"),
            ("Microsoft.WindowsAppSDK.WinUI", "2.2.1"),
        }
        self.assertEqual(set(REVIEWED_NUGET_PACKAGE_SHA512), expected_nuget_packages)
        lock = json.loads(
            (
                Path(__file__).parents[1]
                / "windows"
                / "TVTimeRecovery.Windows"
                / "packages.lock.json"
            ).read_text(encoding="utf-8")
        )
        locked_nuget_packages = {
            (name, binding["resolved"])
            for target in lock["dependencies"].values()
            for name, binding in target.items()
        }
        self.assertEqual(locked_nuget_packages, expected_nuget_packages)

    def synthetic_package(self, root: Path) -> tuple[Path, Path, dict[tuple[str, str], str]]:
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
        content_hash = base64.b64encode(
            hashlib.sha512(b"synthetic-nuget-content-hash").digest()
        ).decode("ascii")
        (package_root / ".nupkg.metadata").write_text(
            json.dumps({"version": 2, "contentHash": content_hash, "source": "synthetic"}),
            encoding="utf-8",
        )
        (package_root / "fake.package.nuspec").write_bytes(nuspec.encode("utf-8"))
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
        return lock, package, {("Fake.Package", "1.2.3"): package_hash}

    def test_nuget_collection_binds_package_hash_metadata_and_license(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, _package, reviewed_hashes = self.synthetic_package(root)
            output = root / "notices"
            output.mkdir()
            components = _collect_nuget(output, lock, root, reviewed_hashes)
            self.assertEqual(len(components), 1)
            self.assertEqual(components[0]["name"], "Fake.Package")
            self.assertNotEqual(
                components[0]["content_hash"],
                components[0]["package_sha512"],
            )
            license_path = output / "nuget" / "Fake.Package" / "license-expression.txt"
            self.assertEqual(license_path.read_text(encoding="utf-8"), "MIT\n")

    def test_nuget_collection_rejects_package_byte_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, package, reviewed_hashes = self.synthetic_package(root)
            package.write_bytes(b"tampered-synthetic-package")
            output = root / "notices"
            output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "downloaded hash"):
                _collect_nuget(output, lock, root, reviewed_hashes)

    def test_nuget_collection_rejects_expanded_asset_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, _package, reviewed_hashes = self.synthetic_package(root)
            expanded = root / "fake.package" / "1.2.3" / "lib" / "net8.0" / "synthetic.dll"
            expanded.write_bytes(b"tampered-expanded-asset")
            output = root / "notices"
            output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "expanded NuGet asset"):
                _collect_nuget(output, lock, root, reviewed_hashes)

    def test_nuget_collection_rejects_missing_required_archive_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, _package, reviewed_hashes = self.synthetic_package(root)
            (root / "fake.package" / "1.2.3" / "lib" / "net8.0" / "synthetic.dll").unlink()
            output = root / "notices"
            output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "required package archive member"):
                _collect_nuget(output, lock, root, reviewed_hashes)

    def test_nuget_collection_rejects_unarchived_expanded_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, _package, reviewed_hashes = self.synthetic_package(root)
            (root / "fake.package" / "1.2.3" / "synthetic-extra.bin").write_bytes(
                b"synthetic-unarchived-asset"
            )
            output = root / "notices"
            output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "not bound to its package archive"):
                _collect_nuget(output, lock, root, reviewed_hashes)

    def test_nuget_collection_rejects_coordinated_cache_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, package, reviewed_hashes = self.synthetic_package(root)
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
            with self.assertRaisesRegex(RuntimeError, "reviewed package hash"):
                _collect_nuget(output, lock, root, reviewed_hashes)

    def test_nuget_collection_rejects_linked_expanded_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, _package, reviewed_hashes = self.synthetic_package(root)
            package_root = root / "fake.package" / "1.2.3"
            (package_root / "linked-asset").symlink_to(
                package_root / "lib" / "net8.0" / "synthetic.dll"
            )
            output = root / "notices"
            output.mkdir()
            with self.assertRaisesRegex(RuntimeError, "linked asset"):
                _collect_nuget(output, lock, root, reviewed_hashes)

    def test_dotnet_runtime_collection_binds_exact_package_notices(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            name = "Microsoft.NETCore.App.Runtime.win-x64"
            version = "8.0.29"
            package_root = root / name.casefold() / version
            package_root.mkdir(parents=True)
            package = package_root / f"{name.casefold()}.{version}.nupkg"
            nuspec = f"""<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{name}</id><version>{version}</version>
    <license type="expression">MIT</license>
  </metadata>
</package>
"""
            runtime_asset = b"synthetic-dotnet-runtime"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("[Content_Types].xml", b"synthetic-content-types")
                archive.writestr(f"{name}.nuspec", nuspec)
                archive.writestr("LICENSE.TXT", b"Synthetic runtime license\n")
                archive.writestr(
                    "THIRD-PARTY-NOTICES.TXT",
                    b"Synthetic runtime notices\n",
                )
                archive.writestr("runtimes/win-x64/lib/net8.0/synthetic.dll", runtime_asset)
            package_hash = base64.b64encode(hashlib.sha512(package.read_bytes()).digest()).decode(
                "ascii"
            )
            content_hash = base64.b64encode(
                hashlib.sha512(b"synthetic-dotnet-content-hash").digest()
            ).decode("ascii")
            (package_root / f"{name.casefold()}.{version}.nupkg.sha512").write_text(
                package_hash,
                encoding="ascii",
            )
            (package_root / ".nupkg.metadata").write_text(
                json.dumps({"version": 2, "contentHash": content_hash}),
                encoding="utf-8",
            )
            (package_root / f"{name}.nuspec").write_bytes(nuspec.encode("utf-8"))
            (package_root / "LICENSE.TXT").write_bytes(b"Synthetic runtime license\n")
            (package_root / "THIRD-PARTY-NOTICES.TXT").write_bytes(b"Synthetic runtime notices\n")
            expanded = package_root / "runtimes" / "win-x64" / "lib" / "net8.0"
            expanded.mkdir(parents=True)
            (expanded / "synthetic.dll").write_bytes(runtime_asset)
            output = root / "notices"
            output.mkdir()
            with mock.patch.object(
                windows_licenses,
                "DOTNET_RUNTIME_PACKAGE",
                (name, version, content_hash, package_hash),
            ):
                component = _collect_dotnet_runtime(output, root)
            self.assertEqual(component["ecosystem"], "dotnet-runtime")
            self.assertEqual(component["sdk_version"], "8.0.423")
            self.assertEqual(component["content_hash"], content_hash)
            self.assertEqual(component["package_sha512"], package_hash)
            self.assertEqual(
                (output / "dotnet" / "runtime-license-expression.txt").read_text(encoding="utf-8"),
                "MIT\n",
            )
            self.assertEqual(
                (output / "dotnet" / "LICENSE.txt").read_text(encoding="ascii"),
                "Synthetic runtime license\n",
            )
            self.assertEqual(
                (output / "dotnet" / "ThirdPartyNotices.txt").read_text(encoding="ascii"),
                "Synthetic runtime notices\n",
            )

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
