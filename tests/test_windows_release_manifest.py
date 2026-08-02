from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from script.generate_windows_release_manifest import generate
from script.verify_windows_release import verify

SOURCE_COMMIT = "1" * 40
SOURCE_TREE = "2" * 40
THUMBPRINT = "A" * 40


class WindowsReleaseManifestTests(unittest.TestCase):
    def test_manifest_generator_runs_with_isolated_python(self) -> None:
        script = Path(__file__).resolve().parents[1] / "script/generate_windows_release_manifest.py"
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [sys.executable, "-I", str(script), "--help"],
                cwd=temporary,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def write_msix(self, path: Path, extra_name: str | None = None) -> None:
        manifest = """<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
 xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
 IgnorableNamespaces="rescap">
 <Identity Name="AmirBrooks.TVTimeBackupExtractor.Alpha"
  Publisher="CN=TV Time Backup Extractor Alpha" Version="0.3.1.1" />
 <Capabilities><rescap:Capability Name="runFullTrust" /></Capabilities>
</Package>
"""
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AppxManifest.xml", manifest)
            archive.writestr("AppxBlockMap.xml", "<BlockMap />")
            archive.writestr("AppxSignature.p7x", b"synthetic-signature")
            archive.writestr("TVTimeRecovery.Windows.exe", b"synthetic-executable")
            if extra_name:
                archive.writestr(extra_name, b"synthetic-forbidden-payload")

    def create_bundle(self, root: Path, extra_msix_name: str | None = None) -> tuple[Path, Path]:
        source_root = root / "source"
        for relative in (
            "global.json",
            "requirements-windows-build.lock",
            "windows/TVTimeRecovery.Windows/packages.lock.json",
        ):
            lock = source_root / relative
            lock.parent.mkdir(parents=True, exist_ok=True)
            lock.write_text(f"synthetic-{relative}\n", encoding="utf-8")
        files = {
            "package": root / "TV-Time-Backup-Extractor-0.3.1-alpha.1-Windows-x64.msix",
            "certificate": root / "TV-Time-Backup-Extractor-0.3.1-alpha.1-Windows-x64.cer",
            "installer": root / "Install-Windows-Alpha.ps1",
            "uninstaller": root / "Uninstall-Windows-Alpha.ps1",
            "trust_helper": root / "Windows-Certificate-Trust.ps1",
            "readme": root / "README.txt",
            "license": root / "LICENSE.txt",
            "third_party_notices": root / "THIRD-PARTY-NOTICES.txt",
        }
        self.write_msix(files["package"], extra_msix_name)
        for label, path in files.items():
            if label != "package":
                path.write_bytes(f"synthetic-{label}\n".encode("ascii"))
        manifest = root / "windows-release-manifest.json"
        generate(
            argparse.Namespace(
                release_version="0.3.1-alpha.1",
                source_commit=SOURCE_COMMIT,
                source_tree=SOURCE_TREE,
                package_identity="AmirBrooks.TVTimeBackupExtractor.Alpha",
                certificate_thumbprint=THUMBPRINT,
                unsigned_package_sha256="3" * 64,
                block_map_sha256="4" * 64,
                python_version="3.13.12",
                dotnet_sdk_version="8.0.423",
                source_root=source_root,
                output=manifest,
                **files,
            )
        )
        bundle = root / "windows-alpha.zip"
        with zipfile.ZipFile(bundle, "w") as archive:
            for path in sorted(root.iterdir(), key=lambda candidate: candidate.name):
                if path != bundle and path.is_file():
                    archive.write(path, path.name)
        return bundle, source_root

    def verify_bundle(self, bundle: Path, source_root: Path) -> None:
        verify(
            argparse.Namespace(
                bundle=bundle,
                release_version="0.3.1-alpha.1",
                source_commit=SOURCE_COMMIT,
                source_tree=SOURCE_TREE,
                structural_only=True,
                source_root=source_root,
            )
        )

    def test_generated_bundle_is_exact_source_bound_and_private_key_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, source_root = self.create_bundle(Path(temporary))
            self.verify_bundle(bundle, source_root)
            with zipfile.ZipFile(bundle) as archive:
                manifest = json.loads(archive.read("windows-release-manifest.json"))
            self.assertEqual(manifest["source"]["git_commit"], SOURCE_COMMIT)
            self.assertFalse(manifest["signing"]["private_key_included"])
            self.assertEqual(
                [record["path"] for record in manifest["dependency_locks"]],
                [
                    "global.json",
                    "requirements-windows-build.lock",
                    "windows/TVTimeRecovery.Windows/packages.lock.json",
                ],
            )

    def test_bundle_rejects_dependency_lock_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, source_root = self.create_bundle(Path(temporary))
            (source_root / "requirements-windows-build.lock").write_text(
                "tampered-synthetic-lock\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "dependency locks"):
                self.verify_bundle(bundle, source_root)

    def test_bundle_rejects_unexpected_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, source_root = self.create_bundle(Path(temporary))
            with zipfile.ZipFile(bundle, "a") as archive:
                archive.writestr("unexpected.txt", "synthetic")
            with self.assertRaisesRegex(RuntimeError, "unexpected files"):
                self.verify_bundle(bundle, source_root)

    def test_msix_rejects_ai_or_webview_payload_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, source_root = self.create_bundle(Path(temporary), "Microsoft.WebView2.Core.dll")
            with self.assertRaisesRegex(RuntimeError, "AI or WebView"):
                self.verify_bundle(bundle, source_root)

    def test_msix_allows_required_ai_or_webview_license_notice_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, source_root = self.create_bundle(
                Path(temporary),
                "Notices/nuget/Microsoft.Web.WebView2/license-expression.txt",
            )
            self.verify_bundle(bundle, source_root)

    def test_default_verification_requires_windows_cryptographic_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, source_root = self.create_bundle(Path(temporary))
            arguments = argparse.Namespace(
                bundle=bundle,
                release_version="0.3.1-alpha.1",
                source_commit=SOURCE_COMMIT,
                source_tree=SOURCE_TREE,
                source_root=source_root,
            )
            with (
                mock.patch("script.verify_windows_release.sys.platform", "darwin"),
                self.assertRaisesRegex(RuntimeError, "requires Windows"),
            ):
                verify(arguments)


if __name__ == "__main__":
    unittest.main()
