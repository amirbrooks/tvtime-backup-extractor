from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class WindowsPrivatePackagingContractTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_msix_is_x64_self_contained_with_only_required_full_trust(self) -> None:
        project = self.read("windows/TVTimeRecovery.Windows/TVTimeRecovery.Windows.csproj")
        manifest = self.read("windows/TVTimeRecovery.Windows/Package.appxmanifest")
        self.assertIn("<Platforms>x64</Platforms>", project)
        self.assertIn("<RuntimeIdentifiers>win-x64</RuntimeIdentifiers>", project)
        self.assertIn("<WindowsAppSDKSelfContained>true", project)
        self.assertIn("<RestorePackagesWithLockFile>true", project)
        self.assertIn("<RestoreLockedMode>true", project)
        self.assertIn("<DebugType>none</DebugType>", project)
        self.assertIn("<DebugSymbols>false</DebugSymbols>", project)
        self.assertIn("<DisableXbfLineInfo>true</DisableXbfLineInfo>", project)
        self.assertIn("<PathMap>", project)
        capabilities = re.findall(r'<(?:\w+:)?Capability Name="([^"]+)"', manifest)
        self.assertEqual(capabilities, ["runFullTrust"])
        self.assertNotIn("internetClient", manifest)
        self.assertNotIn("broadFileSystemAccess", manifest)

    def test_windows_sdk_dependencies_are_exactly_pinned(self) -> None:
        project = self.read("windows/TVTimeRecovery.Windows/TVTimeRecovery.Windows.csproj")
        references = re.findall(r'<PackageReference Include="([^"]+)" Version="([^"]+)"', project)
        self.assertEqual(
            references,
            [
                ("Microsoft.WindowsAppSDK", "[2.2.0]"),
                ("Microsoft.Windows.SDK.BuildTools", "[10.0.26100.4948]"),
            ],
        )
        for _, version in references:
            self.assertRegex(version, r"^\[\d+\.\d+\.\d+(?:\.\d+)?\]$")

        lock = json.loads(self.read("windows/TVTimeRecovery.Windows/packages.lock.json"))
        dependencies = lock["dependencies"]
        self.assertEqual(
            set(dependencies),
            {"net8.0-windows10.0.26100", "net8.0-windows10.0.26100/win-x64"},
        )
        direct = dependencies["net8.0-windows10.0.26100"]
        self.assertEqual(direct["Microsoft.WindowsAppSDK"]["resolved"], "2.2.0")
        self.assertEqual(
            direct["Microsoft.Windows.SDK.BuildTools"]["resolved"],
            "10.0.26100.4948",
        )
        for target in dependencies.values():
            for binding in target.values():
                self.assertRegex(binding["resolved"], r"^\d+\.\d+\.\d+(?:\.\d+)?$")
                self.assertGreaterEqual(len(binding["contentHash"]), 44)
                if binding["type"] == "Direct":
                    resolved = binding["resolved"]
                    self.assertEqual(binding["requested"], f"[{resolved}, {resolved}]")

    def test_cross_host_compile_check_uses_real_locked_windows_references(self) -> None:
        project = self.read(
            "windows/TVTimeRecovery.Windows.CompileCheck/TVTimeRecovery.Windows.CompileCheck.csproj"
        )
        self.assertIn("../TVTimeRecovery.Windows/*.cs", project)
        self.assertIn("../TVTimeRecovery.Windows/packages.lock.json", project)
        self.assertIn("<RestoreLockedMode>true", project)
        self.assertIn("<OutputType>Exe</OutputType>", project)
        self.assertIn('<Compile Include="Program.cs" />', project)
        self.assertIn("<WindowsAppSdkAutoInitialize>false", project)
        self.assertNotIn("<UseWinUI>true", project)

        harness = self.read("windows/TVTimeRecovery.Windows.CompileCheck/Program.cs")
        self.assertIn("ValidateCompletedOutput", harness)
        self.assertIn("7 tamper cases rejected", harness)

    def test_helper_uses_explicit_handle_list_secret_pipe_and_job_object(self) -> None:
        source = self.read("windows/TVTimeRecovery.Windows/NativeHelperProcess.cs")
        for required in (
            "ProcThreadAttributeHandleList",
            "UpdateProcThreadAttribute",
            "TVTIME_SECRET_HANDLE",
            "TVTIME_DESTINATION_HANDLE",
            "CreateSuspended",
            "AssignProcessToJobObject",
            "TerminateProcess",
            "JobObjectLimitKillOnJobClose",
            'CreateFileW("NUL"',
        ):
            self.assertIn(required, source)
        self.assertNotIn("RedirectStandardError", source)
        self.assertLess(
            source.index("TerminateProcess(process, 1)"),
            source.index(
                "throw new Win32Exception();", source.index("TerminateProcess(process, 1)")
            ),
        )
        self.assertIn("job?.Dispose();\n            process?.Dispose();", source)
        self.assertIn(
            "await helper.WaitForSuccessfulExitAsync();",
            self.read("windows/TVTimeRecovery.Windows/RecoverySupport.cs"),
        )
        self.assertLess(
            source.index("WaitForSingleObject(_process, 5_000)", source.index("DisposeAsync")),
            source.index("_job.Dispose();", source.index("DisposeAsync")),
        )
        cleanup = source.split("finally", 1)[1]
        self.assertLess(
            cleanup.index("TerminateProcess(process, 1)"),
            cleanup.index("job?.Dispose()"),
        )

        safety = self.read("tvtime_extractor/safety.py")
        private_file = safety.split("def _windows_create_private_file_descriptor", 1)[1]
        private_file = private_file.split("def windows_create_private_staging_descriptor", 1)[0]
        staging_call = safety.split("def windows_create_private_staging_descriptor", 1)[1]
        staging_call, capture_call = staging_call.split(
            "def windows_create_private_capture_descriptor", 1
        )
        capture_call = capture_call.split("def _windows_rename_handle_no_replace", 1)[0]
        self.assertIn("_WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE", private_file)
        self.assertNotIn("_WINDOWS_FILE_SHARE_DELETE", private_file)
        self.assertIn("_WINDOWS_DELETE", staging_call)
        self.assertNotIn("_WINDOWS_DELETE", capture_call)

    def test_native_ui_does_not_persist_source_access_or_swallow_fatal_errors(self) -> None:
        main_window = self.read("windows/TVTimeRecovery.Windows/MainWindow.xaml.cs")
        xaml = self.read("windows/TVTimeRecovery.Windows/MainWindow.xaml")
        application = self.read("windows/TVTimeRecovery.Windows/App.xaml.cs")
        self.assertNotIn("FutureAccessList", main_window)
        self.assertNotIn("StorageApplicationPermissions", main_window)
        self.assertIn("args.Handled = false", application)
        self.assertIn("LaunchPrivateFileAsync", main_window)
        self.assertGreaterEqual(main_window.count("ValidateCompletedOutput"), 2)
        self.assertIn("LaunchFolderAsync", main_window)
        self.assertIn("browser or viewer history", xaml)
        self.assertIn("Windows Recent Items", xaml)
        support = self.read("windows/TVTimeRecovery.Windows/RecoverySupport.cs")
        self.assertIn("RequiredArtifacts", support)
        self.assertIn("identifiers.SetEquals(expectedArtifacts.Keys)", support)
        self.assertIn("RequireExactDirectoryMembers", support)
        self.assertIn("RejectReparseTree", support)
        self.assertIn("properties.Length != keys.Count", support)
        self.assertIn("leases.Add(OpenPinnedDirectory(output))", support)
        self.assertIn("leases.Add(OpenPinnedDirectory(analysis))", support)
        self.assertIn("FileShare.Read", support)
        self.assertIn("internal sealed class ValidatedRecoveryOutput : IDisposable", support)
        self.assertGreaterEqual(main_window.count("using var validated"), 2)
        self.assertIn("_completedOutput?.Dispose();", main_window)
        self.assertIn('"ios_encrypted_backup"', main_window)
        self.assertIn('Tag="ios_encrypted_backup"', xaml)
        self.assertIn('EncryptedIosRequest("preflight"', support)
        self.assertIn('EncryptedIosRequest("recover"', support)
        self.assertIn('completed.TryGetProperty("backup_receipt"', support)
        self.assertIn("await recovery.SendSecretAsync(password", support)

        mac_root = self.read("macos/Sources/TVTimeRecoveryApp/RecoveryRootView.swift")
        self.assertIn(".id(acquisitionKind.rawValue)", mac_root)

        self.assertNotIn('SelectedIndex="0"', xaml)
        self.assertLess(
            main_window.index("InitializeComponent();"),
            main_window.index("SourceKind.SelectedIndex = 0;"),
        )

    def test_native_windows_app_has_no_network_client_or_elevation_request(self) -> None:
        source_root = ROOT / "windows/TVTimeRecovery.Windows"
        production_source = "\n".join(
            path.read_text(encoding="utf-8") for path in sorted(source_root.glob("*.cs"))
        )
        for forbidden in (
            "HttpClient",
            "WebRequest",
            "WebClient",
            "TcpClient",
            "UdpClient",
            "System.Net",
            "Sockets",
        ):
            self.assertNotIn(forbidden, production_source)

        application_manifest = self.read("windows/TVTimeRecovery.Windows/app.manifest")
        self.assertNotIn("requireAdministrator", application_manifest)
        self.assertNotIn("highestAvailable", application_manifest)

    def test_build_and_install_scripts_remain_private_only(self) -> None:
        scripts = "\n".join(
            self.read(path)
            for path in (
                "script/build_windows_helper.ps1",
                "script/build_windows_app.ps1",
                "script/install_windows_private.ps1",
            )
        )
        self.assertIn("--require-hashes", scripts)
        self.assertIn("--only-binary=:all:", scripts)
        self.assertIn("AppxPackageSigningEnabled=false", scripts)
        self.assertIn("New-SelfSignedCertificate", scripts)
        self.assertIn("TrustedPeople", scripts)
        self.assertIn("Get-AuthenticodeSignature", scripts)
        self.assertIn("Add-AppxPackage", scripts)
        self.assertIn("Get-AppxPackage", scripts)
        self.assertIn("this installer never removes app data", scripts)
        self.assertIn("scan_macos_release.py", scripts)
        self.assertNotRegex(
            scripts,
            r"(?i)\b(?:gh\s+release|git\s+push|Invoke-WebRequest|curl|upload)\b",
        )

    def test_powershell_packaging_is_fail_closed_and_returns_only_result_paths(self) -> None:
        helper = self.read("script/build_windows_helper.ps1")
        app = self.read("script/build_windows_app.ps1")
        installer = self.read("script/install_windows_private.ps1")

        self.assertIn("function Assert-NativeSuccess", helper)
        for failure in (
            "hash-locked Windows helper dependencies",
            "local Windows helper source",
            "Windows helper dependency environment",
            "PyInstaller could not build",
            "helper failed its privacy scan",
        ):
            self.assertIn(failure, helper)
        self.assertGreaterEqual(helper.count("Assert-NativeSuccess"), 8)

        # Operational native output must go to the host. The final Write-Output in
        # each child script is then the only pipeline value captured by its caller.
        self.assertGreaterEqual(helper.count("| Out-Host"), 7)
        self.assertGreaterEqual(app.count("| Out-Host"), 4)
        self.assertIn(
            '$appxPackageDirectoryArgument = "/p:AppxPackageDir=$msixOutputDirectory"',
            app,
        )
        self.assertIn("$appxPackageDirectoryArgument | Out-Host", app)
        self.assertNotIn("/p:AppxPackageDir=($OutputRoot", app)
        self.assertRegex(helper, r"Write-Output \$final\s*$")
        self.assertRegex(app, r"Write-Output \$packages\[0\]\.FullName\s*$")
        self.assertIn('$helperRoot = & (Join-Path $PSScriptRoot "build_windows_helper.ps1")', app)
        self.assertIn('$Package = & (Join-Path $PSScriptRoot "build_windows_app.ps1")', installer)
        self.assertLess(installer.index("$trustedStore.Add"), installer.index("verify /pa /v"))
        self.assertLess(installer.index("verify /pa /v"), installer.index("Add-AppxPackage"))
        self.assertIn("$trustedStore.Remove($publicCertificate)", installer)
        self.assertIn("SignerCertificate.Thumbprint -ne $certificate.Thumbprint", installer)

    def test_generated_private_build_paths_are_ignored(self) -> None:
        ignore = self.read(".gitignore")
        self.assertIn("dist-windows-private/", ignore)
        self.assertIn("windows/TVTimeRecovery.Windows/Assets/", ignore)
        self.assertIn("windows/TVTimeRecovery.Windows/Helpers/", ignore)
        self.assertIn("windows/TVTimeRecovery.Windows/bin/", ignore)
        self.assertIn("windows/TVTimeRecovery.Windows/obj/", ignore)

    def test_source_manifest_includes_windows_build_and_package_inputs(self) -> None:
        manifest = self.read("MANIFEST.in")
        self.assertIn("recursive-include script *.ps1", manifest)
        self.assertIn("recursive-include windows *.appxmanifest", manifest)
        self.assertIn("*.json", manifest)
        self.assertIn("prune windows/TVTimeRecovery.Windows/obj", manifest)
        self.assertIn("prune windows/TVTimeRecovery.Windows.CompileCheck/obj", manifest)
        for required in (
            "script/collect_windows_licenses.py",
            "windows/THIRD_PARTY_NOTICES.md",
            "windows/TVTimeRecovery.Windows/packages.lock.json",
            "windows/TVTimeRecovery.Windows.CompileCheck/GeneratedXamlStubs.cs",
        ):
            self.assertTrue((ROOT / required).is_file())

    def test_private_candidate_version_cannot_masquerade_as_published_v020(self) -> None:
        self.assertIn('version = "0.3.0"', self.read("pyproject.toml"))
        self.assertIn('__version__ = "0.3.0"', self.read("tvtime_extractor/__init__.py"))
        self.assertIn(
            "<string>0.3.0</string>",
            self.read("macos/Bundle/Info.plist"),
        )
        self.assertIn(
            "<string>0.3.0</string>",
            self.read("macos/Bundle/TVTimeHelper-Info.plist"),
        )
        self.assertIn(
            'Version="0.3.0.0"',
            self.read("windows/TVTimeRecovery.Windows/Package.appxmanifest"),
        )
        changelog = self.read("CHANGELOG.md")
        self.assertIn("Unreleased private cross-platform candidate", changelog)
        self.assertIn("not been tagged, uploaded, published", changelog)


if __name__ == "__main__":
    unittest.main()
