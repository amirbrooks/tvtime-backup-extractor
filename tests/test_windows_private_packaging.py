from __future__ import annotations

import ast
import hashlib
import json
import re
import unittest
from pathlib import Path

from tvtime_extractor.analyze import MAXIMUM_ANALYSIS_SUMMARY_BYTES
from tvtime_extractor.integrity import MAXIMUM_INVENTORY_BYTES
from tvtime_extractor.report import (
    _BOUND_ARTIFACTS,
    MAXIMUM_DOMAINS_BYTES,
    MAXIMUM_REPORT_ARTIFACT_BYTES,
)
from tvtime_extractor.safety import MAXIMUM_COMPLETION_MARKER_BYTES

ROOT = Path(__file__).resolve().parents[1]


class WindowsPrivatePackagingContractTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def read_windows_validator(self) -> str:
        source_root = ROOT / "windows" / "TVTimeRecovery.Windows"
        return "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(source_root.glob("RecoveryOutputValidator*.cs"))
        )

    def csharp_long_constant(self, source: str, name: str) -> int:
        match = re.search(rf"\b{name}\s*=\s*([0-9L *]+);", source)
        self.assertIsNotNone(match, name)
        value = 1
        for factor in match.group(1).split("*"):
            value *= int(factor.strip().removesuffix("L"))
        return value

    def test_windows_artifact_contract_matches_report_producer(self) -> None:
        contract = self.read("windows/TVTimeRecovery.Windows/RecoveryArtifactContract.cs")
        entries = dict(
            re.findall(
                r'\["([^"]+)"\]\s*=\s*(?:\n\s*)?"([^"]+)"',
                contract,
            )
        )
        expected = dict(_BOUND_ARTIFACTS)
        self.assertEqual(entries, expected)

        validator = self.read_windows_validator()
        harness = self.read("windows/TVTimeRecovery.Windows.CompileCheck/Program.cs")
        self.assertNotIn("RequiredArtifacts =", validator)
        self.assertNotIn("RequiredArtifacts =", harness)
        self.assertIn("RecoveryArtifactContract.RequiredArtifacts", validator)
        self.assertIn("RecoveryArtifactContract.RequiredArtifacts", harness)

    def test_windows_generated_artifact_limits_match_the_python_product_contract(self) -> None:
        contract = self.read("windows/TVTimeRecovery.Windows/RecoveryArtifactContract.cs")
        expected = {
            "MaximumStateBytes": MAXIMUM_COMPLETION_MARKER_BYTES,
            "MaximumSummaryBytes": MAXIMUM_ANALYSIS_SUMMARY_BYTES,
            "MaximumGeneratedArtifactBytes": MAXIMUM_REPORT_ARTIFACT_BYTES,
            "MaximumInventoryBytes": MAXIMUM_INVENTORY_BYTES,
            "MaximumDomainsBytes": MAXIMUM_DOMAINS_BYTES,
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                self.assertEqual(self.csharp_long_constant(contract, name), value)

        artifacts = self.read("windows/TVTimeRecovery.Windows/RecoveryOutputValidator.Artifacts.cs")
        bound_check = "expectedBytes > RecoveryArtifactContract.MaximumBytesFor(identifier)"
        self.assertIn(bound_check, artifacts)
        self.assertLess(
            artifacts.index(bound_check),
            artifacts.index("HashStream(stream, cancellationToken)"),
        )
        for identifier in (
            "extraction_run_state",
            "extraction_inventory",
            "extraction_summary",
            "analysis_summary",
            "extraction_domains",
        ):
            self.assertIn(f'"{identifier}"', contract)

    def test_msix_is_x64_self_contained_with_only_required_full_trust(self) -> None:
        project = self.read("windows/TVTimeRecovery.Windows/TVTimeRecovery.Windows.csproj")
        manifest = self.read("windows/TVTimeRecovery.Windows/Package.appxmanifest")
        self.assertIn("<Platforms>x64</Platforms>", project)
        self.assertIn("<RuntimeIdentifiers>win-x64</RuntimeIdentifiers>", project)
        self.assertIn("<WindowsAppSDKSelfContained>true", project)
        self.assertIn("<RestorePackagesWithLockFile>true", project)
        self.assertIn("<RestoreLockedMode>true", project)
        self.assertIn("<TVTimeGeneratedContentRoot", project)
        self.assertIn("$(TVTimeGeneratedContentRoot)\\Helpers", project)
        self.assertIn("<DebugType>none</DebugType>", project)
        self.assertIn("<DebugSymbols>false</DebugSymbols>", project)
        self.assertIn("<DisableXbfLineInfo>true</DisableXbfLineInfo>", project)
        self.assertIn("<PathMap>", project)
        capabilities = re.findall(r'<(?:\w+:)?Capability Name="([^"]+)"', manifest)
        self.assertEqual(capabilities, ["runFullTrust"])
        self.assertNotIn("internetClient", manifest)
        self.assertNotIn("broadFileSystemAccess", manifest)

    def test_windows_release_keeps_generated_build_content_outside_source(self) -> None:
        builder = self.read("script/build_windows_app.ps1")
        for generated_name in ("Helpers", "Assets", "Notices"):
            self.assertIn(f'Join-Path $generatedContentRoot "{generated_name}"', builder)
        for generated_name in ("obj", "bin"):
            self.assertIn(f'Join-Path $OutputRoot "{generated_name}"', builder)
        for property_name in (
            "TVTimeGeneratedContentRoot",
            "BaseIntermediateOutputPath",
            "MSBuildProjectExtensionsPath",
            "BaseOutputPath",
        ):
            self.assertIn(f"/p:{property_name}=", builder)

    def test_alpha_installers_pin_trust_helper_across_elevation(self) -> None:
        installer = self.read("script/install_windows_alpha.ps1")
        uninstaller = self.read("script/uninstall_windows_alpha.ps1")
        for source in (installer, uninstaller):
            self.assertIn("[IO.FileShare]::None", source)
            self.assertIn("ComputeHash(", source)
            self.assertIn("[IO.StreamReader]::new(", source)
        self.assertIn("-TrustHelperPin $trustHelperPin", installer)
        self.assertNotIn("ReadAllText($TrustHelper", installer)
        self.assertNotIn("ReadAllText($helperPath", uninstaller)

    def test_machine_certificate_is_retained_for_other_windows_users(self) -> None:
        trust_helper = self.read("script/windows_certificate_trust.ps1")
        installer = self.read("script/install_windows_alpha.ps1")
        uninstaller = self.read("script/uninstall_windows_alpha.ps1")
        self.assertIn("Get-AppxPackage `", trust_helper)
        self.assertIn("-AllUsers -Name $packageIdentity", trust_helper)
        self.assertIn("$_.PackageFullName -ceq $PackageFullName", trust_helper)
        self.assertIn('$_.Version -eq [Version]"0.3.1.1"', trust_helper)
        self.assertIn('[string]$_.Architecture -ceq "X64"', trust_helper)
        self.assertIn("return 11", trust_helper)
        self.assertIn("$process.ExitCode -in @(0, 11)", installer)
        self.assertIn("$process.ExitCode -eq 11", uninstaller)
        self.assertIn('-PackageFullName "$removedPackageFullName"', uninstaller)
        self.assertIn(
            "another Windows user still has the same release package installed",
            uninstaller,
        )

    def test_windows_app_sdk_nuget_dependencies_are_exactly_pinned(self) -> None:
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

        workflow = self.read(".github/workflows/ci.yml")
        native_job = workflow.split("  windows-native-compile:", 1)[1]
        native_job = native_job.split("\n  macos-app:", 1)[0]
        self.assertIn(
            "actions/setup-dotnet@d4c94342e560b34958eacfc5d055d21461ed1c5d",
            native_job,
        )
        self.assertIn('dotnet-version: "8.0.423"', native_job)
        self.assertIn("dotnet restore", native_job)
        self.assertIn("--locked-mode", native_job)
        self.assertIn("dotnet run", native_job)
        self.assertIn("--no-restore", native_job)

    def test_helper_uses_explicit_handle_list_secret_pipe_and_job_object(self) -> None:
        source = self.read("windows/TVTimeRecovery.Windows/NativeHelperProcess.cs")
        self.assertIn(
            'new[] { "SystemRoot", "WINDIR", "TEMP", "TMP" }',
            source,
        )
        for private_environment_name in (
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "OneDrive",
            "DROPBOX",
            "GOOGLE_DRIVE",
        ):
            self.assertNotIn(private_environment_name, source)
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
        self.assertIn(
            "FileReadAttributes | FileAddSubdirectory | FileTraverse",
            source,
        )
        self.assertLess(
            source.index("TerminateProcess(process, 1)"),
            source.index(
                "throw new Win32Exception();", source.index("TerminateProcess(process, 1)")
            ),
        )
        self.assertIn("job?.Dispose();\n            process?.Dispose();", source)
        self.assertIn(
            "await helper.WaitForSuccessfulExitAsync();",
            self.read("windows/TVTimeRecovery.Windows/RecoveryCoordinator.cs"),
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
        self.assertIn("create_relative_regular_file_path", private_file)
        self.assertIn("_windows_pinned_absolute_directory_handle", private_file)
        self.assertIn("exclusive=True", staging_call)
        self.assertIn("temporary=True", staging_call)
        self.assertIn("exclusive=True", capture_call)
        self.assertIn("allow_path_reopen=True", capture_call)
        windows_native = self.read("tvtime_extractor/windows_native.py")
        output_creator = windows_native.split("def create_or_replace_regular_file", 1)[1]
        output_creator = output_creator.split("def create_relative_regular_file_path", 1)[0]
        self.assertIn("FILE_OPEN_IF", output_creator)
        self.assertIn("validate_private_acl(handle)", output_creator)
        self.assertLess(
            output_creator.index("validate_private_acl(handle)"),
            output_creator.index("_truncate_regular_file(handle)"),
        )
        self.assertIn("FILE_SHARE_READ | FILE_SHARE_WRITE", output_creator)
        self.assertNotIn("FILE_SHARE_DELETE", output_creator)
        extraction = self.read("tvtime_extractor/extract.py")
        dependency_temp = extraction.split("def _anchored_dependency_temporary_directories", 1)[
            1
        ].split("def read_backup_password", 1)[0]
        self.assertIn("_windows_create_and_hold_bound_descendant_directory", dependency_temp)
        private_cleanup = extraction.split("def _remove_private_temp_tree", 1)[1].split(
            "def _dispose_dependency", 1
        )[0]
        self.assertIn("windows_delete_bound_private_tree(root)", private_cleanup)
        self.assertLess(
            private_cleanup.index("windows_delete_bound_private_tree(root)"),
            private_cleanup.index("root_metadata = root.lstat()"),
        )
        native_cleanup = windows_native.split("def delete_private_tree", 1)[1].split(
            "def _truncate_regular_file", 1
        )[0]
        self.assertIn("_open_relative_for_delete", native_cleanup)
        self.assertIn("_mark_handle_for_deletion", native_cleanup)
        self.assertNotIn("unlink(", native_cleanup)
        self.assertNotIn("rmdir(", native_cleanup)

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
        coordinator = self.read("windows/TVTimeRecovery.Windows/RecoveryCoordinator.cs")
        validator = self.read_windows_validator()
        pinned_file = self.read("windows/TVTimeRecovery.Windows/PinnedRecoveryFile.cs")
        self.assertIn("RequiredArtifacts", validator)
        self.assertIn("identifiers.SetEquals(expectedArtifacts.Keys)", validator)
        self.assertIn("RequireExactDirectoryMembers", validator)
        self.assertIn("RejectReparseTree", validator)
        self.assertIn("properties.Length != keys.Count", validator)
        self.assertIn("leases.Add(PinnedRecoveryFile.OpenDirectory(output))", validator)
        self.assertIn("leases.Add(PinnedRecoveryFile.OpenDirectory(analysis))", validator)
        self.assertGreaterEqual(validator.count("PinnedRecoveryFile.Open("), 4)
        self.assertNotIn("new FileStream(", validator)
        self.assertIn("FileFlagOpenReparsePoint", pinned_file)
        self.assertIn("PinDirectoryChain(root, parent)", pinned_file)
        self.assertIn("FileIdentity.From(visibleInformation)", pinned_file)
        self.assertIn("file.EnsureIdentity()", validator)
        self.assertIn("CanonicalInventoryRelativePath", validator)
        self.assertIn('const string escapePrefix = "./"', validator)
        self.assertNotIn("FileShareDelete", pinned_file)
        self.assertIn(
            "internal sealed class ValidatedRecoveryOutput : IDisposable",
            coordinator,
        )
        self.assertGreaterEqual(main_window.count("using var validated"), 2)
        self.assertIn("_completedOutput?.Dispose();", main_window)
        self.assertIn('"ios_encrypted_backup"', main_window)
        self.assertIn('Tag="ios_encrypted_backup"', xaml)
        self.assertIn('EncryptedIosRequest("preflight"', coordinator)
        self.assertIn('EncryptedIosRequest("recover"', coordinator)
        self.assertIn('completed.TryGetProperty("backup_receipt"', coordinator)
        self.assertIn("await recovery.SendSecretAsync(password", coordinator)

        mac_root = self.read("macos/Sources/TVTimeRecoveryApp/RecoveryRootView.swift")
        self.assertIn(".id(acquisitionKind.rawValue)", mac_root)

        self.assertNotIn('SelectedIndex="0"', xaml)
        self.assertLess(
            main_window.index("InitializeComponent();"),
            main_window.index("SourceKind.SelectedIndex = 0;"),
        )

        closing = main_window.split("private async void Window_Closing", 1)[1]
        closing = closing.split("private async void SelectBackup_Click", 1)[0]
        self.assertIn("args.Cancel = true", closing)
        self.assertIn("_cancellation?.Cancel();", closing)
        self.assertIn("await activeRecovery;", closing)
        self.assertIn("Close();", closing)
        self.assertLess(
            closing.index("_cancellation?.Cancel();"),
            closing.index("await activeRecovery;"),
        )
        self.assertLess(closing.index("await activeRecovery;"), closing.index("Close();"))
        self.assertIn("_activeRecovery = activeRecovery;", main_window)
        self.assertNotIn("Closed +=", main_window)
        self.assertIn("return await Task.Run(", coordinator)
        self.assertIn(
            "RecoveryOutputValidator.ValidateCompletedOutput(output, cancellationToken)",
            coordinator,
        )
        self.assertGreaterEqual(
            validator.count("cancellationToken.ThrowIfCancellationRequested()"),
            8,
        )
        self.assertNotIn("SHA256.HashData(stream)", validator)

    def test_native_windows_app_has_no_network_ai_or_elevation_request(self) -> None:
        source_root = ROOT / "windows/TVTimeRecovery.Windows"
        reviewed_suffixes = {".appxmanifest", ".cs", ".csproj", ".manifest", ".xaml", ".xml"}
        native_source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(source_root.rglob("*"))
            if path.is_file()
            and path.suffix.casefold() in reviewed_suffixes
            and not {"bin", "obj"}.intersection(path.relative_to(source_root).parts)
        )
        production_python_paths = [
            ROOT / "scripts/windows_helper_entry.py",
            *sorted((ROOT / "tvtime_extractor").glob("*.py")),
        ]
        helper_source = "\n".join(
            path.read_text(encoding="utf-8") for path in production_python_paths
        )
        production_source = native_source + "\n" + helper_source
        for forbidden in (
            "HttpClient",
            "WebRequest",
            "WebClient",
            "TcpClient",
            "UdpClient",
            "System.Net",
            "Sockets",
            "Microsoft.Windows.AI",
            "MachineLearning",
            "WindowsAppSDK.AI",
            "WindowsAppSDK.ML",
            "VideoScaler",
            "WebView2",
        ):
            self.assertNotIn(forbidden, production_source)

        python_imports: set[str] = set()
        for path in production_python_paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    python_imports.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    python_imports.add(node.module)
                    python_imports.update(f"{node.module}.{alias.name}" for alias in node.names)
        forbidden_python_imports = {
            "aiohttp",
            "anthropic",
            "ftplib",
            "google.genai",
            "google.generativeai",
            "grpc",
            "http.client",
            "http.server",
            "httpx",
            "imaplib",
            "keras",
            "langchain",
            "llama_cpp",
            "openai",
            "poplib",
            "requests",
            "sklearn",
            "smtplib",
            "socket",
            "telnetlib",
            "tensorflow",
            "torch",
            "transformers",
            "urllib.request",
            "websockets",
            "xmlrpc.client",
            "xmlrpc.server",
        }
        forbidden_imports_found = {
            imported
            for imported in python_imports
            for forbidden in forbidden_python_imports
            if imported == forbidden or imported.startswith(f"{forbidden}.")
        }
        self.assertFalse(forbidden_imports_found)
        self.assertNotIn("__import__", helper_source)
        self.assertNotIn("import_module", helper_source)
        for forbidden_ai_name in (
            "anthropic",
            "langchain",
            "llama_cpp",
            "openai",
            "tensorflow",
            "transformers",
        ):
            self.assertNotIn(forbidden_ai_name, helper_source.casefold())

        application_manifest = self.read("windows/TVTimeRecovery.Windows/app.manifest")
        self.assertNotIn("requireAdministrator", application_manifest)
        self.assertNotIn("highestAvailable", application_manifest)

    def test_build_and_install_scripts_remain_private_only(self) -> None:
        workflow = self.read(".github/workflows/ci.yml")
        scripts = "\n".join(
            self.read(path)
            for path in (
                "script/build_windows_helper.ps1",
                "script/build_windows_app.ps1",
                "script/windows_packaging_lib.ps1",
                "script/windows_msix_integrity.ps1",
                "script/test_windows_packaging_lib.ps1",
                "script/test_windows_msix_integrity.ps1",
                "script/windows_certificate_trust.ps1",
                "script/install_windows_private.ps1",
            )
        )
        self.assertIn("--require-hashes", scripts)
        self.assertIn("--only-binary=:all:", scripts)
        self.assertIn("AppxPackageSigningEnabled=false", scripts)
        self.assertIn("New-SelfSignedCertificate", scripts)
        self.assertIn("TrustedPeople", scripts)
        self.assertRegex(
            scripts,
            r'X509Store\(\s*"TrustedPeople",\s*"LocalMachine"\s*\)',
        )
        self.assertNotRegex(
            scripts,
            r'X509Store\(\s*"TrustedPeople",\s*"CurrentUser"\s*\)',
        )
        self.assertIn("WindowsBuiltInRole]::Administrator", scripts)
        self.assertIn("Get-AuthenticodeSignature", scripts)
        self.assertIn("$candidate.Issuer -eq $subject", scripts)
        self.assertIn("$candidate.FriendlyName -eq $friendlyName", scripts)
        self.assertIn('"1.3.6.1.5.5.7.3.3"', scripts)
        self.assertIn("Add-AppxPackage", scripts)
        self.assertIn("Get-AppxPackage", scripts)
        self.assertIn("this installer never removes app data", scripts)
        self.assertIn("scan_macos_release.py", scripts)
        self.assertIn("System.Management.Automation.Language.Parser", workflow)
        self.assertIn("Windows PowerShell 5.1 packaging script failed to parse", workflow)
        self.assertNotRegex(
            scripts,
            r"(?i)\b(?:gh\s+release|git\s+push|Invoke-WebRequest|curl|upload)\b",
        )

    def test_powershell_packaging_is_fail_closed_and_returns_only_result_paths(self) -> None:
        helper = self.read("script/build_windows_helper.ps1")
        app = self.read("script/build_windows_app.ps1")
        library = self.read("script/windows_packaging_lib.ps1")
        native_capabilities = self.read("script/WindowsPackagingNative.cs")
        file_capabilities = self.read("script/WindowsPackagingFile.cs")
        capability_paths = sorted((ROOT / "script").glob("WindowsPackaging*.cs"))
        self.assertEqual(
            [path.name for path in capability_paths],
            [
                "WindowsPackagingCapabilities.cs",
                "WindowsPackagingFile.cs",
                "WindowsPackagingNative.cs",
                "WindowsPackagingNativeOperations.cs",
                "WindowsPackagingTree.cs",
            ],
        )
        capabilities = "\n".join(path.read_text(encoding="utf-8") for path in capability_paths)
        installer = self.read("script/install_windows_private.ps1")
        certificate_trust = self.read("script/windows_certificate_trust.ps1")
        certificate_trust_hash = (
            hashlib.sha256((ROOT / "script/windows_certificate_trust.ps1").read_bytes())
            .hexdigest()
            .upper()
        )
        msix_integrity = self.read("script/windows_msix_integrity.ps1")
        collector = self.read("script/collect_windows_licenses.py")

        self.assertIn("function Assert-NativeSuccess", helper)
        for failure in (
            "hash-locked Windows helper dependencies",
            "local Windows helper source",
            "Windows helper dependency environment",
            "Windows helper builds require reviewed x64 Python",
            "PyInstaller could not build",
            "helper failed its privacy scan",
        ):
            self.assertIn(failure, helper)
        self.assertIn("struct.calcsize('P') == 8", helper)
        self.assertIn("verify_windows_python_environment.py", helper)
        self.assertGreaterEqual(helper.count("-B -I"), 8)
        self.assertGreaterEqual(helper.count("--no-compile"), 2)
        self.assertIn("build environment must be fresh", helper)
        self.assertIn("private Windows build output must be fresh", helper)
        self.assertIn(".build-tools-", app)
        self.assertIn("/p:RestorePackagesPath=$nugetRoot", app)
        self.assertIn("Remove-ContainedOrdinaryTree", app)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", library)
        self.assertIn("WindowsPackagingCapabilities.cs", library)
        self.assertIn("Get-Item -LiteralPath", library)
        self.assertIn("DirectoryCapabilities]::CreateChild", library)
        self.assertIn("DirectoryCapabilities]::Rename", library)
        self.assertIn("DirectoryCapabilities]::DeleteTree", library)
        self.assertIn("New-ContainedOrdinaryTreeSnapshot", library)
        self.assertIn("Convert-ContainedOrdinaryDirectoryToTreeSnapshot", library)
        self.assertIn("TrustedRootOwnership", library)
        self.assertIn("DestinationRootOwnership", library)
        self.assertIn("OwnershipToken.Identity", library)

        self.assertIn("function Remove-ContainedOrdinaryTrees", library)
        self.assertNotIn("New-Item -ItemType Directory", library)
        self.assertNotIn("Remove-Item -LiteralPath $tombstone -Recurse", library)
        self.assertIn("NtCreateFile", capabilities)
        self.assertIn("private const uint Win32OpenExisting = 3;", native_capabilities)
        self.assertIn("private const uint NtFileOpen = 1;", native_capabilities)
        self.assertIn("NtFileOpen,", file_capabilities)
        self.assertNotIn("OpenExisting,", file_capabilities)
        self.assertIn(
            "attributes.RootDirectory = trustedRoot.DangerousGetHandle()",
            capabilities,
        )
        self.assertIn("DangerousAddRef", capabilities)
        self.assertNotIn("GetFinalPathNameByHandle", capabilities)
        self.assertNotIn("ReOpenFile", capabilities)
        self.assertNotIn("SafeFileHandle bridge", capabilities)
        self.assertIn("owned.DetachHandle()", capabilities)
        self.assertIn("owned.RestoreHandle(root)", capabilities)
        self.assertIn("FileCreate", capabilities)
        self.assertIn("FileDirectoryFile", capabilities)
        self.assertIn("NtSetInformationFile", capabilities)
        self.assertIn("NtFileRenameInformation", capabilities)
        self.assertIn(
            "private struct FileRenameInformation",
            capabilities,
        )
        self.assertIn(
            "Marshal.SizeOf(typeof(FileRenameInformation)) +",
            capabilities,
        )
        self.assertIn(
            "encoded.Length + sizeof(char));",
            capabilities,
        )
        self.assertIn(
            "if (status < 0)",
            capabilities,
        )
        self.assertIn("FileDispositionInfo", capabilities)
        self.assertIn("FileBasicInfo", capabilities)
        self.assertIn("LockTree", capabilities)
        self.assertIn("ReadTreeManifest", capabilities)
        self.assertIn("RevalidateTree", capabilities)
        self.assertIn("RelockAfterMove", capabilities)
        self.assertIn("SHA256.Create()", capabilities)
        self.assertIn("FileAttributeReparsePoint", capabilities)
        self.assertIn("FileCapabilities", capabilities)
        self.assertIn("FileNonDirectoryFile", capabilities)
        self.assertIn("expectedIdentity", capabilities)
        self.assertIn("FileShareRead | FileShareWrite", capabilities)
        move_section = library[library.index("function Move-ContainedOrdinaryDirectory") :]
        owned_move = move_section.index(
            "$movedDestination = [TVTimeWindowsPackaging.DirectoryCapabilities]::Rename"
        )
        moved_token_update = move_section.index(
            "$OwnershipToken.Candidate = [IO.Path]::GetFullPath($movedDestination)",
            owned_move,
        )
        moved_validation = move_section.index(
            "Assert-ContainedOrdinaryDirectoryOwnership -OwnershipToken $OwnershipToken",
            moved_token_update,
        )
        self.assertLess(owned_move, moved_token_update)
        self.assertLess(moved_token_update, moved_validation)
        self.assertIn("$OwnershipToken.Snapshot.Path", move_section)
        self.assertIn("windows_packaging_lib.ps1", helper)
        self.assertIn("windows_packaging_lib.ps1", app)
        self.assertIn("windows_msix_integrity.ps1", app)
        self.assertIn(".notices-stage-", app)
        self.assertIn("Move-ContainedOrdinaryDirectory", app)
        self.assertIn("-PrimaryError $buildError", app)
        self.assertIn("-PrimaryError $bodyError", helper)
        self.assertIn("-ReturnBuildState", app)
        self.assertIn("HelperOwnership", helper)
        self.assertIn("HelperManifest", helper)
        self.assertIn("helperDestinationOwnership.Manifest -cne $helperManifest", app)
        self.assertIn("packagedHelperManifest -cne $helperManifest", app)
        self.assertIn("packagedAssetManifest -cne $assetDestinationOwnership.Manifest", app)
        self.assertIn("packagedNoticeManifest -cne $noticeDestinationOwnership.Manifest", app)
        for required in (
            "PackageIdentityPin",
            "PackageIdentity",
            "UnsignedPackageSha256",
            "UnsignedBlockMapDigest",
            "OutputRootOwnership",
            "Open-PrivateMsixIdentityPin",
            "Open-PrivateMsixStrictReadPin",
            "Get-PrivateMsixSha256",
            "Get-PrivateMsixBlockMapDigest",
        ):
            self.assertIn(required, app)
        self.assertLess(
            app.index("$helperDestinationOwnership = New-ContainedOrdinaryDirectory"),
            app.index("Copy-Item -LiteralPath $helperMember.FullName"),
        )
        self.assertIn(
            "-OwnershipTokens @($buildEnvironmentOwnership, $outputRootOwnership)",
            app,
        )
        self.assertIn("py -3.13 -B -I -m venv", helper)
        self.assertIn("$cleanupTokens += $outputRootOwnership", helper)
        self.assertIn("caller-owned empty directory", collector)
        self.assertGreaterEqual(helper.count("Assert-NativeSuccess"), 8)
        restore_done = app.index("The locked Windows dependency restore failed.")
        nuget_snapshot = app.index("$nugetRootOwnership = New-ContainedOrdinaryTreeSnapshot")
        collector_run = app.index("script\\collect_windows_licenses.py")
        nuget_revalidation = app.index(
            "Assert-ContainedOrdinaryTreeSnapshot",
            collector_run,
        )
        package_build = app.index("/p:GenerateAppxPackageOnBuild=true")
        self.assertLess(restore_done, nuget_snapshot)
        self.assertLess(nuget_snapshot, collector_run)
        self.assertLess(collector_run, nuget_revalidation)
        self.assertLess(nuget_revalidation, package_build)

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
        self.assertIn("Write-Output $helperResult", helper)
        self.assertIn("Write-Output $packageResult", app)
        self.assertIn(
            '$helperBuildState = & (Join-Path $PSScriptRoot "build_windows_helper.ps1")',
            app,
        )
        self.assertIn(
            '$buildState = & (Join-Path $PSScriptRoot "build_windows_app.ps1") -ReturnBuildState',
            installer,
        )
        self.assertIn("windows_msix_integrity.ps1", installer)
        self.assertIn("UnsignedPackageSha256", installer)
        self.assertIn("UnsignedBlockMapDigest", installer)
        self.assertIn("Signing changed the reviewed private MSIX payload", installer)
        self.assertIn("-Verb RunAs", installer)
        self.assertIn("-EncodedCommand", installer)
        self.assertIn(
            f'$expectedTrustHelperSha256 = "{certificate_trust_hash}"',
            installer,
        )
        self.assertIn("[Environment+SpecialFolder]::Windows", installer)
        self.assertIn("System32\\WindowsPowerShell\\v1.0\\powershell.exe", installer)
        self.assertNotIn("(Get-Process -Id $PID", installer)
        self.assertIn("WindowsBuiltInRole]::Administrator", certificate_trust)
        self.assertIn('"TrustedPeople",', certificate_trust)
        self.assertIn('"LocalMachine"', certificate_trust)
        self.assertNotIn("build_windows_app.ps1", certificate_trust)
        self.assertNotIn("build_windows_helper.ps1", certificate_trust)
        self.assertNotIn("Start-Process", certificate_trust)
        self.assertIn("$certificateAdded = $true", certificate_trust)
        self.assertIn("$rollbackStore.Remove($rollbackMatch)", certificate_trust)
        self.assertIn("return 21", certificate_trust)
        self.assertIn("$installationError = $_", installer)
        self.assertIn("$installationError.Exception", installer)
        self.assertIn("Machine trust may remain", installer)
        self.assertIn("$elevatedProcess.ExitCode -eq 20", installer)
        self.assertIn("throw $unresolvedTrustMessage", installer)
        first_strict = installer.index("$packageStrictPin = Open-PrivateMsixStrictReadPin")
        sign = installer.index("& $signTool.FullName sign")
        second_strict = installer.index(
            "$packageStrictPin = Open-PrivateMsixStrictReadPin",
            sign,
        )
        identity_release = installer.index("$packageIdentityPin.Dispose()", second_strict)
        signature_verify = installer.index("verify /pa /v", identity_release)
        install = installer.index("Add-AppxPackage", signature_verify)
        self.assertLess(first_strict, sign)
        self.assertLess(sign, second_strict)
        self.assertLess(second_strict, identity_release)
        self.assertLess(identity_release, signature_verify)
        self.assertLess(signature_verify, install)
        trust_add = installer.index(
            "$trustedCertificateAdded = Invoke-LocalMachineCertificateTrust"
        )
        self.assertLess(
            installer.index("build_windows_app.ps1"),
            trust_add,
        )
        self.assertLess(trust_add, installer.index("verify /pa /v"))
        self.assertLess(installer.index("verify /pa /v"), installer.index("Add-AppxPackage"))
        self.assertIn('-Operation "Remove" -Certificate $publicCertificate', installer)
        self.assertIn("$store.Remove($matches[0])", certificate_trust)
        self.assertIn("SignerCertificate.Thumbprint -ne $certificate.Thumbprint", installer)
        self.assertIn("function Resolve-PrivateMsixCapabilityPath", msix_integrity)
        self.assertIn("FileCapabilities]::OpenIdentityPin", msix_integrity)
        self.assertIn("FileCapabilities]::OpenStrictReadPin", msix_integrity)
        self.assertIn("ExpectedIdentity", msix_integrity)
        self.assertIn("AppxBlockMap.xml", msix_integrity)
        self.assertIn("[Security.Cryptography.SHA256]::Create()", msix_integrity)
        self.assertNotIn("[IO.File]::Open", msix_integrity)
        msix_test = self.read("script/test_windows_msix_integrity.ps1")
        self.assertIn("missing MSIX path was created", msix_test)
        self.assertIn("missing MSIX ancestor was created", msix_test)

    def test_windows_release_manifest_binds_runtime_and_reviewed_source(self) -> None:
        collector = self.read("script/collect_windows_licenses.py")
        guide = self.read("docs/windows.md")
        notices = self.read("windows/THIRD_PARTY_NOTICES.md")
        self.assertIn("DOTNET_RUNTIME_PACKAGE", collector)
        self.assertIn('"final_msix_inventory_complete": False', collector)
        self.assertIn('"final-msix-binary-to-component-inventory"', collector)
        self.assertIn('"source_commit_bound": source_bound', collector)
        self.assertIn('"public-experimental-alpha"', collector)
        self.assertIn("verified Git archive", notices)
        self.assertIn("self-contained runtime", notices)
        self.assertIn("public alpha", guide)

    def test_public_windows_alpha_build_is_source_bound_and_downloadable(self) -> None:
        builder = self.read("script/build_windows_release.ps1")
        installer = self.read("script/install_windows_alpha.ps1")
        uninstaller = self.read("script/uninstall_windows_alpha.ps1")
        manifest_generator = self.read("script/generate_windows_release_manifest.py")
        verifier = self.read("script/verify_windows_release.py")
        workflow = self.read(".github/workflows/windows-alpha.yml")
        for required in (
            "git_source_stage.py",
            "SourceCommit",
            "SourceTree",
            "Open-PrivateMsixStrictReadPin",
            "New-SelfSignedCertificate",
            "verify_windows_release.py",
            "scan_macos_release.py",
        ):
            self.assertIn(required, builder)
        self.assertIn('$expectedSource = Join-Path $stageRoot "source"', builder)
        self.assertIn("TVTIME_IMMUTABLE_WINDOWS_RELEASE_SOURCE", builder)
        self.assertIn("git_source_stage.py", builder)
        self.assertIn("& $stagedBuilder", builder)
        self.assertIn("--remove --repository $checkoutRoot --source $source", builder)
        self.assertIn("The Windows release checkout changed during the build", builder)
        self.assertIn('"private_key_included": False', manifest_generator)
        self.assertIn('"dependency_locks"', manifest_generator)
        self.assertIn("AcceptCertificateTrust", installer)
        self.assertIn("Assert-ExactBundleMembership", installer)
        self.assertIn("Get-AuthenticodeSignature", installer)
        self.assertIn("-DeleteKey", builder)
        self.assertIn("verify_windows_signature.ps1", verifier)
        self.assertIn("Add-AppxPackage", installer)
        self.assertIn("can delete reports", uninstaller)
        self.assertIn("Get-FileHash", uninstaller)
        self.assertIn("Publisher -cne $expectedSubject", uninstaller)
        self.assertIn("Remove-AppxPackage", uninstaller)
        self.assertIn("FORBIDDEN_MSIX_NAME_TOKENS", verifier)
        self.assertIn("ephemeral-self-signed-alpha", verifier)
        self.assertIn("Build, install, and launch Windows x64 alpha", workflow)
        self.assertIn("Upload the exact Windows tester artifacts", workflow)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", workflow)

    def test_generated_private_build_paths_are_ignored(self) -> None:
        ignore = self.read(".gitignore")
        self.assertIn("dist-windows-private/", ignore)
        self.assertIn("windows/TVTimeRecovery.Windows/Assets/", ignore)
        self.assertIn("windows/TVTimeRecovery.Windows/Helpers/", ignore)
        self.assertIn("windows/TVTimeRecovery.Windows/bin/", ignore)
        self.assertIn("windows/TVTimeRecovery.Windows/obj/", ignore)

    def test_source_manifest_includes_windows_build_and_package_inputs(self) -> None:
        manifest = self.read("MANIFEST.in")
        self.assertIn("recursive-include script *.cs *.ps1 *.py *.sh *.swift", manifest)
        self.assertIn("recursive-include windows *.appxmanifest", manifest)
        self.assertIn("*.json", manifest)
        self.assertIn("prune windows/TVTimeRecovery.Windows/obj", manifest)
        self.assertIn("prune windows/TVTimeRecovery.Windows.CompileCheck/obj", manifest)
        for required in (
            "script/WindowsPackagingCapabilities.cs",
            "script/WindowsPackagingFile.cs",
            "script/WindowsPackagingNative.cs",
            "script/WindowsPackagingNativeOperations.cs",
            "script/WindowsPackagingTree.cs",
            "script/collect_windows_licenses.py",
            "script/windows_certificate_trust.ps1",
            "script/windows_msix_integrity.ps1",
            "script/test_windows_msix_integrity.ps1",
            "windows/THIRD_PARTY_NOTICES.md",
            "windows/TVTimeRecovery.Windows/packages.lock.json",
            "windows/TVTimeRecovery.Windows.CompileCheck/GeneratedXamlStubs.cs",
        ):
            self.assertTrue((ROOT / required).is_file())

    def test_v031_alpha_versions_are_explicit_on_every_platform(self) -> None:
        self.assertIn('version = "0.3.1a1"', self.read("pyproject.toml"))
        self.assertIn('__version__ = "0.3.1a1"', self.read("tvtime_extractor/__init__.py"))
        self.assertIn(
            "<string>0.3.1</string>",
            self.read("macos/Bundle/Info.plist"),
        )
        self.assertIn(
            "<string>0.3.1</string>",
            self.read("macos/Bundle/TVTimeHelper-Info.plist"),
        )
        self.assertIn(
            "<string>0.3.1-alpha.1</string>",
            self.read("macos/Bundle/Info.plist"),
        )
        self.assertIn(
            "<string>0.3.1-alpha.1</string>",
            self.read("macos/Bundle/TVTimeHelper-Info.plist"),
        )
        self.assertIn(
            'Version="0.3.1.1"',
            self.read("windows/TVTimeRecovery.Windows/Package.appxmanifest"),
        )
        self.assertIn(
            "TV Time Backup Extractor Alpha",
            self.read("windows/TVTimeRecovery.Windows/Package.appxmanifest"),
        )
        self.assertIn(
            'PRIVATE_WINDOWS_VERSION = "0.3.1-alpha.1"',
            self.read("script/collect_windows_licenses.py"),
        )
        release_builder = self.read("script/build_release_app.sh")
        self.assertIn("release-$RELEASE_VERSION-macos", release_builder)
        self.assertIn("$RELEASE_VERSION-macOS-$package_label.dmg", release_builder)
        changelog = self.read("CHANGELOG.md")
        self.assertIn("## 0.3.1-alpha.1 - Unreleased", changelog)
        self.assertRegex(changelog, r"v0\.2\.0 remains the latest stable\s+release")
        release_record = self.read("docs/release-v0.3.1-alpha.1.md")
        self.assertIn("This prerelease is not published", release_record)
        self.assertIn("downloadable Windows x64 tester bundle", release_record)


if __name__ == "__main__":
    unittest.main()
