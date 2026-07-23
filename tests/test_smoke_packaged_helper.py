from __future__ import annotations

import io
import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from script import smoke_packaged_helper

DEVELOPER_ID_IDENTITY = "Developer ID Application: Example Organization (AB12CD34EF)"
ROOT = Path(__file__).resolve().parent.parent


def completed(
    arguments: list[str],
    *,
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(arguments, returncode, stdout, stderr)


def developer_id_details(
    *,
    flags: str = "0x10000(runtime)",
    authority: str = DEVELOPER_ID_IDENTITY,
    team_identifier: str = "AB12CD34EF",
) -> bytes:
    return (
        f"CodeDirectory flags={flags}\nAuthority={authority}\nTeamIdentifier={team_identifier}\n"
    ).encode()


def successful_codesign(arguments: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
    if "--verbose=4" in arguments:
        return completed(arguments, stderr=b"flags=0x10002(adhoc,runtime)\n")
    if "--entitlements" in arguments and "--display" in arguments:
        return completed(
            arguments,
            stdout=plistlib.dumps(smoke_packaged_helper.STANDALONE_SMOKE_ENTITLEMENTS),
        )
    return completed(arguments)


def successful_developer_id_codesign(
    arguments: list[str], **_: object
) -> subprocess.CompletedProcess[bytes]:
    if arguments[0] == "/usr/bin/lipo":
        return completed(arguments, stdout=b"arm64\n")
    if "--verbose=4" in arguments:
        return completed(
            arguments,
            stderr=developer_id_details(),
        )
    if "--entitlements" in arguments and "--display" in arguments:
        return completed(
            arguments,
            stdout=plistlib.dumps(smoke_packaged_helper.DEVELOPER_ID_STANDALONE_ENTITLEMENTS),
        )
    return completed(arguments)


class ProcessCleanupTests(unittest.TestCase):
    def test_cleanup_closes_all_pipes_after_process_has_exited(self) -> None:
        process = mock.Mock()
        process.stdin = io.BytesIO()
        process.stdout = io.BytesIO()
        process.stderr = io.BytesIO()
        process.poll.return_value = 0

        smoke_packaged_helper.terminate_process(process)

        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        process.terminate.assert_not_called()


class StandaloneHelperSignatureTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "packaged macOS helper descriptors are POSIX-only")
    def test_smoke_maps_and_restores_reserved_destination_descriptor(self) -> None:
        try:
            before = os.fstat(smoke_packaged_helper.DESTINATION_PARENT_FILE_DESCRIPTOR)
            before_identity = (int(before.st_dev), int(before.st_ino))
            before_inheritable = os.get_inheritable(
                smoke_packaged_helper.DESTINATION_PARENT_FILE_DESCRIPTOR
            )
        except OSError:
            before_identity = None
            before_inheritable = None

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            expected = parent.stat()
            with smoke_packaged_helper.mapped_destination_parent_descriptor(parent) as identity:
                self.assertEqual(
                    identity,
                    (int(expected.st_dev), int(expected.st_ino)),
                )
                mapped = os.fstat(smoke_packaged_helper.DESTINATION_PARENT_FILE_DESCRIPTOR)
                self.assertEqual(
                    (int(mapped.st_dev), int(mapped.st_ino)),
                    identity,
                )

        try:
            after = os.fstat(smoke_packaged_helper.DESTINATION_PARENT_FILE_DESCRIPTOR)
            after_identity = (int(after.st_dev), int(after.st_ino))
            after_inheritable = os.get_inheritable(
                smoke_packaged_helper.DESTINATION_PARENT_FILE_DESCRIPTOR
            )
        except OSError:
            after_identity = None
            after_inheritable = None
        self.assertEqual(after_identity, before_identity)
        self.assertEqual(after_inheritable, before_inheritable)
        self.assertEqual(smoke_packaged_helper.PROTOCOL_VERSION, 3)

    @mock.patch.object(smoke_packaged_helper.subprocess, "run", side_effect=successful_codesign)
    def test_copy_is_resigned_with_hardened_runtime_and_exact_entitlements(
        self,
        run: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_bundle = root / "source-helper.bundle"
            helper = source_bundle / "Contents" / "MacOS" / "helper"
            helper.parent.mkdir(parents=True)
            helper.write_bytes(b"synthetic executable\n")
            helper.chmod(0o755)

            copied_helper = smoke_packaged_helper.create_standalone_helper_copy(
                helper,
                root,
            )

            self.assertTrue(copied_helper.is_file())
            signing_command = run.call_args_list[0].args[0]
            self.assertEqual(signing_command[signing_command.index("--options") + 1], "runtime")
            entitlement_path = Path(signing_command[signing_command.index("--entitlements") + 1])
            self.assertEqual(
                plistlib.loads(entitlement_path.read_bytes()),
                smoke_packaged_helper.STANDALONE_SMOKE_ENTITLEMENTS,
            )
            self.assertEqual(signing_command[signing_command.index("--sign") + 1], "-")

    @mock.patch.object(smoke_packaged_helper.subprocess, "run")
    def test_verifier_rejects_a_non_hardened_signature(self, run: mock.Mock) -> None:
        run.side_effect = [
            completed([]),
            completed([], stderr=b"flags=0x2(adhoc)\n"),
        ]

        with self.assertRaisesRegex(RuntimeError, "lost hardened runtime"):
            smoke_packaged_helper.verify_standalone_helper_signature(Path("helper.bundle"))

    @mock.patch.object(smoke_packaged_helper.subprocess, "run")
    def test_verifier_rejects_a_non_ad_hoc_signature(self, run: mock.Mock) -> None:
        run.side_effect = [
            completed([]),
            completed([], stderr=b"flags=0x10000(runtime)\n"),
        ]

        with self.assertRaisesRegex(RuntimeError, "not ad-hoc signed"):
            smoke_packaged_helper.verify_standalone_helper_signature(Path("helper.bundle"))

    @mock.patch.object(smoke_packaged_helper.subprocess, "run")
    def test_verifier_rejects_any_extra_entitlement(self, run: mock.Mock) -> None:
        entitlements = {
            **smoke_packaged_helper.STANDALONE_SMOKE_ENTITLEMENTS,
            "com.apple.security.app-sandbox": True,
        }
        run.side_effect = [
            completed([]),
            completed([], stderr=b"flags=0x10002(adhoc,runtime)\n"),
            completed([], stdout=plistlib.dumps(entitlements)),
        ]

        with self.assertRaisesRegex(RuntimeError, "exact smoke entitlements"):
            smoke_packaged_helper.verify_standalone_helper_signature(Path("helper.bundle"))

    @mock.patch.object(smoke_packaged_helper.subprocess, "run")
    def test_verifier_rejects_a_missing_library_validation_exception(
        self,
        run: mock.Mock,
    ) -> None:
        run.side_effect = [
            completed([]),
            completed([], stderr=b"flags=0x10002(adhoc,runtime)\n"),
            completed([], stdout=plistlib.dumps({})),
        ]

        with self.assertRaisesRegex(RuntimeError, "exact smoke entitlements"):
            smoke_packaged_helper.verify_standalone_helper_signature(Path("helper.bundle"))


class DeveloperIDStandaloneHelperSignatureTests(unittest.TestCase):
    @mock.patch.object(
        smoke_packaged_helper.subprocess,
        "run",
        side_effect=successful_developer_id_codesign,
    )
    def test_copy_is_resigned_once_with_runtime_and_empty_entitlements(
        self,
        run: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_bundle = root / "source-helper.bundle"
            helper = source_bundle / "Contents" / "MacOS" / "helper"
            helper.parent.mkdir(parents=True)
            helper.write_bytes(b"synthetic executable\n")
            helper.chmod(0o755)
            nested_payload = source_bundle / "Contents" / "Resources" / "nested-library"
            nested_payload.parent.mkdir(parents=True)
            nested_payload.write_bytes(b"already Developer ID signed\n")

            copied_helper = smoke_packaged_helper.create_developer_id_standalone_helper_copy(
                helper,
                root,
                DEVELOPER_ID_IDENTITY,
                "arm64",
            )

            self.assertTrue(copied_helper.is_file())
            signing_commands = [
                call.args[0] for call in run.call_args_list if "--force" in call.args[0]
            ]
            self.assertEqual(len(signing_commands), 1)
            signing_command = signing_commands[0]
            self.assertEqual(
                signing_command[signing_command.index("--sign") + 1],
                DEVELOPER_ID_IDENTITY,
            )
            self.assertEqual(signing_command[signing_command.index("--options") + 1], "runtime")
            self.assertIn("--timestamp", signing_command)
            self.assertNotIn("--deep", signing_command)
            self.assertEqual(
                Path(signing_command[-1]),
                root / "developer-id-standalone-helper.bundle",
            )
            entitlement_path = Path(signing_command[signing_command.index("--entitlements") + 1])
            self.assertEqual(plistlib.loads(entitlement_path.read_bytes()), {})
            self.assertNotIn(
                b"disable-library-validation",
                entitlement_path.read_bytes(),
            )
            self.assertEqual(
                copied_helper.parent.parent / "Resources" / "nested-library",
                root
                / "developer-id-standalone-helper.bundle"
                / "Contents"
                / "Resources"
                / "nested-library",
            )
            self.assertEqual(
                (copied_helper.parent.parent / "Resources" / "nested-library").read_bytes(),
                nested_payload.read_bytes(),
            )

            verification_command = run.call_args_list[1].args[0]
            self.assertEqual(
                verification_command[1:5],
                ["--verify", "--deep", "--strict", "--verbose=2"],
            )
            architecture_command = run.call_args_list[-1].args[0]
            self.assertEqual(
                architecture_command,
                ["/usr/bin/lipo", "-archs", str(copied_helper)],
            )

    def test_release_pipeline_runs_smoke_after_signing_and_before_notarization(self) -> None:
        contents = (ROOT / "script" / "build_release_app.sh").read_text(encoding="utf-8")
        function_start = contents.index("build_release_for_architecture()")
        function_contents = contents[function_start:]
        signing_index = function_contents.index("sign_macos_app_inside_out")
        smoke_index = function_contents.index('"$ROOT_DIR/script/smoke_packaged_helper.py"')
        notarization_index = function_contents.index(
            '/usr/bin/xcrun notarytool submit "$app_notary_zip"'
        )
        self.assertLess(signing_index, smoke_index)
        self.assertLess(smoke_index, notarization_index)
        smoke_invocation = function_contents[smoke_index:notarization_index]
        self.assertIn('--developer-id-identity "$TVTIME_SIGNING_IDENTITY"', smoke_invocation)
        self.assertIn('--architecture "$architecture"', smoke_invocation)

    def test_launch_command_uses_requested_architecture(self) -> None:
        helper = Path("/synthetic/helper")
        self.assertEqual(
            smoke_packaged_helper.developer_id_launch_command(helper, "x86_64"),
            ["/usr/bin/arch", "-x86_64", str(helper)],
        )

    @mock.patch.object(smoke_packaged_helper.subprocess, "run")
    def test_verifier_rejects_failed_deep_signature(self, run: mock.Mock) -> None:
        run.return_value = completed([], returncode=1)

        with self.assertRaisesRegex(RuntimeError, "deep, strict"):
            smoke_packaged_helper.verify_developer_id_standalone_helper_signature(
                Path("helper.bundle"),
                Path("helper.bundle/Contents/MacOS/helper"),
                DEVELOPER_ID_IDENTITY,
                "arm64",
            )

    @mock.patch.object(smoke_packaged_helper.subprocess, "run")
    def test_verifier_rejects_ad_hoc_signature(self, run: mock.Mock) -> None:
        run.side_effect = [
            completed([]),
            completed(
                [],
                stderr=developer_id_details(flags="0x10002(adhoc,runtime)"),
            ),
        ]

        with self.assertRaisesRegex(RuntimeError, "unexpectedly ad-hoc"):
            smoke_packaged_helper.verify_developer_id_standalone_helper_signature(
                Path("helper.bundle"),
                Path("helper.bundle/Contents/MacOS/helper"),
                DEVELOPER_ID_IDENTITY,
                "arm64",
            )

    @mock.patch.object(smoke_packaged_helper.subprocess, "run")
    def test_verifier_rejects_missing_hardened_runtime(self, run: mock.Mock) -> None:
        run.side_effect = [
            completed([]),
            completed([], stderr=developer_id_details(flags="0x0(none)")),
        ]

        with self.assertRaisesRegex(RuntimeError, "lost hardened runtime"):
            smoke_packaged_helper.verify_developer_id_standalone_helper_signature(
                Path("helper.bundle"),
                Path("helper.bundle/Contents/MacOS/helper"),
                DEVELOPER_ID_IDENTITY,
                "arm64",
            )

    @mock.patch.object(smoke_packaged_helper.subprocess, "run")
    def test_verifier_rejects_wrong_team_identifier(self, run: mock.Mock) -> None:
        run.side_effect = [
            completed([]),
            completed(
                [],
                stderr=developer_id_details(team_identifier="ZZ99YY88XX"),
            ),
        ]

        with self.assertRaisesRegex(RuntimeError, "Team ID did not match"):
            smoke_packaged_helper.verify_developer_id_standalone_helper_signature(
                Path("helper.bundle"),
                Path("helper.bundle/Contents/MacOS/helper"),
                DEVELOPER_ID_IDENTITY,
                "arm64",
            )

    @mock.patch.object(smoke_packaged_helper.subprocess, "run")
    def test_verifier_rejects_wrong_certificate_authority(self, run: mock.Mock) -> None:
        run.side_effect = [
            completed([]),
            completed(
                [],
                stderr=developer_id_details(
                    authority="Apple Development: Example Organization (AB12CD34EF)"
                ),
            ),
        ]

        with self.assertRaisesRegex(RuntimeError, "authority did not match"):
            smoke_packaged_helper.verify_developer_id_standalone_helper_signature(
                Path("helper.bundle"),
                Path("helper.bundle/Contents/MacOS/helper"),
                DEVELOPER_ID_IDENTITY,
                "arm64",
            )

    @mock.patch.object(smoke_packaged_helper.subprocess, "run")
    def test_verifier_rejects_any_entitlement(self, run: mock.Mock) -> None:
        run.side_effect = [
            completed([]),
            completed(
                [],
                stderr=developer_id_details(),
            ),
            completed(
                [],
                stdout=plistlib.dumps({"com.apple.security.cs.disable-library-validation": True}),
            ),
        ]

        with self.assertRaisesRegex(RuntimeError, "exact empty entitlement dictionary"):
            smoke_packaged_helper.verify_developer_id_standalone_helper_signature(
                Path("helper.bundle"),
                Path("helper.bundle/Contents/MacOS/helper"),
                DEVELOPER_ID_IDENTITY,
                "arm64",
            )

    @mock.patch.object(smoke_packaged_helper.subprocess, "run")
    def test_verifier_rejects_wrong_architecture(self, run: mock.Mock) -> None:
        run.side_effect = [
            completed([]),
            completed(
                [],
                stderr=developer_id_details(),
            ),
            completed([], stdout=plistlib.dumps({})),
            completed([], stdout=b"x86_64\n"),
        ]

        with self.assertRaisesRegex(RuntimeError, "exact requested architecture"):
            smoke_packaged_helper.verify_developer_id_standalone_helper_signature(
                Path("helper.bundle"),
                Path("helper.bundle/Contents/MacOS/helper"),
                DEVELOPER_ID_IDENTITY,
                "arm64",
            )


if __name__ == "__main__":
    unittest.main()
