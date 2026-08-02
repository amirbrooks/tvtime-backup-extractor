from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from tvtime_extractor.android_device import (
    AndroidDeviceState,
    AndroidLegacyBackupState,
    AndroidPackageState,
    _bounded_execute,
    _CommandResult,
    _package_backup_allowed,
    capture_legacy_android_backup,
    privacy_safe_probe_payload,
    probe_android_device,
)
from tvtime_extractor.errors import TVTimeError, UserInputError
from tvtime_extractor.safety import require_private_path


class _SyntheticADB:
    def __init__(self, responses: dict[tuple[str, ...], _CommandResult]) -> None:
        self.responses = responses

    def __call__(self, arguments: list[str], _timeout: float) -> _CommandResult:
        command = tuple(arguments[1:])
        return self.responses.get(command, _CommandResult(1, b"", b"synthetic failure"))


def _response(returncode: int = 0, stdout: bytes = b"") -> _CommandResult:
    return _CommandResult(returncode, stdout, b"")


class AndroidCapabilityProbeTests(unittest.TestCase):
    def test_backup_flag_parser_handles_android_property_spellings(self) -> None:
        for spelling in ("allowBackup", "allow_backup"):
            for separator in ("=", " : "):
                with self.subTest(spelling=spelling, separator=separator, value="true"):
                    self.assertIs(
                        _package_backup_allowed(f"targetSdk=30 {spelling}{separator}true"),
                        True,
                    )
                with self.subTest(spelling=spelling, separator=separator, value="false"):
                    self.assertIs(
                        _package_backup_allowed(f"targetSdk=30 {spelling}{separator}false"),
                        False,
                    )

        for flag_list in (
            "flags=[ HAS_CODE ALLOW_BACKUP ]",
            "flags=[HAS_CODE,ALLOW_BACKUP]",
            "pkgFlags=[ HAS_CODE ALLOW_BACKUP ]",
        ):
            with self.subTest(flag_list=flag_list):
                self.assertIs(_package_backup_allowed(flag_list), True)

        for malformed in (
            "targetSdk=30",
            "not_allow_backup=true",
            "allow_backup=trueish",
            "allow_backup=falseish",
            "flags=[ HAS_CODE NOT_ALLOW_BACKUP ]",
            "flags=[ HAS_CODE ALLOW_BACKUP_EXTRA ]",
            "flags=[ HAS_CODE ALLOW_BACKUP=trueish ]",
            "privatePkgFlags=[ HAS_CODE ALLOW_BACKUP ]",
        ):
            with self.subTest(malformed=malformed):
                self.assertIsNone(_package_backup_allowed(malformed))

        self.assertIs(
            _package_backup_allowed("allowBackup=true backupDisabled=true"),
            False,
        )

    def test_command_output_is_killed_at_the_privacy_bound(self) -> None:
        with self.assertRaisesRegex(Exception, "oversized diagnostic response"):
            _bounded_execute(
                [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 1100000)"],
                10.0,
            )

    @unittest.skipIf(os.name == "nt", "POSIX stdout-descriptor capture")
    def test_capture_stdout_is_written_only_to_the_held_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "synthetic-capture.ab"
            descriptor = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                result = _bounded_execute(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.stdout.buffer.write(b'synthetic-capture')",
                    ],
                    10.0,
                    monitored_descriptor=descriptor,
                    stdout_descriptor=descriptor,
                )
                self.assertEqual(result.stdout, b"")
                self.assertEqual(os.pread(descriptor, 64, 0), b"synthetic-capture")
            finally:
                os.close(descriptor)

    def test_modern_release_app_is_present_but_not_a_legacy_backup_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            adb = Path(temporary) / "synthetic-adb"
            executor = _SyntheticADB(
                {
                    ("version",): _response(stdout=b"Android Debug Bridge version synthetic\n"),
                    ("devices",): _response(
                        stdout=b"List of devices attached\nSYNTHETIC_SERIAL\tdevice\n"
                    ),
                    (
                        "-s",
                        "SYNTHETIC_SERIAL",
                        "shell",
                        "pm",
                        "path",
                        "com.tozelabs.tvshowtime",
                    ): _response(stdout=b"package:/synthetic/base.apk\n"),
                    (
                        "-s",
                        "SYNTHETIC_SERIAL",
                        "shell",
                        "dumpsys",
                        "package",
                        "com.tozelabs.tvshowtime",
                    ): _response(stdout=b"targetSdk=35 allowBackup=true flags=[ HAS_CODE ]\n"),
                }
            )
            probe = probe_android_device(adb, executor=executor)
        self.assertEqual(probe.device, AndroidDeviceState.AVAILABLE)
        self.assertEqual(probe.package, AndroidPackageState.PRESENT)
        self.assertEqual(probe.legacy_backup, AndroidLegacyBackupState.MODERN_RELEASE_APP)
        self.assertFalse(probe.can_attempt_legacy_backup)
        self.assertEqual(probe.target_sdk_band, "31_or_newer")

    def test_older_backup_enabled_app_is_a_bounded_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            adb = Path(temporary) / "synthetic-adb"
            executor = _SyntheticADB(
                {
                    ("version",): _response(stdout=b"Android Debug Bridge version synthetic\n"),
                    ("devices",): _response(
                        stdout=b"List of devices attached\nSYNTHETIC_SERIAL\tdevice\n"
                    ),
                    (
                        "-s",
                        "SYNTHETIC_SERIAL",
                        "shell",
                        "pm",
                        "path",
                        "com.tozelabs.tvshowtime",
                    ): _response(stdout=b"package:/synthetic/base.apk\n"),
                    (
                        "-s",
                        "SYNTHETIC_SERIAL",
                        "shell",
                        "dumpsys",
                        "package",
                        "com.tozelabs.tvshowtime",
                    ): _response(stdout=b"targetSdk=30 allowBackup=true flags=[ HAS_CODE ]\n"),
                }
            )
            probe = probe_android_device(adb, executor=executor)
        self.assertEqual(probe.legacy_backup, AndroidLegacyBackupState.CANDIDATE)
        self.assertTrue(probe.can_attempt_legacy_backup)

    def test_authorization_and_multiple_device_states_expose_no_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            adb = Path(temporary) / "synthetic-adb"
            unauthorized = probe_android_device(
                adb,
                executor=_SyntheticADB(
                    {
                        ("version",): _response(stdout=b"synthetic\n"),
                        ("devices",): _response(
                            stdout=b"List of devices attached\nPRIVATE_SERIAL\tunauthorized\n"
                        ),
                    }
                ),
            )
            multiple = probe_android_device(
                adb,
                executor=_SyntheticADB(
                    {
                        ("version",): _response(stdout=b"synthetic\n"),
                        ("devices",): _response(
                            stdout=(
                                b"List of devices attached\nPRIVATE_ONE\tdevice\n"
                                b"PRIVATE_TWO\tdevice\n"
                            )
                        ),
                    }
                ),
            )
        self.assertEqual(unauthorized.device, AndroidDeviceState.AUTHORIZATION_REQUIRED)
        self.assertEqual(multiple.device, AndroidDeviceState.MULTIPLE_DEVICES)
        payload = privacy_safe_probe_payload(multiple)
        encoded = repr(payload)
        self.assertNotIn("PRIVATE_ONE", encoded)
        self.assertNotIn("PRIVATE_TWO", encoded)
        self.assertEqual(
            set(payload),
            {
                "device",
                "package",
                "legacy_backup",
                "target_sdk_band",
                "debuggable",
                "backup_allowed",
                "can_attempt_legacy_backup",
            },
        )

    def test_explicit_legacy_capture_creates_a_private_supported_container(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adb = root / "synthetic-adb"
            destination = root / "private-capture.ab"

            def executor(arguments: list[str], _timeout: float) -> _CommandResult:
                command = tuple(arguments[1:])
                if command == ("version",):
                    return _response(stdout=b"synthetic\n")
                if command == ("devices",):
                    return _response(stdout=b"List of devices attached\nSYNTHETIC\tdevice\n")
                if command[-4:] == (
                    "shell",
                    "pm",
                    "path",
                    "com.tozelabs.tvshowtime",
                ):
                    return _response(stdout=b"package:/synthetic/base.apk\n")
                if "dumpsys" in command:
                    return _response(stdout=b"targetSdk=30 allowBackup=true\n")
                if "backup" in command:
                    output = Path(arguments[arguments.index("-f") + 1])
                    output.write_bytes(b"ANDROID BACKUP\n5\n1\nnone\nsynthetic")
                    return _response()
                return _CommandResult(1, b"", b"synthetic")

            result = capture_legacy_android_backup(
                adb,
                destination,
                acknowledge_device_capture=True,
                executor=executor,
            )
            self.assertEqual(result.android_backup_version, 5)
            self.assertTrue(destination.is_file())
            if os.name == "nt":
                require_private_path(destination, expected_type=stat.S_IFREG)
            else:
                self.assertEqual(destination.stat().st_mode & 0o077, 0)

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-alias regression")
    def test_capture_path_substitution_cannot_redirect_adb_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adb = root / "synthetic-adb"
            destination = root / "private-capture.ab"
            outside = root / "must-remain-empty"
            outside.write_bytes(b"")

            def executor(arguments: list[str], _timeout: float) -> _CommandResult:
                command = tuple(arguments[1:])
                if command == ("version",):
                    return _response(stdout=b"synthetic\n")
                if command == ("devices",):
                    return _response(stdout=b"List of devices attached\nSYNTHETIC\tdevice\n")
                if command[-4:] == (
                    "shell",
                    "pm",
                    "path",
                    "com.tozelabs.tvshowtime",
                ):
                    return _response(stdout=b"package:/synthetic/base.apk\n")
                if "dumpsys" in command:
                    return _response(stdout=b"targetSdk=30 allowBackup=true\n")
                if "backup" in command:
                    output = Path(arguments[arguments.index("-f") + 1])
                    destination.unlink()
                    destination.symlink_to(outside)
                    output.write_bytes(b"ANDROID BACKUP\n5\n1\nnone\nsynthetic")
                    return _response()
                return _CommandResult(1, b"", b"synthetic")

            with self.assertRaises(TVTimeError):
                capture_legacy_android_backup(
                    adb,
                    destination,
                    acknowledge_device_capture=True,
                    executor=executor,
                )
            self.assertEqual(outside.read_bytes(), b"")

    def test_capture_rejects_device_replacement_after_private_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adb = root / "synthetic-adb"
            destination = root / "must-not-exist.ab"
            device_calls = 0
            backup_called = False

            def executor(arguments: list[str], _timeout: float) -> _CommandResult:
                nonlocal backup_called, device_calls
                command = tuple(arguments[1:])
                if command == ("version",):
                    return _response(stdout=b"synthetic\n")
                if command == ("devices",):
                    device_calls += 1
                    serial = b"PRIVATE_FIRST" if device_calls == 1 else b"PRIVATE_REPLACEMENT"
                    return _response(stdout=b"List of devices attached\n" + serial + b"\tdevice\n")
                if command[-4:] == (
                    "shell",
                    "pm",
                    "path",
                    "com.tozelabs.tvshowtime",
                ):
                    return _response(stdout=b"package:/synthetic/base.apk\n")
                if "dumpsys" in command:
                    return _response(stdout=b"targetSdk=30 allowBackup=true\n")
                if "backup" in command:
                    backup_called = True
                return _response()

            with self.assertRaises(UserInputError):
                capture_legacy_android_backup(
                    adb,
                    destination,
                    acknowledge_device_capture=True,
                    executor=executor,
                )
            self.assertFalse(backup_called)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
