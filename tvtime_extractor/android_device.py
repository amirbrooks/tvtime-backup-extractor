from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .acquisition import (
    ANDROID_PACKAGE_NAME,
    AcquisitionPreflight,
    inspect_android_backup_descriptor,
)
from .errors import TVTimeError, UserInputError
from .safety import (
    harden_private_descriptor,
    nearest_git_root,
    no_link_absolute_path,
    require_private_local_destination,
    windows_create_private_capture_descriptor,
)

ADB_MAXIMUM_OUTPUT_BYTES = 1024 * 1024
ADB_MAXIMUM_BACKUP_BYTES = 4 * 1024 * 1024 * 1024
ADB_PROBE_TIMEOUT_SECONDS = 15.0
ADB_BACKUP_TIMEOUT_SECONDS = 30.0 * 60.0
_TARGET_SDK_PATTERN = re.compile(r"(?:targetSdk|targetSdkVersion)\s*[=:]\s*(\d{1,3})")
_BACKUP_ALLOWED_PATTERN = re.compile(
    r"(?<![a-z0-9_])allow_?backup\s*[=:]\s*(true|false)(?![a-z0-9_])",
    re.IGNORECASE,
)
_BACKUP_DISABLED_PATTERN = re.compile(
    r"(?<![a-z0-9_])backup_?disabled\s*[=:]\s*true(?![a-z0-9_])",
    re.IGNORECASE,
)
_PACKAGE_FLAGS_PATTERN = re.compile(
    r"(?<![a-z0-9_])(?:pkg)?flags\s*=\s*\[([^\]\r\n]*)\]",
    re.IGNORECASE,
)


class AndroidDeviceState(str, Enum):
    AVAILABLE = "available"
    ADB_UNAVAILABLE = "adb_unavailable"
    NO_DEVICE = "no_device"
    MULTIPLE_DEVICES = "multiple_devices"
    AUTHORIZATION_REQUIRED = "authorization_required"
    TRANSPORT_UNAVAILABLE = "transport_unavailable"


class AndroidPackageState(str, Enum):
    PRESENT = "present"
    MISSING = "missing"
    UNKNOWN = "unknown"


class AndroidLegacyBackupState(str, Enum):
    CANDIDATE = "candidate"
    MODERN_RELEASE_APP = "modern_release_app"
    BACKUP_DISABLED = "backup_disabled"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AndroidCapabilityProbe:
    device: AndroidDeviceState
    package: AndroidPackageState
    legacy_backup: AndroidLegacyBackupState
    target_sdk_band: str
    debuggable: bool
    backup_allowed: bool | None
    _transport_serial: str | None = field(default=None, repr=False, compare=False)

    @property
    def can_attempt_legacy_backup(self) -> bool:
        return (
            self.device is AndroidDeviceState.AVAILABLE
            and self.package is AndroidPackageState.PRESENT
            and self.legacy_backup is AndroidLegacyBackupState.CANDIDATE
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "device": self.device.value,
            "package": self.package.value,
            "legacy_backup": self.legacy_backup.value,
            "target_sdk_band": self.target_sdk_band,
            "debuggable": self.debuggable,
            "backup_allowed": self.backup_allowed,
            "can_attempt_legacy_backup": self.can_attempt_legacy_backup,
        }


@dataclass(frozen=True)
class _CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


CommandExecutor = Callable[[Sequence[str], float], _CommandResult]


def _bounded_execute(
    arguments: Sequence[str],
    timeout_seconds: float,
    *,
    monitored_descriptor: int | None = None,
    stdout_descriptor: int | None = None,
) -> _CommandResult:
    if not arguments or any(not isinstance(value, str) or not value for value in arguments):
        raise UserInputError("The Android device command was malformed.")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP"}
    }
    # Anonymous pipes can deadlock if a child fills one stream while the other is
    # being consumed. Private temporary files let us enforce the byte limit on
    # every supported host without retaining identifiers or diagnostics after
    # this call returns.
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                list(arguments),
                stdin=subprocess.DEVNULL,
                stdout=stdout_descriptor if stdout_descriptor is not None else stdout_file,
                stderr=stderr_file,
                shell=False,
                close_fds=True,
                env=environment,
            )
        except (OSError, ValueError) as exc:
            raise TVTimeError("The bundled Android device bridge was unavailable.") from exc
        deadline = time.monotonic() + timeout_seconds
        diagnostic_oversized = False
        backup_oversized = False
        while process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                process.wait()
                raise TVTimeError("The Android device operation timed out safely.")
            diagnostic_oversized = (
                os.fstat(stdout_file.fileno()).st_size > ADB_MAXIMUM_OUTPUT_BYTES
                or os.fstat(stderr_file.fileno()).st_size > ADB_MAXIMUM_OUTPUT_BYTES
            )
            backup_oversized = monitored_descriptor is not None and (
                os.fstat(monitored_descriptor).st_size > ADB_MAXIMUM_BACKUP_BYTES
            )
            if diagnostic_oversized or backup_oversized:
                process.kill()
                process.wait()
                break
            time.sleep(0.02)
        diagnostic_oversized = diagnostic_oversized or (
            os.fstat(stdout_file.fileno()).st_size > ADB_MAXIMUM_OUTPUT_BYTES
            or os.fstat(stderr_file.fileno()).st_size > ADB_MAXIMUM_OUTPUT_BYTES
        )
        backup_oversized = backup_oversized or (
            monitored_descriptor is not None
            and os.fstat(monitored_descriptor).st_size > ADB_MAXIMUM_BACKUP_BYTES
        )
        if diagnostic_oversized:
            raise TVTimeError("The Android device returned an oversized diagnostic response.")
        if backup_oversized:
            raise TVTimeError("The Android device returned an oversized local response.")
        stdout_file.seek(0)
        stderr_file.seek(0)
        return _CommandResult(process.returncode, stdout_file.read(), stderr_file.read())


def _decode_bounded(value: bytes) -> str:
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise TVTimeError("The Android device returned an invalid diagnostic response.") from exc


@contextmanager
def _bound_capture_destination(
    destination: Path,
    *,
    direct_stdout: bool,
) -> Iterator[tuple[Path, int, Callable[[], None]]]:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        if os.name == "nt":
            descriptor = windows_create_private_capture_descriptor(destination)
            child_path = destination
        else:
            descriptor = os.open(destination, flags, 0o600)
            harden_private_descriptor(descriptor, expected_type=stat.S_IFREG, mode=0o600)
            child_path = Path(f"/dev/fd/{descriptor}")
    except BaseException as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if isinstance(exc, TVTimeError):
            raise
        raise TVTimeError(
            "The private Android acquisition file could not be created safely."
        ) from exc
    relay_root: Path | None = None
    relay: Path | None = None
    dummy_writer = -1
    relay_errors: list[BaseException] = []
    relay_thread: threading.Thread | None = None
    relay_finished = False

    def finish_relay() -> None:
        nonlocal dummy_writer, relay_finished
        if relay_finished:
            return
        relay_finished = True
        if dummy_writer >= 0:
            os.close(dummy_writer)
            dummy_writer = -1
        if relay_thread is not None:
            relay_thread.join(timeout=10)
            if relay_thread.is_alive():
                relay_errors.append(TVTimeError("The Android capture relay did not stop safely."))
        if relay_errors:
            error = relay_errors[0]
            if isinstance(error, TVTimeError):
                raise error
            raise TVTimeError(
                "The private Android acquisition file could not be written safely."
            ) from error
        os.fsync(descriptor)

    try:
        if os.name != "nt" and direct_stdout:
            child_path = Path("/dev/stdout")
        elif os.name != "nt":
            relay_root = Path(tempfile.mkdtemp(prefix=".android-capture-", dir=destination.parent))
            os.chmod(relay_root, 0o700)
            relay = relay_root / "capture.pipe"
            os.mkfifo(relay, 0o600)

            def copy_relay() -> None:
                total = 0
                try:
                    with relay.open("rb", buffering=0) as source:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > ADB_MAXIMUM_BACKUP_BYTES:
                                raise TVTimeError(
                                    "The Android device returned an oversized backup container."
                                )
                            view = memoryview(chunk)
                            while view:
                                written = os.write(descriptor, view)
                                if written <= 0:
                                    raise OSError("The private Android capture write stopped.")
                                view = view[written:]
                except BaseException as exc:
                    relay_errors.append(exc)

            relay_thread = threading.Thread(target=copy_relay, name="android-capture-relay")
            relay_thread.start()
            dummy_writer = os.open(relay, os.O_WRONLY)
            child_path = relay
        yield child_path, descriptor, finish_relay
    finally:
        try:
            finish_relay()
        finally:
            os.close(descriptor)
            if relay is not None:
                relay.unlink(missing_ok=True)
            if relay_root is not None:
                relay_root.rmdir()


def _require_bound_capture_identity(destination: Path, descriptor: int) -> None:
    try:
        visible = os.lstat(destination)
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise TVTimeError("The private Android acquisition file identity changed.") from exc
    if stat.S_ISLNK(visible.st_mode) or not os.path.samestat(visible, opened):
        raise TVTimeError("The private Android acquisition file identity changed.")


def _authorized_serials(output: bytes) -> tuple[list[str], bool]:
    text = _decode_bounded(output)
    authorized: list[str] = []
    authorization_required = False
    for index, raw_line in enumerate(text.splitlines()):
        line = raw_line.strip()
        if not line or (index == 0 and line == "List of devices attached"):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        state = fields[1]
        if state == "device":
            authorized.append(fields[0])
        elif state in {"unauthorized", "offline"}:
            authorization_required = True
    return authorized, authorization_required


def _run_for_device(
    adb: Path,
    serial: str,
    arguments: Sequence[str],
    *,
    executor: CommandExecutor,
    timeout_seconds: float = ADB_PROBE_TIMEOUT_SECONDS,
) -> _CommandResult:
    return executor(
        [os.fspath(adb), "-s", serial, *arguments],
        timeout_seconds,
    )


def _target_sdk_band(package_dump: str) -> tuple[str, int | None]:
    match = _TARGET_SDK_PATTERN.search(package_dump)
    if match is None:
        return "unknown", None
    value = int(match.group(1))
    if value >= 31:
        return "31_or_newer", value
    if value >= 23:
        return "23_to_30", value
    return "22_or_older", value


def _package_backup_allowed(package_dump: str) -> bool | None:
    values = {match.group(1).casefold() for match in _BACKUP_ALLOWED_PATTERN.finditer(package_dump)}
    if "false" in values or _BACKUP_DISABLED_PATTERN.search(package_dump) is not None:
        return False
    if "true" in values:
        return True
    for match in _PACKAGE_FLAGS_PATTERN.finditer(package_dump):
        flags = {flag.casefold() for flag in re.split(r"[\s,]+", match.group(1)) if flag}
        if "allow_backup" in flags:
            return True
    return None


def probe_android_device(
    adb_executable: Path,
    *,
    executor: CommandExecutor = _bounded_execute,
) -> AndroidCapabilityProbe:
    adb = no_link_absolute_path(adb_executable)
    try:
        version = executor([os.fspath(adb), "version"], ADB_PROBE_TIMEOUT_SECONDS)
    except TVTimeError:
        return AndroidCapabilityProbe(
            device=AndroidDeviceState.ADB_UNAVAILABLE,
            package=AndroidPackageState.UNKNOWN,
            legacy_backup=AndroidLegacyBackupState.UNKNOWN,
            target_sdk_band="unknown",
            debuggable=False,
            backup_allowed=None,
        )
    if version.returncode != 0:
        return AndroidCapabilityProbe(
            device=AndroidDeviceState.ADB_UNAVAILABLE,
            package=AndroidPackageState.UNKNOWN,
            legacy_backup=AndroidLegacyBackupState.UNKNOWN,
            target_sdk_band="unknown",
            debuggable=False,
            backup_allowed=None,
        )
    devices = executor([os.fspath(adb), "devices"], ADB_PROBE_TIMEOUT_SECONDS)
    if devices.returncode != 0:
        device_state = AndroidDeviceState.TRANSPORT_UNAVAILABLE
        serials: list[str] = []
        authorization_required = False
    else:
        serials, authorization_required = _authorized_serials(devices.stdout)
        if len(serials) > 1:
            device_state = AndroidDeviceState.MULTIPLE_DEVICES
        elif len(serials) == 1:
            device_state = AndroidDeviceState.AVAILABLE
        elif authorization_required:
            device_state = AndroidDeviceState.AUTHORIZATION_REQUIRED
        else:
            device_state = AndroidDeviceState.NO_DEVICE
    if device_state is not AndroidDeviceState.AVAILABLE:
        return AndroidCapabilityProbe(
            device=device_state,
            package=AndroidPackageState.UNKNOWN,
            legacy_backup=AndroidLegacyBackupState.UNKNOWN,
            target_sdk_band="unknown",
            debuggable=False,
            backup_allowed=None,
        )

    serial = serials[0]
    package_path = _run_for_device(
        adb,
        serial,
        ["shell", "pm", "path", ANDROID_PACKAGE_NAME],
        executor=executor,
    )
    if package_path.returncode != 0 or not package_path.stdout.startswith(b"package:"):
        return AndroidCapabilityProbe(
            device=AndroidDeviceState.AVAILABLE,
            package=AndroidPackageState.MISSING,
            legacy_backup=AndroidLegacyBackupState.UNSUPPORTED,
            target_sdk_band="unknown",
            debuggable=False,
            backup_allowed=None,
        )
    package_result = _run_for_device(
        adb,
        serial,
        ["shell", "dumpsys", "package", ANDROID_PACKAGE_NAME],
        executor=executor,
    )
    if package_result.returncode != 0:
        return AndroidCapabilityProbe(
            device=AndroidDeviceState.AVAILABLE,
            package=AndroidPackageState.PRESENT,
            legacy_backup=AndroidLegacyBackupState.UNKNOWN,
            target_sdk_band="unknown",
            debuggable=False,
            backup_allowed=None,
        )
    package_dump = _decode_bounded(package_result.stdout)
    sdk_band, target_sdk = _target_sdk_band(package_dump)
    normalized = package_dump.casefold()
    debuggable = "debuggable" in normalized and "debuggable=false" not in normalized
    backup_allowed = _package_backup_allowed(package_dump)
    if backup_allowed is False:
        legacy = AndroidLegacyBackupState.BACKUP_DISABLED
    elif target_sdk is not None and target_sdk >= 31 and not debuggable:
        legacy = AndroidLegacyBackupState.MODERN_RELEASE_APP
    elif target_sdk is not None and (target_sdk < 31 or debuggable):
        legacy = AndroidLegacyBackupState.CANDIDATE
    else:
        legacy = AndroidLegacyBackupState.UNKNOWN
    return AndroidCapabilityProbe(
        device=AndroidDeviceState.AVAILABLE,
        package=AndroidPackageState.PRESENT,
        legacy_backup=legacy,
        target_sdk_band=sdk_band,
        debuggable=debuggable,
        backup_allowed=backup_allowed,
        _transport_serial=serial,
    )


def capture_legacy_android_backup(
    adb_executable: Path,
    destination: Path,
    *,
    acknowledge_device_capture: bool,
    executor: CommandExecutor = _bounded_execute,
) -> AcquisitionPreflight:
    if not acknowledge_device_capture:
        raise UserInputError(
            "Android device capture requires explicit acknowledgement before the phone is used."
        )
    probe = probe_android_device(adb_executable, executor=executor)
    if not probe.can_attempt_legacy_backup:
        raise UserInputError("This Android device is not a safe legacy-backup candidate.")
    adb = no_link_absolute_path(adb_executable)
    devices = executor([os.fspath(adb), "devices"], ADB_PROBE_TIMEOUT_SECONDS)
    serials, _authorization_required = _authorized_serials(devices.stdout)
    if len(serials) != 1 or serials[0] != probe._transport_serial:
        raise UserInputError("Exactly one authorized Android device is required.")
    destination = no_link_absolute_path(destination)
    require_private_local_destination(destination)
    if nearest_git_root(destination) is not None:
        raise UserInputError(
            "The private Android acquisition file must be outside every Git repository."
        )
    if destination.exists() or destination.is_symlink():
        raise UserInputError("The private Android acquisition file must be fresh.")
    direct_stdout = executor is _bounded_execute and os.name != "nt"
    with _bound_capture_destination(destination, direct_stdout=direct_stdout) as (
        child_path,
        destination_descriptor,
        finish_relay,
    ):
        _require_bound_capture_identity(destination, destination_descriptor)
        capture_arguments = [
            os.fspath(adb),
            "-s",
            serials[0],
            "backup",
            "-noapk",
            "-f",
            os.fspath(child_path),
            ANDROID_PACKAGE_NAME,
        ]
        if executor is _bounded_execute:
            result = _bounded_execute(
                capture_arguments,
                ADB_BACKUP_TIMEOUT_SECONDS,
                monitored_descriptor=destination_descriptor,
                stdout_descriptor=destination_descriptor if direct_stdout else None,
            )
        else:
            result = executor(capture_arguments, ADB_BACKUP_TIMEOUT_SECONDS)
            if os.fstat(destination_descriptor).st_size > ADB_MAXIMUM_BACKUP_BYTES:
                raise TVTimeError("The Android device returned an oversized local response.")
        finish_relay()
        _require_bound_capture_identity(destination, destination_descriptor)
        if result.returncode != 0 or not destination.is_file():
            raise TVTimeError("The Android device did not complete a local backup.")
        preflight = inspect_android_backup_descriptor(destination_descriptor)
        _require_bound_capture_identity(destination, destination_descriptor)
        return preflight


def privacy_safe_probe_payload(probe: AndroidCapabilityProbe) -> Mapping[str, object]:
    """Return the only device-probe fields permitted across a native UI boundary."""

    return probe.as_dict()
