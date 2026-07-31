from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from script.validate_recovery_output import validate_recovery_output  # noqa: E402
from tests.cross_platform_fixtures import (  # noqa: E402
    create_synthetic_android_backup,
    create_synthetic_android_snapshot,
    create_synthetic_official_export,
)
from tvtime_extractor.acquisition import (  # noqa: E402
    ANDROID_BACKUP_MAGIC,
    RecoverySourceKind,
    recover_acquired_source,
)
from tvtime_extractor.errors import UnsupportedSchemaError  # noqa: E402
from tvtime_extractor.safety import secure_directory, secure_file, set_private_umask  # noqa: E402

MAXIMUM_SCRUB_FILE_BYTES = 64 * 1024 * 1024
MAXIMUM_SCRUB_TREE_BYTES = 512 * 1024 * 1024


class AcceptanceFailure(RuntimeError):
    """A privacy-safe acceptance failure whose detail must never be printed."""


@dataclass(frozen=True)
class Gate:
    name: str
    status: str


def _encoded_needles(values: Iterable[str]) -> tuple[bytes, ...]:
    needles: list[bytes] = []
    for value in values:
        if len(value) < 4:
            continue
        for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
            needles.append(value.encode(encoding))
    return tuple(needles)


def _environment_needles() -> tuple[bytes, ...]:
    values = {
        os.fspath(Path.home()),
        os.fspath(ROOT),
        os.environ.get("USERPROFILE", ""),
    }
    return _encoded_needles(value for value in values if value)


def _contains_needle(path: Path, needles: tuple[bytes, ...]) -> bool:
    overlap_size = max((len(needle) for needle in needles), default=0)
    overlap = b""
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            block = overlap + chunk
            if any(needle in block for needle in needles):
                return True
            overlap = block[-overlap_size:] if overlap_size else b""
    return False


def scrub_synthetic_tree(root: Path) -> None:
    root = root.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise AcceptanceFailure("synthetic tree root was unsafe")
    needles = _environment_needles()
    total_bytes = 0
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directory_names:
            directory = current_path / name
            metadata = directory.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise AcceptanceFailure("synthetic tree contained an unsafe directory")
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
                raise AcceptanceFailure("synthetic directory permissions were not private")
        for name in file_names:
            path = current_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise AcceptanceFailure("synthetic tree contained an unsafe file")
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
                raise AcceptanceFailure("synthetic file permissions were not private")
            if metadata.st_size > MAXIMUM_SCRUB_FILE_BYTES:
                raise AcceptanceFailure("synthetic file exceeded the scrub bound")
            total_bytes += metadata.st_size
            if total_bytes > MAXIMUM_SCRUB_TREE_BYTES:
                raise AcceptanceFailure("synthetic tree exceeded the scrub bound")
            if _contains_needle(path, needles):
                raise AcceptanceFailure("synthetic tree contained host-specific content")


def _recover_fixture(source_kind: RecoverySourceKind, source: Path, output: Path) -> None:
    result = recover_acquired_source(
        source_kind=source_kind,
        source=source,
        output_directory=output,
        acknowledge_sensitive_output=True,
    )
    if result.analysis.get("parser_status") != "recognized":
        raise AcceptanceFailure("synthetic analysis was not recognized")
    if int(result.analysis.get("series_library", 0)) < 1:
        raise AcceptanceFailure("synthetic analysis lost its expected series")
    validate_recovery_output(result.extraction.extraction_root.parent)


def _run_synthetic_gates(root: Path) -> list[Gate]:
    gates: list[Gate] = []
    cases = (
        (
            "android_archive",
            RecoverySourceKind.ANDROID_LEGACY_BACKUP,
            create_synthetic_android_backup(root / "source-android.ab"),
        ),
        (
            "android_snapshot",
            RecoverySourceKind.ANDROID_PRESERVED_SNAPSHOT,
            create_synthetic_android_snapshot(root / "source-snapshot"),
        ),
        (
            "official_export",
            RecoverySourceKind.TVTIME_OFFICIAL_EXPORT,
            create_synthetic_official_export(root / "source-export.zip"),
        ),
    )
    for name, source_kind, source in cases:
        try:
            _recover_fixture(source_kind, source, root / f"output-{name}")
        except Exception:
            gates.append(Gate(name, "FAIL"))
        else:
            gates.append(Gate(name, "PASS"))

    encrypted = root / "source-unsupported-encrypted.ab"
    encrypted.write_bytes(ANDROID_BACKUP_MAGIC + b"5\n1\nAES-256\nsynthetic")
    secure_file(encrypted)
    rejected_output = root / "output-unsupported-encrypted"
    try:
        recover_acquired_source(
            source_kind=RecoverySourceKind.ANDROID_LEGACY_BACKUP,
            source=encrypted,
            output_directory=rejected_output,
            acknowledge_sensitive_output=True,
        )
    except UnsupportedSchemaError:
        gates.append(Gate("unsupported_android_rejected", "PASS"))
    except Exception:
        gates.append(Gate("unsupported_android_rejected", "FAIL"))
    else:
        gates.append(Gate("unsupported_android_rejected", "FAIL"))

    try:
        scrub_synthetic_tree(root)
    except Exception:
        gates.append(Gate("privacy_scrub", "FAIL"))
    else:
        gates.append(Gate("privacy_scrub", "PASS"))
    return gates


def _vswhere_has_msbuild() -> bool:
    program_files = os.environ.get("PROGRAMFILES(X86)", "")
    if not program_files:
        return False
    vswhere = Path(program_files) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        return False
    try:
        result = subprocess.run(
            [
                os.fspath(vswhere),
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.Component.MSBuild",
                "-find",
                r"MSBuild\**\Bin\MSBuild.exe",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and any(line.strip() for line in result.stdout.splitlines())


def readiness_gates(
    *,
    which: Callable[[str], str | None] = shutil.which,
    platform_name: str = sys.platform,
    require_adb: bool = False,
    require_android_emulator: bool = False,
    require_windows_toolchain: bool = False,
    msbuild_probe: Callable[[], bool] = _vswhere_has_msbuild,
) -> list[Gate]:
    def optional(name: str, available: bool, required: bool) -> Gate:
        if available:
            return Gate(name, "PASS")
        return Gate(name, "FAIL" if required else "SKIP")

    gates = [optional("adb_tool", which("adb") is not None, require_adb)]
    gates.append(
        optional(
            "android_emulator",
            which("emulator") is not None,
            require_android_emulator,
        )
    )
    windows_tools = (
        which("dotnet") is not None
        and (which("pwsh") is not None or which("powershell") is not None)
        and (which("msbuild") is not None or which("MSBuild.exe") is not None or msbuild_probe())
    )
    windows_required = require_windows_toolchain or platform_name.startswith("win")
    gates.append(optional("windows_toolchain", windows_tools, windows_required))
    return gates


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run privacy-safe synthetic cross-platform recovery acceptance checks."
    )
    parser.add_argument("--require-adb", action="store_true")
    parser.add_argument("--require-android-emulator", action="store_true")
    parser.add_argument("--require-windows-toolchain", action="store_true")
    arguments = parser.parse_args()

    set_private_umask()
    gates: list[Gate] = []
    try:
        with tempfile.TemporaryDirectory(prefix="tvtime-synthetic-acceptance-") as temporary:
            root = secure_directory(Path(temporary))
            gates.extend(_run_synthetic_gates(root))
    except Exception:
        gates.append(Gate("synthetic_environment", "FAIL"))
    gates.extend(
        readiness_gates(
            require_adb=arguments.require_adb,
            require_android_emulator=arguments.require_android_emulator,
            require_windows_toolchain=arguments.require_windows_toolchain,
        )
    )

    for gate in gates:
        print(f"GATE {gate.name} {gate.status}")
    failed = any(gate.status == "FAIL" for gate in gates)
    print(f"RESULT {'FAIL' if failed else 'PASS'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
