from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import select
import shutil
import stat
import struct
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import BinaryIO

PROTOCOL_VERSION = 3
DESTINATION_PARENT_FILE_DESCRIPTOR = 4
MAXIMUM_FRAME_BYTES = 1024 * 1024
AD_HOC_CODE_DIRECTORY_FLAG = 0x2
HARDENED_RUNTIME_CODE_DIRECTORY_FLAG = 0x10000
STANDALONE_SMOKE_ENTITLEMENTS = {
    "com.apple.security.cs.disable-library-validation": True,
}
DEVELOPER_ID_STANDALONE_ENTITLEMENTS: dict[str, object] = {}
SUPPORTED_RELEASE_ARCHITECTURES = {"arm64", "x86_64"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def immutable_tree_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    records: list[tuple[object, ...]] = []
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        current_path = Path(current)
        metadata = current_path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or current_path.is_symlink():
            raise RuntimeError("Synthetic source contains an unsafe directory entry")
        records.append(
            (
                current_path.relative_to(root).as_posix(),
                "directory",
                stat.S_IMODE(metadata.st_mode),
                metadata.st_mtime_ns,
            )
        )
        for file_name in file_names:
            path = current_path / file_name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                raise RuntimeError("Synthetic source contains an unsafe file entry")
            records.append(
                (
                    path.relative_to(root).as_posix(),
                    "file",
                    stat.S_IMODE(metadata.st_mode),
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    sha256_file(path),
                )
            )
    return tuple(records)


def framed_json(value: object) -> bytes:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if not encoded or len(encoded) > MAXIMUM_FRAME_BYTES:
        raise RuntimeError("Synthetic helper request exceeded the protocol bound")
    return struct.pack(">I", len(encoded)) + encoded


def read_event_line(stream: BinaryIO, deadline: float) -> dict[str, object]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("Packaged helper timed out before a terminal event")
    readable, _, _ = select.select([stream.fileno()], [], [], remaining)
    if not readable:
        raise RuntimeError("Packaged helper timed out before a terminal event")
    line = stream.readline(MAXIMUM_FRAME_BYTES + 2)
    if not line:
        raise RuntimeError("Packaged helper closed its event stream unexpectedly")
    if len(line) > MAXIMUM_FRAME_BYTES + 1 or not line.endswith(b"\n"):
        raise RuntimeError("Packaged helper emitted an invalid event frame")
    try:
        event = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Packaged helper emitted invalid event JSON") from error
    if not isinstance(event, dict):
        raise RuntimeError("Packaged helper event was not an object")
    return event


def create_synthetic_backup(root: Path) -> tuple[Path, Path]:
    backup = root / "synthetic-encrypted-backup"
    backup.mkdir(mode=0o700)
    with (backup / "Manifest.plist").open("wb") as handle:
        plistlib.dump({"IsEncrypted": True}, handle)
    with (backup / "Status.plist").open("wb") as handle:
        plistlib.dump({"SnapshotState": "finished"}, handle)
    (backup / "Manifest.db").write_bytes(b"synthetic manifest placeholder\n")
    output = root / "fresh-private-destination"
    return backup, output


@contextmanager
def mapped_destination_parent_descriptor(parent: Path) -> Iterator[tuple[int, int]]:
    """Temporarily reserve FD 4 in this single-threaded smoke process for Popen."""

    saved = -1
    source = -1
    try:
        original_inheritable = os.get_inheritable(DESTINATION_PARENT_FILE_DESCRIPTOR)
    except OSError:
        original_inheritable = False
    else:
        # If FD 4 is live, failing to save it must stop the smoke rather than
        # silently clobber a caller-owned descriptor.
        saved = os.dup(DESTINATION_PARENT_FILE_DESCRIPTOR)
    try:
        source = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        if source != DESTINATION_PARENT_FILE_DESCRIPTOR:
            os.dup2(
                source,
                DESTINATION_PARENT_FILE_DESCRIPTOR,
                inheritable=True,
            )
            os.close(source)
        source = -1
        metadata = os.fstat(DESTINATION_PARENT_FILE_DESCRIPTOR)
        yield (int(metadata.st_dev), int(metadata.st_ino))
    finally:
        if source >= 0:
            os.close(source)
        if saved < 0:
            with suppress(OSError):
                os.close(DESTINATION_PARENT_FILE_DESCRIPTOR)
        else:
            os.dup2(
                saved,
                DESTINATION_PARENT_FILE_DESCRIPTOR,
                inheritable=original_inheritable,
            )
            os.close(saved)


def terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.stdin is not None and not process.stdin.closed:
        process.stdin.close()
    try:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    finally:
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def verify_standalone_helper_signature(bundle: Path) -> None:
    verification = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(bundle)],
        capture_output=True,
        check=False,
    )
    if verification.returncode != 0:
        raise RuntimeError("Standalone frozen-helper test copy did not pass code-signing checks")

    signing_details = subprocess.run(
        ["/usr/bin/codesign", "--display", "--verbose=4", str(bundle)],
        capture_output=True,
        check=False,
    )
    flags_match = re.search(
        rb"\bflags=0x([0-9a-fA-F]+)",
        signing_details.stdout + signing_details.stderr,
    )
    if signing_details.returncode != 0 or flags_match is None:
        raise RuntimeError("Could not inspect the standalone frozen-helper signing flags")
    code_directory_flags = int(flags_match.group(1), 16)
    if not code_directory_flags & AD_HOC_CODE_DIRECTORY_FLAG:
        raise RuntimeError("Standalone frozen-helper test copy was not ad-hoc signed")
    if not code_directory_flags & HARDENED_RUNTIME_CODE_DIRECTORY_FLAG:
        raise RuntimeError("Standalone frozen-helper test copy lost hardened runtime")

    entitlements = subprocess.run(
        [
            "/usr/bin/codesign",
            "--display",
            "--entitlements",
            "-",
            "--xml",
            str(bundle),
        ],
        capture_output=True,
        check=False,
    )
    try:
        applied_entitlements = plistlib.loads(entitlements.stdout)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise RuntimeError("Could not inspect the standalone frozen-helper entitlements") from error
    if entitlements.returncode != 0 or applied_entitlements != STANDALONE_SMOKE_ENTITLEMENTS:
        raise RuntimeError(
            "Standalone frozen-helper test copy did not have the exact smoke entitlements"
        )


def developer_id_team_identifier(identity: str) -> str:
    if not identity.startswith("Developer ID Application:"):
        raise RuntimeError("Developer ID smoke requires a Developer ID Application identity")
    match = re.search(r"\(([A-Z0-9]{10})\)\s*$", identity)
    if match is None:
        raise RuntimeError("Developer ID smoke identity did not contain a valid Team ID")
    return match.group(1)


def developer_id_launch_command(helper: Path, architecture: str) -> list[str]:
    if architecture not in SUPPORTED_RELEASE_ARCHITECTURES:
        raise RuntimeError("Developer ID smoke requires arm64 or x86_64")
    return ["/usr/bin/arch", f"-{architecture}", str(helper)]


def verify_developer_id_standalone_helper_signature(
    bundle: Path,
    helper: Path,
    identity: str,
    architecture: str,
) -> None:
    expected_team_identifier = developer_id_team_identifier(identity)
    if architecture not in SUPPORTED_RELEASE_ARCHITECTURES:
        raise RuntimeError("Developer ID smoke requires arm64 or x86_64")

    verification = subprocess.run(
        [
            "/usr/bin/codesign",
            "--verify",
            "--deep",
            "--strict",
            "--verbose=2",
            str(bundle),
        ],
        capture_output=True,
        check=False,
    )
    if verification.returncode != 0:
        raise RuntimeError(
            "Developer ID standalone helper did not pass deep, strict code-signing checks"
        )

    signing_details = subprocess.run(
        ["/usr/bin/codesign", "--display", "--verbose=4", str(bundle)],
        capture_output=True,
        check=False,
    )
    details = signing_details.stdout + signing_details.stderr
    flags_match = re.search(rb"\bflags=0x([0-9a-fA-F]+)", details)
    team_match = re.search(rb"(?m)^TeamIdentifier=([A-Z0-9]+)$", details)
    authority_match = re.search(rb"(?m)^Authority=(.+)$", details)
    if (
        signing_details.returncode != 0
        or flags_match is None
        or team_match is None
        or authority_match is None
    ):
        raise RuntimeError("Could not inspect the Developer ID standalone helper signature")
    code_directory_flags = int(flags_match.group(1), 16)
    if code_directory_flags & AD_HOC_CODE_DIRECTORY_FLAG:
        raise RuntimeError("Developer ID standalone helper was unexpectedly ad-hoc signed")
    if not code_directory_flags & HARDENED_RUNTIME_CODE_DIRECTORY_FLAG:
        raise RuntimeError("Developer ID standalone helper lost hardened runtime")
    try:
        applied_authority = authority_match.group(1).decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError(
            "Could not inspect the Developer ID standalone helper authority"
        ) from error
    if applied_authority != identity:
        raise RuntimeError(
            "Developer ID standalone helper authority did not match the requested identity"
        )
    applied_team_identifier = team_match.group(1).decode("ascii")
    if applied_team_identifier != expected_team_identifier:
        raise RuntimeError("Developer ID standalone helper Team ID did not match the identity")

    entitlements = subprocess.run(
        [
            "/usr/bin/codesign",
            "--display",
            "--entitlements",
            "-",
            "--xml",
            str(bundle),
        ],
        capture_output=True,
        check=False,
    )
    try:
        applied_entitlements = plistlib.loads(entitlements.stdout)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise RuntimeError(
            "Could not inspect the Developer ID standalone helper entitlements"
        ) from error
    if entitlements.returncode != 0 or applied_entitlements != DEVELOPER_ID_STANDALONE_ENTITLEMENTS:
        raise RuntimeError(
            "Developer ID standalone helper did not have an exact empty entitlement dictionary"
        )

    architecture_check = subprocess.run(
        ["/usr/bin/lipo", "-archs", str(helper)],
        capture_output=True,
        check=False,
    )
    try:
        applied_architectures = architecture_check.stdout.decode("ascii").split()
    except UnicodeDecodeError as error:
        raise RuntimeError(
            "Could not inspect the Developer ID standalone helper architecture"
        ) from error
    if architecture_check.returncode != 0 or applied_architectures != [architecture]:
        raise RuntimeError(
            "Developer ID standalone helper did not have the exact requested architecture"
        )


def create_standalone_helper_copy(helper: Path, root: Path) -> Path:
    """Copy the frozen payload with the narrow profile needed for a shell smoke.

    The shipped helper intentionally inherits the native app's sandbox, so macOS terminates
    it when it is launched directly by a non-sandboxed shell. The standalone copy removes
    only that launch constraint. It remains ad-hoc signed with hardened runtime enabled and
    retains only the library-validation exception needed by the frozen Python payload.
    """
    bundle = next((parent for parent in helper.parents if parent.suffix == ".bundle"), None)
    if bundle is None:
        raise RuntimeError("Packaged helper was not inside its expected bundle")
    relative_helper = helper.relative_to(bundle)
    standalone_bundle = root / "standalone-helper.bundle"
    shutil.copytree(bundle, standalone_bundle, symlinks=True)
    smoke_entitlements = root / "standalone-helper-smoke-entitlements.plist"
    with smoke_entitlements.open("wb") as handle:
        plistlib.dump(STANDALONE_SMOKE_ENTITLEMENTS, handle, sort_keys=True)
    signing = subprocess.run(
        [
            "/usr/bin/codesign",
            "--force",
            "--sign",
            "-",
            "--timestamp=none",
            "--options",
            "runtime",
            "--entitlements",
            str(smoke_entitlements),
            str(standalone_bundle),
        ],
        capture_output=True,
        check=False,
    )
    if signing.returncode != 0:
        raise RuntimeError("Could not prepare the frozen helper for standalone smoke testing")
    verify_standalone_helper_signature(standalone_bundle)
    standalone_helper = standalone_bundle / relative_helper
    if not standalone_helper.is_file() or not os.access(standalone_helper, os.X_OK):
        raise RuntimeError("Standalone frozen-helper test copy was not executable")
    return standalone_helper


def create_developer_id_standalone_helper_copy(
    helper: Path,
    root: Path,
    identity: str,
    architecture: str,
) -> Path:
    """Prepare a direct-launch copy without changing any nested frozen payload.

    The release app has already been signed and verified before this function is called. Signing
    only the copied outer helper bundle replaces its sandbox-inheritance entitlement with an exact
    empty dictionary. Nested frameworks and libraries retain their original Developer ID signatures.
    """
    developer_id_team_identifier(identity)
    if architecture not in SUPPORTED_RELEASE_ARCHITECTURES:
        raise RuntimeError("Developer ID smoke requires arm64 or x86_64")
    bundle = next((parent for parent in helper.parents if parent.suffix == ".bundle"), None)
    if bundle is None:
        raise RuntimeError("Packaged helper was not inside its expected bundle")
    relative_helper = helper.relative_to(bundle)
    standalone_bundle = root / "developer-id-standalone-helper.bundle"
    shutil.copytree(bundle, standalone_bundle, symlinks=True)
    empty_entitlements = root / "developer-id-empty-entitlements.plist"
    with empty_entitlements.open("wb") as handle:
        plistlib.dump(DEVELOPER_ID_STANDALONE_ENTITLEMENTS, handle, sort_keys=True)
    empty_entitlements.chmod(0o600)
    signing = subprocess.run(
        [
            "/usr/bin/codesign",
            "--force",
            "--sign",
            identity,
            "--timestamp",
            "--options",
            "runtime",
            "--entitlements",
            str(empty_entitlements),
            str(standalone_bundle),
        ],
        capture_output=True,
        check=False,
    )
    if signing.returncode != 0:
        raise RuntimeError("Could not prepare the Developer ID helper for standalone smoke testing")
    standalone_helper = standalone_bundle / relative_helper
    if not standalone_helper.is_file() or not os.access(standalone_helper, os.X_OK):
        raise RuntimeError("Developer ID standalone helper test copy was not executable")
    verify_developer_id_standalone_helper_signature(
        standalone_bundle,
        standalone_helper,
        identity,
        architecture,
    )
    return standalone_helper


def run_smoke(
    helper: Path,
    *,
    developer_id_identity: str | None = None,
    architecture: str | None = None,
) -> None:
    if not helper.is_file() or helper.is_symlink() or not os.access(helper, os.X_OK):
        raise RuntimeError("Packaged helper is missing, linked, or not executable")
    if (developer_id_identity is None) != (architecture is None):
        raise RuntimeError("Developer ID smoke requires both an identity and an architecture")

    with tempfile.TemporaryDirectory(prefix="tvtime-packaged-helper-smoke-") as temporary:
        root = Path(temporary)
        backup, output = create_synthetic_backup(root)
        before = immutable_tree_snapshot(backup)
        if developer_id_identity is None:
            standalone_helper = create_standalone_helper_copy(helper, root)
            launch_command = [str(standalone_helper)]
        else:
            if architecture is None:
                raise RuntimeError("Developer ID smoke architecture was unavailable")
            standalone_helper = create_developer_id_standalone_helper_copy(
                helper,
                root,
                developer_id_identity,
                architecture,
            )
            launch_command = developer_id_launch_command(standalone_helper, architecture)
        with mapped_destination_parent_descriptor(output.parent) as destination_identity:
            process = subprocess.Popen(
                launch_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                pass_fds=(DESTINATION_PARENT_FILE_DESCRIPTOR,),
            )
        try:
            if process.stdin is None or process.stdout is None or process.stderr is None:
                raise RuntimeError("Could not create packaged-helper protocol pipes")
            request = {
                "protocolVersion": PROTOCOL_VERSION,
                "type": "preflight",
                "payload": {
                    "backup_directory": str(backup),
                    "output_directory": str(output),
                    "destination_parent_identity": {
                        "device": destination_identity[0],
                        "inode": destination_identity[1],
                    },
                    "acknowledge_sensitive_output": False,
                    "include_raw_cache": False,
                    "include_decrypted_manifest": False,
                    "backup_receipt": None,
                },
            }
            process.stdin.write(framed_json(request))
            process.stdin.flush()

            deadline = time.monotonic() + 30
            expected_sequence = 1
            ready_seen = False
            progress_seen = False
            completed_seen = False
            while not completed_seen:
                event = read_event_line(process.stdout, deadline)
                if set(event) != {"protocolVersion", "sequence", "type", "payload"}:
                    raise RuntimeError("Packaged helper event fields did not match protocol v3")
                if event.get("protocolVersion") != PROTOCOL_VERSION:
                    raise RuntimeError("Packaged helper used an incompatible protocol version")
                if event.get("sequence") != expected_sequence:
                    raise RuntimeError("Packaged helper event sequence was not contiguous")
                expected_sequence += 1
                event_type = event.get("type")
                payload = event.get("payload")
                if not isinstance(payload, dict):
                    raise RuntimeError("Packaged helper event payload was not an object")
                if event_type == "ready":
                    if ready_seen or expected_sequence != 2:
                        raise RuntimeError("Packaged helper ready event was not first and unique")
                    capabilities = payload.get("capabilities")
                    if (
                        not isinstance(capabilities, list)
                        or "preflight" not in capabilities
                        or "destination-parent-fd" not in capabilities
                        or "source-receipt-v1" not in capabilities
                    ):
                        raise RuntimeError("Packaged helper did not advertise preflight support")
                    ready_seen = True
                elif event_type == "progress":
                    if not ready_seen or payload.get("stage") != "preflight":
                        raise RuntimeError("Packaged helper emitted invalid preflight progress")
                    progress_seen = True
                elif event_type == "completed":
                    if (
                        not ready_seen
                        or not progress_seen
                        or set(payload)
                        != {
                            "preflight",
                            "backup_receipt",
                        }
                    ):
                        raise RuntimeError("Packaged helper emitted an invalid completion payload")
                    preflight = payload.get("preflight")
                    if not isinstance(preflight, dict):
                        raise RuntimeError("Packaged helper preflight summary was unavailable")
                    if preflight.get("encrypted") is not True:
                        raise RuntimeError("Packaged helper did not confirm synthetic encryption")
                    if preflight.get("snapshot_state") != "finished":
                        raise RuntimeError("Packaged helper did not confirm synthetic completion")
                    if preflight.get("backup_regular_files") != 3:
                        raise RuntimeError(
                            "Packaged helper returned an invalid synthetic file count"
                        )
                    receipt = payload.get("backup_receipt")
                    receipt_fields = {
                        "schema_version",
                        "contract",
                        "root_device",
                        "root_inode",
                        "backup_regular_files",
                        "backup_logical_bytes",
                        "manifest_plist",
                        "manifest_database",
                        "status_plist",
                    }
                    if not isinstance(receipt, dict) or set(receipt) != receipt_fields:
                        raise RuntimeError("Packaged helper returned an invalid source receipt")
                    if (
                        receipt.get("schema_version") != 1
                        or receipt.get("contract") != "tvtime-backup-preflight-receipt-v0.2"
                        or receipt.get("backup_regular_files")
                        != preflight.get("backup_regular_files")
                        or receipt.get("backup_logical_bytes")
                        != preflight.get("backup_logical_bytes")
                    ):
                        raise RuntimeError(
                            "Packaged helper source receipt was not bound to preflight"
                        )
                    file_fields = {
                        "mode",
                        "size",
                        "modified_ns",
                        "changed_ns",
                        "device",
                        "inode",
                        "sha256",
                    }
                    for key in ("manifest_plist", "manifest_database", "status_plist"):
                        file_snapshot = receipt.get(key)
                        if (
                            not isinstance(file_snapshot, dict)
                            or set(file_snapshot) != file_fields
                            or not isinstance(file_snapshot.get("sha256"), str)
                            or re.fullmatch(r"[0-9a-f]{64}", file_snapshot["sha256"]) is None
                        ):
                            raise RuntimeError(
                                "Packaged helper source receipt file snapshot was invalid"
                            )
                    completed_seen = True
                elif event_type in {"failed", "cancelled"}:
                    raise RuntimeError("Packaged helper rejected a safe synthetic preflight")
                else:
                    raise RuntimeError("Packaged helper emitted an unsupported event type")

            process.stdin.close()
            return_code = process.wait(timeout=10)
            if return_code != 0:
                raise RuntimeError("Packaged helper exited unsuccessfully after completion")
            if process.stdout.read(1):
                raise RuntimeError("Packaged helper emitted data after its terminal event")
            if process.stderr.read(1):
                raise RuntimeError("Packaged helper leaked diagnostic output outside the protocol")
            if output.exists() or output.is_symlink():
                raise RuntimeError("Packaged helper preflight unexpectedly created recovery output")
            if immutable_tree_snapshot(backup) != before:
                raise RuntimeError("Packaged helper changed the synthetic source backup")
        finally:
            terminate_process(process)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--developer-id-identity")
    parser.add_argument("--architecture", choices=sorted(SUPPORTED_RELEASE_ARCHITECTURES))
    arguments = parser.parse_args()
    run_smoke(
        arguments.helper.expanduser().absolute(),
        developer_id_identity=arguments.developer_id_identity,
        architecture=arguments.architecture,
    )
    print(
        "Packaged helper synthetic preflight passed: protocol framing, terminal event, "
        "no output, and source immutability."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
