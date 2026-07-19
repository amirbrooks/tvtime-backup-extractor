from __future__ import annotations

import getpass
import hashlib
import io
import json
import os
import plistlib
import secrets
import shutil
import stat
import sys
import tempfile
from collections.abc import Callable
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import (
    AppDataMissingError,
    BackupPasswordError,
    BackupUnfinishedError,
    SourceChangedError,
    TVTimeError,
    UnsafePathError,
    UserInputError,
    insufficient_space_error,
    is_insufficient_space_error,
)
from .integrity import SourceSnapshot, reconcile_raw_tree
from .safety import (
    EXTRACTION_RUN_STATE_CONTRACT,
    EXTRACTION_RUN_STATE_SCHEMA_VERSION,
    ExtractionLayout,
    anchored_bound_output_root,
    harden_private_descriptor,
    held_destination_parent,
    no_link_absolute_path,
    prepare_anchored_extraction_layout,
    prepare_extraction_layout,
    promote_file_no_replace_atomic,
    require_fresh_output_platform_support,
    require_private_descriptor,
    safe_domain_component,
    safe_join,
    safe_manifest_relative_path,
    secure_directory,
    secure_file,
    set_private_umask,
    validate_backup_directory,
    validate_file_id,
    write_csv_private,
    write_json_private_atomic,
    write_text_private,
)

TVTIME_BUNDLE_ID = "com.tozelabs.tvshowtime"
PRIMARY_DOMAIN = f"AppDomain-{TVTIME_BUNDLE_ID}"
RELATED_PLUGIN_DOMAIN_PREFIX = f"AppDomainPlugin-{TVTIME_BUNDLE_ID}."
DEPENDENCY_FAILURE_MESSAGE = (
    "The encrypted-backup dependency failed safely. Recovery remains incomplete; preserve the "
    "source backup and retry into a fresh private destination."
)
DEPENDENCY_FILE_FAILURE_MESSAGE = "The selected backup file could not be copied safely."
MAXIMUM_MANIFEST_DOMAIN_ROWS = 64
MAXIMUM_MANIFEST_FILE_ROWS = 250_000
MAXIMUM_MANIFEST_CELL_BYTES = 4 * 1024 * 1024
MAXIMUM_MANIFEST_COMBINED_BYTES = 256 * 1024 * 1024
MAXIMUM_STATUS_PLIST_BYTES = 1024 * 1024
_MANIFEST_FETCH_BATCH_ROWS = 256


@dataclass(frozen=True)
class ExtractionResult:
    extraction_root: Path
    summary: dict[str, Any]

    @property
    def has_failures(self) -> bool:
        return bool(self.summary["failures"])


@dataclass(frozen=True)
class BackupFileSnapshot:
    mode: int
    size: int
    modified_ns: int
    changed_ns: int
    device: int
    inode: int
    sha256: str

    def same_content(self, other: BackupFileSnapshot) -> bool:
        return self.size == other.size and self.sha256 == other.sha256


@dataclass(frozen=True)
class BackupPreflightSnapshot:
    root_device: int
    root_inode: int
    manifest_plist: BackupFileSnapshot
    manifest_database: BackupFileSnapshot
    status_plist: BackupFileSnapshot


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _same_source_metadata(before: os.stat_result, after: os.stat_result) -> bool:
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    return all(getattr(before, field, 0) == getattr(after, field, 0) for field in fields)


def _source_payload_state(
    path: Path,
    *,
    snapshot_destination: Path | None = None,
    source_root_descriptor: int | None = None,
) -> BackupFileSnapshot:
    """Hash/copy one source payload through a stable, descriptor-rooted no-follow chain."""

    parent_descriptor = -1
    source_name: str | Path = path
    try:
        if source_root_descriptor is not None:
            if (
                path.is_absolute()
                or not path.parts
                or any(part in {"", ".", ".."} for part in path.parts)
            ):
                raise UnsafePathError("A descriptor-rooted source path was invalid.")
            parent_descriptor = os.dup(source_root_descriptor)
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            for component in path.parts[:-1]:
                child_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=parent_descriptor,
                )
                opened_directory = os.fstat(child_descriptor)
                if not stat.S_ISDIR(opened_directory.st_mode):
                    os.close(child_descriptor)
                    raise UnsafePathError(
                        "A descriptor-rooted source path traversed an unsafe directory."
                    )
                os.close(parent_descriptor)
                parent_descriptor = child_descriptor
            source_name = path.parts[-1]
            before = os.stat(
                source_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        else:
            before = path.lstat()
    except UnsafePathError:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        raise
    except (OSError, ValueError) as exc:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        raise SourceChangedError(
            "A selected encrypted source payload was unavailable. Preserve the incomplete output "
            "and retry from a completed, disconnected backup."
        ) from exc
    if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        raise UnsafePathError(
            "A selected encrypted source payload was not a regular file; refusing extraction."
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    destination_descriptor = -1
    digest = hashlib.sha256()
    byte_count = 0
    try:
        if parent_descriptor >= 0:
            descriptor = os.open(source_name, flags, dir_fd=parent_descriptor)
        else:
            descriptor = os.open(source_name, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_source_metadata(before, opened):
            raise SourceChangedError(
                "A selected encrypted source payload changed while it was opened. Preserve the "
                "incomplete output and retry from a completed, disconnected backup."
            )
        if snapshot_destination is not None:
            secure_directory(snapshot_destination.parent)
            destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            destination_flags |= (
                getattr(os, "O_BINARY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            destination_descriptor = os.open(snapshot_destination, destination_flags, 0o600)
            harden_private_descriptor(
                destination_descriptor,
                expected_type=stat.S_IFREG,
                mode=0o600,
            )
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            byte_count += len(chunk)
            digest.update(chunk)
            if destination_descriptor >= 0:
                remaining = memoryview(chunk)
                while remaining:
                    written = os.write(destination_descriptor, remaining)
                    if written <= 0:
                        raise OSError("short encrypted snapshot write")
                    remaining = remaining[written:]
        after = os.fstat(descriptor)
        if destination_descriptor >= 0:
            os.fsync(destination_descriptor)
        if parent_descriptor >= 0:
            path_after = os.stat(
                source_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        else:
            path_after = path.lstat()
    except OSError as exc:
        if snapshot_destination is not None:
            with suppress(OSError):
                snapshot_destination.unlink()
        if is_insufficient_space_error(exc):
            raise insufficient_space_error() from exc
        raise SourceChangedError(
            "A selected encrypted source payload changed during verification. Preserve the "
            "incomplete output and retry from a completed, disconnected backup."
        ) from exc
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)

    if (
        _is_link_or_reparse(path_after)
        or not stat.S_ISREG(path_after.st_mode)
        or not _same_source_metadata(opened, after)
        or not _same_source_metadata(after, path_after)
        or byte_count != after.st_size
    ):
        raise SourceChangedError(
            "A selected encrypted source payload changed during verification. Preserve the "
            "incomplete output and retry from a completed, disconnected backup."
        )
    if snapshot_destination is not None:
        secure_file(snapshot_destination)
    return BackupFileSnapshot(
        mode=int(after.st_mode),
        size=int(after.st_size),
        modified_ns=int(after.st_mtime_ns),
        changed_ns=int(after.st_ctime_ns),
        device=int(after.st_dev),
        inode=int(after.st_ino),
        sha256=digest.hexdigest(),
    )


def _finished_status_state(
    path: Path,
    *,
    source_root_descriptor: int | None = None,
) -> BackupFileSnapshot:
    """Read and hash the exact Status.plist bytes that assert a finished snapshot."""

    try:
        if source_root_descriptor is not None:
            if path.is_absolute() or path.parts != (path.name,):
                raise BackupUnfinishedError("The descriptor-rooted backup status path was invalid.")
            before = os.stat(
                path.name,
                dir_fd=source_root_descriptor,
                follow_symlinks=False,
            )
        else:
            before = path.lstat()
    except OSError as exc:
        raise BackupUnfinishedError(
            "The backup has no trustworthy finished status. Let Finder or Apple Devices finish "
            "the encrypted backup, eject the phone, and retry."
        ) from exc
    if (
        _is_link_or_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > MAXIMUM_STATUS_PLIST_BYTES
    ):
        raise BackupUnfinishedError(
            "The backup status was not a bounded regular file. Use a completed, disconnected "
            "backup."
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    payload = bytearray()
    try:
        if source_root_descriptor is not None:
            descriptor = os.open(path.name, flags, dir_fd=source_root_descriptor)
        else:
            descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_source_metadata(before, opened):
            raise SourceChangedError(
                "The backup status changed while it was opened. Retry from a completed, "
                "disconnected backup."
            )
        while len(payload) <= MAXIMUM_STATUS_PLIST_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAXIMUM_STATUS_PLIST_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        after_open = os.fstat(descriptor)
    except OSError as exc:
        raise BackupUnfinishedError(
            "The backup status could not be read safely. Use a completed, disconnected backup."
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        value = plistlib.loads(bytes(payload))
    except plistlib.InvalidFileException as exc:
        raise BackupUnfinishedError(
            "The backup status could not be validated. Use a completed, disconnected backup."
        ) from exc
    if (
        not isinstance(value, dict)
        or str(value.get("SnapshotState") or "").strip().casefold() != "finished"
    ):
        raise BackupUnfinishedError(
            "The selected backup is not marked finished. Let Finder or Apple Devices finish the "
            "backup, then eject the phone before recovery."
        )
    try:
        if source_root_descriptor is not None:
            after = os.stat(
                path.name,
                dir_fd=source_root_descriptor,
                follow_symlinks=False,
            )
        else:
            after = path.lstat()
    except OSError as exc:
        raise SourceChangedError(
            "The backup status changed during verification. Retry from a completed, disconnected "
            "backup."
        ) from exc
    if (
        _is_link_or_reparse(after)
        or not stat.S_ISREG(after.st_mode)
        or not _same_source_metadata(opened, after_open)
        or not _same_source_metadata(after_open, after)
        or len(payload) != opened.st_size
        or len(payload) > MAXIMUM_STATUS_PLIST_BYTES
    ):
        raise SourceChangedError(
            "The backup status changed during verification. Retry from a completed, disconnected "
            "backup."
        )
    return BackupFileSnapshot(
        mode=int(opened.st_mode),
        size=int(opened.st_size),
        modified_ns=int(opened.st_mtime_ns),
        changed_ns=int(opened.st_ctime_ns),
        device=int(opened.st_dev),
        inode=int(opened.st_ino),
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _require_bound_backup_root(
    backup: Path,
    *,
    descriptor: int,
    expected_identity: tuple[int, int],
) -> None:
    """Require one held no-follow directory descriptor to remain the visible backup root."""

    try:
        opened = os.fstat(descriptor)
        visible = backup.lstat()
    except OSError as exc:
        raise SourceChangedError(
            "The selected backup root changed while recovery was preparing to use it."
        ) from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or _is_link_or_reparse(visible)
        or not stat.S_ISDIR(visible.st_mode)
        or (int(opened.st_dev), int(opened.st_ino)) != expected_identity
        or (int(visible.st_dev), int(visible.st_ino)) != expected_identity
    ):
        raise SourceChangedError(
            "The selected backup root changed while recovery was preparing to use it."
        )


@contextmanager
def _held_backup_root(
    backup_directory: Path,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> Any:
    """Hold one no-follow source-root descriptor for the complete extraction operation."""

    backup = validate_backup_directory(backup_directory)
    try:
        before = backup.lstat()
    except OSError as exc:
        raise SourceChangedError("The selected backup root could not be opened safely.") from exc
    if _is_link_or_reparse(before) or not stat.S_ISDIR(before.st_mode):
        raise UnsafePathError("The selected backup root was not a regular directory.")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(backup, flags)
        opened = os.fstat(descriptor)
        identity = (int(opened.st_dev), int(opened.st_ino))
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (int(before.st_dev), int(before.st_ino)) != identity
            or (expected_identity is not None and identity != expected_identity)
        ):
            raise SourceChangedError("The selected backup root changed while it was opened.")
        _require_bound_backup_root(
            backup,
            descriptor=descriptor,
            expected_identity=identity,
        )
        yield descriptor, identity, backup
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _capture_critical_backup_snapshot(
    backup: Path,
    *,
    source_root_descriptor: int,
    expected_source_root_identity: tuple[int, int],
) -> BackupPreflightSnapshot:
    _require_bound_backup_root(
        backup,
        descriptor=source_root_descriptor,
        expected_identity=expected_source_root_identity,
    )
    snapshot = BackupPreflightSnapshot(
        root_device=expected_source_root_identity[0],
        root_inode=expected_source_root_identity[1],
        manifest_plist=_source_payload_state(
            Path("Manifest.plist"),
            source_root_descriptor=source_root_descriptor,
        ),
        manifest_database=_source_payload_state(
            Path("Manifest.db"),
            source_root_descriptor=source_root_descriptor,
        ),
        status_plist=_finished_status_state(
            Path("Status.plist"),
            source_root_descriptor=source_root_descriptor,
        ),
    )
    _require_bound_backup_root(
        backup,
        descriptor=source_root_descriptor,
        expected_identity=expected_source_root_identity,
    )
    return snapshot


def _quiet_dependency_call(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Prevent the pinned dependency from printing private absolute paths."""

    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return function(*args, **kwargs)


def _remove_private_temp_tree(root: Path) -> None:
    """Remove a private tree without traversing links or Windows reparse points."""

    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        return
    if _is_link_or_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise OSError("The private temporary root was not a regular directory.")

    def remove_directory(directory: Path) -> None:
        with os.scandir(directory) as entries:
            for entry in entries:
                candidate = Path(entry.path)
                metadata = entry.stat(follow_symlinks=False)
                if _is_link_or_reparse(metadata):
                    try:
                        candidate.unlink()
                    except IsADirectoryError:
                        candidate.rmdir()
                elif stat.S_ISDIR(metadata.st_mode):
                    remove_directory(candidate)
                else:
                    candidate.unlink()
        directory.rmdir()

    remove_directory(root)


def _dispose_dependency(backup: Any, temp_root: Path, *, strict: bool) -> None:
    """Close the dependency explicitly, scrub secrets, and prove temporary data is gone."""

    close_failed = False
    unsafe_dependency_path = False
    connection = getattr(backup, "_temp_manifest_db_conn", None)
    if connection is not None:
        try:
            _quiet_dependency_call(connection.close)
        except Exception:
            close_failed = True
        with suppress(Exception):
            backup._temp_manifest_db_conn = None

    temporary_folder = getattr(backup, "_temporary_folder", "")
    try:
        dependency_temp = no_link_absolute_path(Path(str(temporary_folder)))
        dependency_temp.relative_to(no_link_absolute_path(temp_root))
    except (OSError, ValueError):
        unsafe_dependency_path = True
    else:
        cleanup = getattr(backup, "_cleanup", None)
        if callable(cleanup):
            with suppress(Exception):
                _quiet_dependency_call(cleanup)

    # iphone-backup-decrypt 0.9.0 has a non-idempotent __del__ that calls
    # self._cleanup() and prints the decrypted manifest path on a second call.
    # Neutralize only this already-disposed instance; no global monkey patching.
    with suppress(Exception):
        backup._cleanup = lambda: None
    for attribute in ("_passphrase", "_keybag", "_manifest_plist"):
        with suppress(Exception):
            setattr(backup, attribute, None)

    removal_failed = False
    try:
        _remove_private_temp_tree(temp_root)
    except Exception:
        removal_failed = True
    if temp_root.exists() or temp_root.is_symlink():
        removal_failed = True
    if strict and (close_failed or unsafe_dependency_path or removal_failed):
        raise TVTimeError(
            "Temporary decrypted recovery data could not be removed safely. Recovery remains "
            "incomplete; keep the destination private and retry into a fresh folder."
        )


@contextmanager
def _anchored_dependency_temporary_directories(temp_root: Path):
    """Keep the decryption dependency's temporary tree relative to the held cwd."""

    original_mkdtemp = tempfile.mkdtemp

    def relative_mkdtemp(
        suffix: str | None = None,
        prefix: str | None = None,
        dir: str | None = None,
    ) -> str:
        if any(value is not None and not isinstance(value, str) for value in (suffix, prefix, dir)):
            raise UnsafePathError("The recovery dependency requested an unsafe temporary path.")
        parent = temp_root if dir is None else no_link_absolute_path(Path(dir))
        trusted_temp_root = no_link_absolute_path(temp_root)
        try:
            parent.relative_to(trusted_temp_root)
        except ValueError as exc:
            raise UnsafePathError(
                "The recovery dependency requested temporary storage outside the private run."
            ) from exc
        for _attempt in range(128):
            name = f"{prefix or 'tmp'}{secrets.token_hex(16)}{suffix or ''}"
            candidate = safe_join(parent, name)
            try:
                candidate.mkdir(mode=0o700)
            except FileExistsError:
                continue
            secure_directory(candidate)
            return str(candidate)
        raise UnsafePathError("A private dependency temporary directory could not be allocated.")

    tempfile.mkdtemp = relative_mkdtemp
    try:
        yield
    finally:
        tempfile.mkdtemp = original_mkdtemp


def read_backup_password(*, password_stdin: bool) -> str:
    if password_stdin:
        passphrase = sys.stdin.readline().rstrip("\r\n")
    else:
        try:
            passphrase = getpass.getpass("Encrypted iOS backup password: ")
        except (EOFError, KeyboardInterrupt) as exc:
            raise UserInputError("No backup password was supplied.") from exc
    if not passphrase:
        raise UserInputError("No backup password was supplied.")
    return passphrase


def _load_decryption_dependency() -> tuple[type[Any], type[Any]]:
    try:
        from iphone_backup_decrypt import EncryptedBackup
        from iphone_backup_decrypt.utils import FilePlist
    except ModuleNotFoundError as exc:
        raise TVTimeError(
            "iphone-backup-decrypt is not installed. Run the installation step from README.md."
        ) from exc
    return EncryptedBackup, FilePlist


def _iso_mtime(value: object) -> str:
    if not isinstance(value, (int, float)) or not value:
        return ""
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int]:
    return int(metadata.st_dev), int(metadata.st_ino)


def _require_single_link_private_staging(
    path: Path,
    descriptor: int,
    *,
    expected_identity: tuple[int, int],
) -> os.stat_result:
    """Bind a visible private staging name to one held regular-file descriptor."""

    descriptor_metadata = require_private_descriptor(
        descriptor,
        expected_type=stat.S_IFREG,
        expected_mode=0o600,
    )
    if (
        _metadata_identity(descriptor_metadata) != expected_identity
        or int(descriptor_metadata.st_nlink) != 1
    ):
        raise UnsafePathError("The private staging descriptor identity changed while in use.")
    try:
        visible_metadata = path.lstat()
    except OSError as exc:
        raise UnsafePathError("The private staging file was no longer visible safely.") from exc
    if (
        _is_link_or_reparse(visible_metadata)
        or not stat.S_ISREG(visible_metadata.st_mode)
        or _metadata_identity(visible_metadata) != expected_identity
        or int(visible_metadata.st_nlink) != 1
    ):
        raise UnsafePathError("The private staging file identity changed while in use.")
    return descriptor_metadata


def _create_private_staging_descriptor(path: Path) -> tuple[int, tuple[int, int]]:
    """Create a private plaintext staging inode and keep it open until promotion."""

    if os.name == "nt" or not (sys.platform == "darwin" or sys.platform.startswith("linux")):
        raise UnsafePathError("Descriptor-bound dependency output is unsupported on this platform.")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = harden_private_descriptor(
            descriptor,
            expected_type=stat.S_IFREG,
            mode=0o600,
        )
        identity = _metadata_identity(metadata)
        _require_single_link_private_staging(
            path,
            descriptor,
            expected_identity=identity,
        )
        return descriptor, identity
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _verified_dependency_output_alias(
    path: Path,
    descriptor: int,
    *,
    expected_identity: tuple[int, int],
) -> str:
    """Return a kernel descriptor alias that the path-only dependency can safely open."""

    _require_single_link_private_staging(
        path,
        descriptor,
        expected_identity=expected_identity,
    )
    if sys.platform == "darwin":
        candidates = (f"/dev/fd/{descriptor}",)
    elif sys.platform.startswith("linux"):
        candidates = (f"/proc/self/fd/{descriptor}", f"/dev/fd/{descriptor}")
    else:
        candidates = ()

    verification_flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    for alias in candidates:
        alias_descriptor = -1
        try:
            alias_metadata = os.stat(alias)
            alias_descriptor = os.open(alias, verification_flags)
            opened_metadata = os.fstat(alias_descriptor)
        except OSError:
            continue
        finally:
            if alias_descriptor >= 0:
                os.close(alias_descriptor)
        if (
            stat.S_ISREG(alias_metadata.st_mode)
            and stat.S_ISREG(opened_metadata.st_mode)
            and _metadata_identity(opened_metadata) == expected_identity
            and int(opened_metadata.st_nlink) == 1
        ):
            _require_single_link_private_staging(
                path,
                descriptor,
                expected_identity=expected_identity,
            )
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            return alias
    raise UnsafePathError(
        "A verified descriptor alias was unavailable for private dependency output."
    )


def _harden_private_staging_descriptor(
    path: Path,
    descriptor: int,
    *,
    expected_identity: tuple[int, int],
) -> os.stat_result:
    metadata = harden_private_descriptor(
        descriptor,
        expected_type=stat.S_IFREG,
        mode=0o600,
    )
    if _metadata_identity(metadata) != expected_identity or int(metadata.st_nlink) != 1:
        raise UnsafePathError("The private staging descriptor identity changed while in use.")
    return _require_single_link_private_staging(
        path,
        descriptor,
        expected_identity=expected_identity,
    )


def _restore_descriptor_timestamp(descriptor: int, value: object) -> None:
    if isinstance(value, (int, float)) and value:
        if os.utime not in os.supports_fd:
            return
        os.utime(descriptor, (value, value))


def _sha256_staging_descriptor(
    path: Path,
    descriptor: int,
    *,
    expected_identity: tuple[int, int],
) -> tuple[int, str]:
    """Hash the held staging inode and reject concurrent mutation or name substitution."""

    before = _require_single_link_private_staging(
        path,
        descriptor,
        expected_identity=expected_identity,
    )
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    after = _require_single_link_private_staging(
        path,
        descriptor,
        expected_identity=expected_identity,
    )
    if not _same_source_metadata(before, after) or offset != int(after.st_size):
        raise UnsafePathError("The private staging file changed while it was verified.")
    return offset, digest.hexdigest()


def _bounded_manifest_cell_size(value: object) -> int:
    """Measure only the small, known SQLite/FilePlist value shapes without recursion."""

    total = 0
    pending = [value]
    visited_containers: set[int] = set()
    visited_values = 0
    while pending:
        item = pending.pop()
        visited_values += 1
        if visited_values > 4_096:
            raise TVTimeError("The backup manifest contained an oversized metadata value.")
        if item is None or isinstance(item, (bool, int, float)):
            total += 16
        elif isinstance(item, str):
            total += len(item.encode("utf-8"))
        elif isinstance(item, (bytes, bytearray, memoryview)):
            total += len(item)
        elif isinstance(item, dict):
            identity = id(item)
            if identity in visited_containers:
                raise TVTimeError("The backup manifest contained cyclic metadata.")
            visited_containers.add(identity)
            if len(item) > 512:
                raise TVTimeError("The backup manifest contained an oversized metadata value.")
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise TVTimeError("The backup manifest contained an invalid metadata key.")
                pending.extend((key, nested))
        elif isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in visited_containers:
                raise TVTimeError("The backup manifest contained cyclic metadata.")
            visited_containers.add(identity)
            if len(item) > 512:
                raise TVTimeError("The backup manifest contained an oversized metadata value.")
            pending.extend(item)
        else:
            raise TVTimeError("The backup manifest contained an unsupported metadata value.")
        if total > MAXIMUM_MANIFEST_CELL_BYTES:
            raise TVTimeError("The backup manifest contained an oversized metadata value.")
    return total


def _bounded_manifest_rows(
    cursor: Any,
    *,
    expected_columns: int,
    maximum_rows: int,
    validate_row: Callable[[tuple[Any, ...]], None],
) -> list[tuple[Any, ...]]:
    fetchmany = getattr(cursor, "fetchmany", None)
    if not callable(fetchmany):
        raise TVTimeError("The backup manifest cursor did not support bounded reads.")
    result: list[tuple[Any, ...]] = []
    combined_bytes = 0
    while True:
        batch = fetchmany(_MANIFEST_FETCH_BATCH_ROWS)
        if not isinstance(batch, (list, tuple)) or len(batch) > _MANIFEST_FETCH_BATCH_ROWS:
            raise TVTimeError("The backup manifest cursor returned an invalid bounded batch.")
        if not batch:
            break
        for raw_row in batch:
            if not isinstance(raw_row, (list, tuple)) or len(raw_row) != expected_columns:
                raise TVTimeError("The backup manifest contained an invalid row shape.")
            row = tuple(raw_row)
            validate_row(row)
            row_bytes = sum(_bounded_manifest_cell_size(cell) for cell in row)
            combined_bytes += row_bytes
            if combined_bytes > MAXIMUM_MANIFEST_COMBINED_BYTES:
                raise TVTimeError("The selected backup manifest exceeded its safe byte limit.")
            result.append(row)
            if len(result) > maximum_rows:
                raise TVTimeError("The selected backup manifest exceeded its safe row limit.")
    return result


def _query_domains(backup: Any) -> list[str]:
    try:
        with backup.manifest_db_cursor() as cursor:
            cursor.execute(
                """
                SELECT DISTINCT domain
                FROM Files
                WHERE domain = ?
                   OR domain LIKE ?
                ORDER BY domain
                """,
                (PRIMARY_DOMAIN, f"{RELATED_PLUGIN_DOMAIN_PREFIX}%"),
            )

            def validate_domain_row(row: tuple[Any, ...]) -> None:
                if not isinstance(row[0], str):
                    raise TVTimeError("The backup manifest contained an invalid domain type.")

            rows = _bounded_manifest_rows(
                cursor,
                expected_columns=1,
                maximum_rows=MAXIMUM_MANIFEST_DOMAIN_ROWS,
                validate_row=validate_domain_row,
            )
            domain_values = [row[0] for row in rows]
    except Exception as exc:
        raise TVTimeError(DEPENDENCY_FAILURE_MESSAGE) from exc
    if any(not isinstance(domain, str) for domain in domain_values):
        raise TVTimeError("The backup manifest contained an invalid TV Time domain type.")
    domains = list(domain_values)
    for domain in domains:
        safe_domain_component(domain)
    if PRIMARY_DOMAIN not in domains:
        raise AppDataMissingError(
            "The TV Time app domain was not present in the selected backup. Choose a completed "
            "backup made after TV Time stored data on the device."
        )
    return domains


def _query_files(backup: Any, domains: list[str]) -> list[tuple[Any, ...]]:
    placeholders = ",".join("?" for _ in domains)
    with backup.manifest_db_cursor() as cursor:
        cursor.execute(
            f"""
            SELECT fileID, domain, relativePath, file
            FROM Files
            WHERE flags = 1 AND domain IN ({placeholders})
            ORDER BY domain, relativePath
            """,
            domains,
        )

        def validate_file_row(row: tuple[Any, ...]) -> None:
            if not isinstance(row[0], str):
                raise TVTimeError("A selected backup file had an invalid file identifier type.")
            if not isinstance(row[1], str):
                raise TVTimeError("A selected backup file had an invalid domain type.")
            if not isinstance(row[2], str):
                raise TVTimeError("A selected backup file had an invalid relative path type.")
            if not isinstance(row[3], (bytes, bytearray, memoryview, dict)):
                raise TVTimeError("The backup manifest contained invalid selected-file metadata.")

        return _bounded_manifest_rows(
            cursor,
            expected_columns=4,
            maximum_rows=MAXIMUM_MANIFEST_FILE_ROWS,
            validate_row=validate_file_row,
        )


def _extract_one_file(
    *,
    backup: Any,
    file_plist_factory: Callable[[Any], Any],
    layout: ExtractionLayout,
    file_id_value: object,
    domain_value: object,
    relative_path_value: object,
    file_bplist: Any,
    source_path: Path | None,
    expected_source_state: BackupFileSnapshot | None,
    source_root_descriptor: int,
) -> dict[str, Any]:
    if not isinstance(file_id_value, str):
        raise ValueError("A selected backup file had an invalid file identifier type")
    if not isinstance(domain_value, str):
        raise ValueError("A selected backup file had an invalid domain type")
    if not isinstance(relative_path_value, str):
        raise ValueError("A selected backup file had an invalid relative path type")
    file_id = validate_file_id(file_id_value)
    domain = safe_domain_component(domain_value)
    relative_path = relative_path_value
    relative = safe_manifest_relative_path(relative_path)
    domain_root = secure_directory(safe_join(layout.raw_root, domain))
    target = safe_join(domain_root, relative)
    secure_directory(target.parent)
    if target.exists() or target.is_symlink():
        raise ValueError(f"Refusing to overwrite extracted file: {relative_path}")

    staging = safe_join(layout.temp_root, f"{file_id}.partial")
    if staging.exists() or staging.is_symlink():
        raise ValueError(f"Refusing to overwrite quarantined partial file: {file_id}")

    file_plist = file_plist_factory(file_bplist)
    declared_size = file_plist.filesize
    if not isinstance(declared_size, int) or isinstance(declared_size, bool):
        raise ValueError("A selected backup file had an invalid declared size type")
    if declared_size < 0:
        raise ValueError("A selected backup file had an invalid negative declared size")
    encrypted_snapshot: Path | None = None
    staging_descriptor = -1
    staging_identity: tuple[int, int] | None = None
    try:
        if declared_size == 0:
            staging_descriptor, staging_identity = _create_private_staging_descriptor(staging)
        else:
            if source_path is None or expected_source_state is None:
                raise ValueError("A non-empty selected backup file had no verified source payload")
            if file_plist.encryption_key is None:
                raise ValueError("A non-empty encrypted file had no wrapped encryption key")
            key = backup._keybag.unwrapKeyForClass(
                file_plist.protection_class,
                file_plist.encryption_key,
            )
            snapshot_root = secure_directory(safe_join(layout.temp_root, "encrypted-source"))
            encrypted_snapshot = safe_join(snapshot_root, file_id[:2], file_id)
            copied_state = _source_payload_state(
                source_path,
                snapshot_destination=encrypted_snapshot,
                source_root_descriptor=source_root_descriptor,
            )
            if copied_state != expected_source_state:
                raise SourceChangedError(
                    "A selected encrypted source payload changed before decryption. Preserve the "
                    "incomplete output and retry from a completed, disconnected backup."
                )
            snapshot_state = _source_payload_state(encrypted_snapshot)
            if not snapshot_state.same_content(expected_source_state):
                raise SourceChangedError(
                    "A selected encrypted source snapshot could not be verified. Preserve the "
                    "incomplete output and retry from a completed, disconnected backup."
                )

            # The pinned dependency accepts only a path. Keep the exact private
            # staging inode open and expose only a kernel descriptor alias, never
            # its replaceable visible pathname.
            staging_descriptor, staging_identity = _create_private_staging_descriptor(staging)
            dependency_output = _verified_dependency_output_alias(
                staging,
                staging_descriptor,
                expected_identity=staging_identity,
            )

            missing = object()
            previous_backup_directory = getattr(backup, "_backup_directory", missing)
            backup._backup_directory = str(snapshot_root)
            # The pinned dependency prints absolute output paths in size warnings.
            # Capture that output because this function independently records the
            # declared and actual sizes in the private inventory.
            try:
                with redirect_stdout(io.StringIO()):
                    backup._decrypt_file_to_disk(
                        file_id=file_id,
                        key=key,
                        file_plist=file_plist,
                        output_filepath=dependency_output,
                    )
            finally:
                if previous_backup_directory is missing:
                    with suppress(AttributeError):
                        del backup._backup_directory
                else:
                    backup._backup_directory = previous_backup_directory
            if not _source_payload_state(encrypted_snapshot).same_content(snapshot_state):
                raise SourceChangedError(
                    "A selected encrypted source snapshot changed during decryption. Preserve the "
                    "incomplete output and retry from a completed, disconnected backup."
                )
        if staging_descriptor < 0 or staging_identity is None:
            raise UnsafePathError("A private decryption staging descriptor was unavailable.")
        _harden_private_staging_descriptor(
            staging,
            staging_descriptor,
            expected_identity=staging_identity,
        )
        _restore_descriptor_timestamp(staging_descriptor, file_plist.mtime)
        os.fsync(staging_descriptor)
        actual_size, staging_sha256 = _sha256_staging_descriptor(
            staging,
            staging_descriptor,
            expected_identity=staging_identity,
        )
        inventory_row = {
            "file_id": file_id,
            "domain": domain,
            "relative_path": relative_path,
            "declared_size": declared_size,
            "actual_size": actual_size,
            "size_match": actual_size == declared_size,
            "mtime": _iso_mtime(file_plist.mtime),
            "sha256": staging_sha256,
        }
        promote_file_no_replace_atomic(
            staging,
            target,
            expected_identity=staging_identity,
            durable=True,
        )
        _require_single_link_private_staging(
            target,
            staging_descriptor,
            expected_identity=staging_identity,
        )
        return inventory_row
    except Exception:
        # A dependency can leave a truncated file after ENOSPC or another
        # mid-copy failure. Preserve it only beneath the private .tmp directory;
        # never risk unlinking a concurrently substituted pathname and never
        # promote it into the recovered raw tree.
        raise
    finally:
        if staging_descriptor >= 0:
            os.close(staging_descriptor)
        if encrypted_snapshot is not None:
            with suppress(OSError):
                encrypted_snapshot.unlink()


def _extract_backup(
    *,
    backup_directory: Path,
    output_directory: Path,
    passphrase: str,
    include_decrypted_manifest: bool = False,
    output_root_is_anchored: bool = False,
    source_root_descriptor: int,
    expected_source_root_identity: tuple[int, int],
    expected_backup_snapshot: BackupPreflightSnapshot | None = None,
    dependency_loader: Callable[[], tuple[type[Any], type[Any]]] = _load_decryption_dependency,
    progress_callback: Callable[[int, int], None] | None = None,
    cancellation_check: Callable[[], None] | None = None,
) -> ExtractionResult:
    """Extract TV Time files from an encrypted local iOS backup."""

    set_private_umask()
    encrypted_backup_factory, file_plist_factory = dependency_loader()
    source_backup = validate_backup_directory(backup_directory)
    source_manifest_snapshot = _capture_critical_backup_snapshot(
        source_backup,
        source_root_descriptor=source_root_descriptor,
        expected_source_root_identity=expected_source_root_identity,
    )
    if (
        expected_backup_snapshot is not None
        and source_manifest_snapshot != expected_backup_snapshot
    ):
        raise SourceChangedError(
            "The selected backup metadata changed after preflight. No plaintext was written."
        )
    if output_root_is_anchored:
        layout = prepare_anchored_extraction_layout(source_backup, output_directory)
    else:
        layout = prepare_extraction_layout(source_backup, output_directory)
    run_state_path = layout.metadata_root / "run_state.json"
    write_json_private_atomic(
        run_state_path,
        {
            "schema_version": EXTRACTION_RUN_STATE_SCHEMA_VERSION,
            "contract": EXTRACTION_RUN_STATE_CONTRACT,
            "status": "incomplete",
            "message": "Extraction did not reach its safe completion checkpoint.",
        },
    )

    previous_tmpdir = os.environ.get("TMPDIR")
    previous_tempdir = tempfile.tempdir
    os.environ["TMPDIR"] = str(layout.temp_root)
    tempfile.tempdir = str(layout.temp_root)
    temporary_contexts = ExitStack()
    backup: Any | None = None
    try:
        if output_root_is_anchored:
            temporary_contexts.enter_context(
                _anchored_dependency_temporary_directories(layout.temp_root)
            )
        if cancellation_check is not None:
            cancellation_check()
        control_sources = {
            "Manifest.plist": source_manifest_snapshot.manifest_plist,
            "Manifest.db": source_manifest_snapshot.manifest_database,
            "Status.plist": source_manifest_snapshot.status_plist,
        }
        control_bytes = sum(state.size for state in control_sources.values())
        control_headroom = max(64 * 1024 * 1024, control_bytes // 10)
        required_control_space = (
            control_bytes + source_manifest_snapshot.manifest_database.size + control_headroom
        )
        if shutil.disk_usage(layout.output_root).free < required_control_space:
            raise insufficient_space_error()
        dependency_source_root = secure_directory(
            safe_join(layout.temp_root, "encrypted-control-snapshot")
        )
        for name, expected_state in control_sources.items():
            snapshot_path = safe_join(dependency_source_root, name)
            copied_state = _source_payload_state(
                Path(name),
                snapshot_destination=snapshot_path,
                source_root_descriptor=source_root_descriptor,
            )
            snapshot_state = _source_payload_state(snapshot_path)
            if copied_state != expected_state or not snapshot_state.same_content(expected_state):
                raise SourceChangedError(
                    "The encrypted backup control files changed before dependency use. Preserve "
                    "the incomplete output and retry from a completed, disconnected backup."
                )
        try:
            backup = _quiet_dependency_call(
                encrypted_backup_factory,
                backup_directory=str(dependency_source_root),
                passphrase=passphrase,
            )
        except OSError as exc:
            if is_insufficient_space_error(exc):
                raise insufficient_space_error() from exc
            raise TVTimeError(DEPENDENCY_FAILURE_MESSAGE) from exc
        except Exception as exc:
            raise TVTimeError(DEPENDENCY_FAILURE_MESSAGE) from exc
        try:
            _quiet_dependency_call(backup.test_decryption)
        except ValueError as exc:
            if str(exc) == "Failed to decrypt keys: incorrect passphrase?":
                raise BackupPasswordError(
                    "Extraction failed: the encrypted backup could not be unlocked with the "
                    "supplied password."
                ) from exc
            raise TVTimeError(DEPENDENCY_FAILURE_MESSAGE) from exc
        except Exception as exc:
            raise TVTimeError(DEPENDENCY_FAILURE_MESSAGE) from exc

        domains = _quiet_dependency_call(_query_domains, backup)
        rows = _quiet_dependency_call(_query_files, backup, domains)
        selected_declared_bytes = 0
        selected_source_states: dict[str, BackupFileSnapshot] = {}
        selected_source_paths: dict[str, Path] = {}
        for file_id_value, domain_value, relative_path_value, file_bplist in rows:
            if cancellation_check is not None:
                cancellation_check()
            if not isinstance(file_id_value, str):
                raise TVTimeError(
                    "A selected backup file had an invalid file identifier type. Preserve the "
                    "completed backup and try a newer extractor release."
                )
            if not isinstance(domain_value, str):
                raise TVTimeError(
                    "A selected backup file had an invalid domain type. Preserve the completed "
                    "backup and try a newer extractor release."
                )
            if not isinstance(relative_path_value, str):
                raise TVTimeError(
                    "A selected backup file had an invalid relative path type. Preserve the "
                    "completed backup and try a newer extractor release."
                )
            try:
                file_id = validate_file_id(file_id_value)
                safe_domain_component(domain_value)
                declared_size = file_plist_factory(file_bplist).filesize
            except Exception as exc:
                raise TVTimeError(
                    "A selected backup file had invalid manifest metadata. Preserve the "
                    "completed backup and try a newer extractor release."
                ) from exc
            if not isinstance(declared_size, int) or isinstance(declared_size, bool):
                raise TVTimeError(
                    "A selected backup file had an invalid declared size type. Preserve the "
                    "completed backup and try a newer extractor release."
                )
            if declared_size < 0:
                raise TVTimeError(
                    "A selected backup file had an invalid negative declared size. Preserve the "
                    "completed backup and try a newer extractor release."
                )
            selected_declared_bytes += declared_size
            if declared_size and file_id not in selected_source_states:
                try:
                    source_path = Path(file_id[:2], file_id)
                except ValueError as exc:
                    raise UnsafePathError(
                        "A selected encrypted source payload had an unsafe path."
                    ) from exc
                selected_source_paths[file_id] = source_path
                selected_source_states[file_id] = _source_payload_state(
                    source_path,
                    source_root_descriptor=source_root_descriptor,
                )
        free_bytes = shutil.disk_usage(layout.output_root).free
        required_headroom = max(64 * 1024 * 1024, selected_declared_bytes // 10)
        largest_encrypted_snapshot = max(
            (state.size for state in selected_source_states.values()),
            default=0,
        )
        retained_manifest_bytes = (
            source_manifest_snapshot.manifest_database.size if include_decrypted_manifest else 0
        )
        if free_bytes < (
            selected_declared_bytes
            + retained_manifest_bytes
            + largest_encrypted_snapshot
            + required_headroom
        ):
            raise insufficient_space_error()

        manifest_sha256 = ""
        if include_decrypted_manifest:
            decrypted_manifest = layout.manifest_root / "Manifest.decrypted.db"
            staged_manifest = safe_join(layout.temp_root, "Manifest.decrypted.db.partial")
            manifest_descriptor = -1
            try:
                manifest_descriptor, staged_manifest_identity = _create_private_staging_descriptor(
                    staged_manifest
                )
                dependency_manifest_output = _verified_dependency_output_alias(
                    staged_manifest,
                    manifest_descriptor,
                    expected_identity=staged_manifest_identity,
                )
                _quiet_dependency_call(
                    backup.save_manifest_file,
                    dependency_manifest_output,
                )
                _harden_private_staging_descriptor(
                    staged_manifest,
                    manifest_descriptor,
                    expected_identity=staged_manifest_identity,
                )
                os.fsync(manifest_descriptor)
                _, manifest_sha256 = _sha256_staging_descriptor(
                    staged_manifest,
                    manifest_descriptor,
                    expected_identity=staged_manifest_identity,
                )
                promote_file_no_replace_atomic(
                    staged_manifest,
                    decrypted_manifest,
                    expected_identity=staged_manifest_identity,
                    durable=True,
                )
                _require_single_link_private_staging(
                    decrypted_manifest,
                    manifest_descriptor,
                    expected_identity=staged_manifest_identity,
                )
            finally:
                if manifest_descriptor >= 0:
                    os.close(manifest_descriptor)

        if cancellation_check is not None:
            cancellation_check()

        remaining_free_bytes = shutil.disk_usage(layout.output_root).free
        if remaining_free_bytes < (
            selected_declared_bytes + largest_encrypted_snapshot + required_headroom
        ):
            raise insufficient_space_error()

        inventory: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        for index, (file_id, domain, relative_path, file_bplist) in enumerate(rows, 1):
            if cancellation_check is not None:
                cancellation_check()
            try:
                inventory.append(
                    _extract_one_file(
                        backup=backup,
                        file_plist_factory=file_plist_factory,
                        layout=layout,
                        file_id_value=file_id,
                        domain_value=domain,
                        relative_path_value=relative_path,
                        file_bplist=file_bplist,
                        source_path=selected_source_paths.get(str(file_id).lower()),
                        expected_source_state=selected_source_states.get(str(file_id).lower()),
                        source_root_descriptor=source_root_descriptor,
                    )
                )
            except OSError as exc:
                if is_insufficient_space_error(exc):
                    raise insufficient_space_error() from exc
                failures.append(
                    {
                        "file_id": str(file_id),
                        "domain": str(domain),
                        "relative_path": str(relative_path),
                        "error": DEPENDENCY_FILE_FAILURE_MESSAGE,
                    }
                )
            except Exception:  # keep a complete private failure inventory
                failures.append(
                    {
                        "file_id": str(file_id),
                        "domain": str(domain),
                        "relative_path": str(relative_path),
                        "error": DEPENDENCY_FILE_FAILURE_MESSAGE,
                    }
                )
            if progress_callback is not None:
                progress_callback(index, len(rows))

        write_csv_private(
            layout.metadata_root / "inventory.csv",
            inventory,
            [
                "file_id",
                "domain",
                "relative_path",
                "declared_size",
                "actual_size",
                "size_match",
                "mtime",
                "sha256",
            ],
            spreadsheet_safe=False,
        )
        discrepancies = [
            {
                "domain": row["domain"],
                "relative_path": row["relative_path"],
                "declared_size": row["declared_size"],
                "actual_size": row["actual_size"],
            }
            for row in inventory
            if not row["size_match"]
        ]
        current_manifest_snapshot = _capture_critical_backup_snapshot(
            source_backup,
            source_root_descriptor=source_root_descriptor,
            expected_source_root_identity=expected_source_root_identity,
        )
        if current_manifest_snapshot != source_manifest_snapshot:
            raise SourceChangedError(
                "The backup manifest changed during extraction. Preserve this incomplete output, "
                "wait for the backup to finish, and retry into a new destination."
            )
        for file_id, expected_state in selected_source_states.items():
            try:
                current_source_path = Path(file_id[:2], file_id)
            except ValueError as exc:
                raise SourceChangedError(
                    "A selected encrypted source payload changed path during extraction. Preserve "
                    "this incomplete output and retry from a completed, disconnected backup."
                ) from exc
            current_state = _source_payload_state(
                current_source_path,
                source_root_descriptor=source_root_descriptor,
            )
            if current_state != expected_state:
                raise SourceChangedError(
                    "A selected encrypted source payload changed during extraction. Preserve this "
                    "incomplete output and retry from a completed, disconnected backup."
                )

        _dispose_dependency(backup, layout.temp_root, strict=True)
        backup = None
        source_snapshot: SourceSnapshot | None = None
        if not failures:
            source_snapshot = reconcile_raw_tree(
                layout.extraction_root,
                cancellation_check=cancellation_check,
            )
        finished_utc = datetime.now(timezone.utc).isoformat()
        summary: dict[str, Any] = {
            "bundle_id": TVTIME_BUNDLE_ID,
            "domains": domains,
            "files_expected": len(rows),
            "files_extracted": len(inventory),
            "failures": failures,
            "bytes_extracted": sum(int(row["actual_size"]) for row in inventory),
            "selected_declared_bytes": selected_declared_bytes,
            "size_discrepancies": discrepancies,
            "decrypted_manifest_included": include_decrypted_manifest,
        }
        if failures:
            summary["failed_utc"] = finished_utc
        else:
            summary["completed_utc"] = finished_utc
        if manifest_sha256:
            summary["manifest_sha256"] = manifest_sha256
        write_json_private_atomic(layout.metadata_root / "summary.json", summary)
        write_text_private(layout.metadata_root / "domains.txt", "\n".join(domains) + "\n")
        if not failures:
            # Bind the completion marker to the same exact finished Status.plist
            # snapshot checked at extraction start, immediately before promotion.
            def revalidate_finished_status() -> None:
                try:
                    current_status = _finished_status_state(
                        Path("Status.plist"),
                        source_root_descriptor=source_root_descriptor,
                    )
                except BackupUnfinishedError as exc:
                    raise SourceChangedError(
                        "The backup completion status changed during extraction. Preserve this "
                        "incomplete output and retry from a completed, disconnected backup."
                    ) from exc
                if current_status != source_manifest_snapshot.status_plist:
                    raise SourceChangedError(
                        "The backup completion status changed during extraction. Preserve this "
                        "incomplete output and retry from a completed, disconnected backup."
                    )
                if source_snapshot is None:
                    raise SourceChangedError(
                        "The extracted source snapshot was not available at completion. Preserve "
                        "this incomplete output and retry from a completed, disconnected backup."
                    )
                reconcile_raw_tree(
                    layout.extraction_root,
                    expected=source_snapshot,
                    cancellation_check=cancellation_check,
                )
                _require_bound_backup_root(
                    source_backup,
                    descriptor=source_root_descriptor,
                    expected_identity=expected_source_root_identity,
                )

            write_json_private_atomic(
                run_state_path,
                {
                    "schema_version": EXTRACTION_RUN_STATE_SCHEMA_VERSION,
                    "contract": EXTRACTION_RUN_STATE_CONTRACT,
                    "status": "complete",
                    "completed_utc": finished_utc,
                    "files_expected": len(rows),
                    "files_extracted": len(inventory),
                    "bytes_extracted": summary["bytes_extracted"],
                    "selected_declared_bytes": selected_declared_bytes,
                    "size_discrepancy_count": len(discrepancies),
                    "source_snapshot": source_snapshot.as_dict(),
                },
                before_replace=revalidate_finished_status,
            )
        return ExtractionResult(extraction_root=layout.extraction_root, summary=summary)
    except TVTimeError:
        raise
    except OSError as exc:
        if is_insufficient_space_error(exc):
            raise insufficient_space_error() from exc
        raise TVTimeError(f"Extraction failed safely: {type(exc).__name__}.") from exc
    except Exception as exc:
        raise TVTimeError(DEPENDENCY_FAILURE_MESSAGE) from exc
    finally:
        if backup is not None:
            with suppress(Exception):
                _dispose_dependency(backup, layout.temp_root, strict=False)
            backup = None
        else:
            with suppress(Exception):
                _remove_private_temp_tree(layout.temp_root)
        temporary_contexts.close()
        tempfile.tempdir = previous_tempdir
        if previous_tmpdir is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = previous_tmpdir


def extract_backup(
    *,
    backup_directory: Path,
    output_directory: Path,
    passphrase: str,
    include_decrypted_manifest: bool = False,
    output_root_is_anchored: bool = False,
    destination_parent_descriptor: int | None = None,
    expected_destination_parent_identity: tuple[int, int] | None = None,
    source_root_descriptor: int | None = None,
    expected_source_root_identity: tuple[int, int] | None = None,
    expected_backup_snapshot: BackupPreflightSnapshot | None = None,
    dependency_loader: Callable[[], tuple[type[Any], type[Any]]] = _load_decryption_dependency,
    progress_callback: Callable[[int, int], None] | None = None,
    cancellation_check: Callable[[], None] | None = None,
) -> ExtractionResult:
    """Extract TV Time files and map storage exhaustion from every setup/write stage."""

    try:
        require_fresh_output_platform_support()
        if (source_root_descriptor is None) != (expected_source_root_identity is None):
            raise UnsafePathError("Source identity binding was incomplete.")
        if source_root_descriptor is None:
            expected_identity = None
            if expected_backup_snapshot is not None:
                expected_identity = (
                    expected_backup_snapshot.root_device,
                    expected_backup_snapshot.root_inode,
                )
            with _held_backup_root(
                backup_directory,
                expected_identity=expected_identity,
            ) as (root_descriptor, root_identity, visible_backup):
                return extract_backup(
                    backup_directory=visible_backup,
                    output_directory=output_directory,
                    passphrase=passphrase,
                    include_decrypted_manifest=include_decrypted_manifest,
                    output_root_is_anchored=output_root_is_anchored,
                    destination_parent_descriptor=destination_parent_descriptor,
                    expected_destination_parent_identity=expected_destination_parent_identity,
                    source_root_descriptor=root_descriptor,
                    expected_source_root_identity=root_identity,
                    expected_backup_snapshot=expected_backup_snapshot,
                    dependency_loader=dependency_loader,
                    progress_callback=progress_callback,
                    cancellation_check=cancellation_check,
                )
        if expected_backup_snapshot is not None and expected_source_root_identity != (
            expected_backup_snapshot.root_device,
            expected_backup_snapshot.root_inode,
        ):
            raise SourceChangedError("The selected backup root no longer matched preflight.")
        if (destination_parent_descriptor is None) != (
            expected_destination_parent_identity is None
        ):
            raise UnsafePathError("Destination identity binding was incomplete.")
        if destination_parent_descriptor is None and not output_root_is_anchored:
            with held_destination_parent(output_directory) as (
                parent_handle,
                parent_identity,
                visible_output,
            ):
                return extract_backup(
                    backup_directory=backup_directory,
                    output_directory=visible_output,
                    passphrase=passphrase,
                    include_decrypted_manifest=include_decrypted_manifest,
                    destination_parent_descriptor=parent_handle,
                    expected_destination_parent_identity=parent_identity,
                    source_root_descriptor=source_root_descriptor,
                    expected_source_root_identity=expected_source_root_identity,
                    expected_backup_snapshot=expected_backup_snapshot,
                    dependency_loader=dependency_loader,
                    progress_callback=progress_callback,
                    cancellation_check=cancellation_check,
                )
        if source_root_descriptor is None or expected_source_root_identity is None:
            raise UnsafePathError("Source identity binding was incomplete.")
        source_backup = validate_backup_directory(backup_directory)
        _require_bound_backup_root(
            source_backup,
            descriptor=source_root_descriptor,
            expected_identity=expected_source_root_identity,
        )
        bounded_status = _finished_status_state(
            Path("Status.plist"),
            source_root_descriptor=source_root_descriptor,
        )
        if (
            expected_backup_snapshot is not None
            and bounded_status != expected_backup_snapshot.status_plist
        ):
            raise SourceChangedError(
                "The selected backup status changed after preflight. No output was created."
            )
        try:
            loaded_dependency = dependency_loader()
        except TVTimeError as exc:
            if dependency_loader is _load_decryption_dependency:
                raise
            raise TVTimeError(DEPENDENCY_FAILURE_MESSAGE) from exc
        except Exception as exc:
            raise TVTimeError(DEPENDENCY_FAILURE_MESSAGE) from exc

        def bound_dependency_loader() -> tuple[type[Any], type[Any]]:
            return loaded_dependency

        if (
            destination_parent_descriptor is not None
            and expected_destination_parent_identity is not None
        ):
            if output_root_is_anchored:
                raise UnsafePathError(
                    "Anchored extraction received conflicting destination handles."
                )
            visible_output = no_link_absolute_path(output_directory)
            with anchored_bound_output_root(
                visible_output,
                destination_parent_descriptor=destination_parent_descriptor,
                expected_parent_identity=expected_destination_parent_identity,
            ) as bound_output:
                result = _extract_backup(
                    backup_directory=source_backup,
                    output_directory=bound_output,
                    passphrase=passphrase,
                    include_decrypted_manifest=include_decrypted_manifest,
                    output_root_is_anchored=True,
                    source_root_descriptor=source_root_descriptor,
                    expected_source_root_identity=expected_source_root_identity,
                    expected_backup_snapshot=expected_backup_snapshot,
                    dependency_loader=bound_dependency_loader,
                    progress_callback=progress_callback,
                    cancellation_check=cancellation_check,
                )
            return ExtractionResult(
                extraction_root=visible_output / result.extraction_root,
                summary=result.summary,
            )
        return _extract_backup(
            backup_directory=backup_directory,
            output_directory=output_directory,
            passphrase=passphrase,
            include_decrypted_manifest=include_decrypted_manifest,
            output_root_is_anchored=output_root_is_anchored,
            source_root_descriptor=source_root_descriptor,
            expected_source_root_identity=expected_source_root_identity,
            expected_backup_snapshot=expected_backup_snapshot,
            dependency_loader=bound_dependency_loader,
            progress_callback=progress_callback,
            cancellation_check=cancellation_check,
        )
    except OSError as exc:
        if is_insufficient_space_error(exc):
            raise insufficient_space_error() from exc
        raise TVTimeError(f"Extraction failed safely: {type(exc).__name__}.") from exc


def public_summary(result: ExtractionResult) -> dict[str, Any]:
    summary = result.summary
    return {
        "extraction_root": str(result.extraction_root),
        "files_expected": summary["files_expected"],
        "files_extracted": summary["files_extracted"],
        "failure_count": len(summary["failures"]),
        "size_discrepancy_count": len(summary["size_discrepancies"]),
        "selected_declared_bytes": summary["selected_declared_bytes"],
        "bytes_extracted": summary["bytes_extracted"],
        "decrypted_manifest_included": summary["decrypted_manifest_included"],
    }


def public_summary_json(result: ExtractionResult) -> str:
    return json.dumps(public_summary(result), indent=2, ensure_ascii=False)
