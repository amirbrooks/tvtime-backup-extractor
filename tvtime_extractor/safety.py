from __future__ import annotations

import csv
import ctypes
import errno
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, TextIO
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import windows_native as _windows_native
from .errors import OutputExistsError, PartialExtractionError, UnsafePathError, UserInputError
from .spreadsheet import spreadsheet_cell_needs_escape, spreadsheet_safe_cell

EXTRACTION_DIRECTORY_NAME = "TVTime-Extraction"
WINDOWS_INVALID_CHARACTERS = frozenset('<>:"|?*')
WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
)
FILE_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
EXTRACTION_RUN_STATE_SCHEMA_VERSION = 2
EXTRACTION_RUN_STATE_CONTRACT = "tvtime-extraction-run-state-v0.2"
MAXIMUM_COMPLETION_MARKER_BYTES = 64 * 1024
_DARWIN_ACL_TYPE_EXTENDED = 0x00000100
_DARWIN_ACL_FIRST_ENTRY = 0
_DARWIN_ACL_NEXT_ENTRY = -1
_DARWIN_ACL_ENTRY_INHERITED = 1 << 4
_DARWIN_ACL_LIBC: Any | None = None
_DARWIN_TRUSTED_ROOT_ALIASES = {
    Path("/etc"): Path("/private/etc"),
    Path("/tmp"): Path("/private/tmp"),
    Path("/var"): Path("/private/var"),
}
_DARWIN_MNT_LOCAL = 0x00001000
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_FILE_ATTRIBUTE_OFFLINE = 0x00001000
_WINDOWS_FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
_WINDOWS_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
_WINDOWS_CLOUD_HYDRATION_ATTRIBUTES = (
    _WINDOWS_FILE_ATTRIBUTE_OFFLINE
    | _WINDOWS_FILE_ATTRIBUTE_RECALL_ON_OPEN
    | _WINDOWS_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)
_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_GENERIC_WRITE = 0x40000000
_WINDOWS_DELETE = 0x00010000
_WINDOWS_READ_CONTROL = 0x00020000
_WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_FILE_SHARE_DELETE = 0x00000004
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_FILE_FLAG_OPEN_NO_RECALL = 0x00100000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_WINDOWS_FILE_LIST_DIRECTORY = 0x00000001
_WINDOWS_FILE_ADD_SUBDIRECTORY = 0x00000004
_WINDOWS_FILE_TRAVERSE = 0x00000020
_WINDOWS_DIRECTORY_CHILD_CREATION_ACCESS = _WINDOWS_FILE_ADD_SUBDIRECTORY | _WINDOWS_FILE_TRAVERSE
_WINDOWS_SYNCHRONIZE = 0x00100000
_LINUX_RENAME_NOREPLACE = 1
_DARWIN_RENAME_EXCL = 0x00000004
_REMOTE_FILESYSTEM_TYPES = frozenset(
    {
        "9p",
        "afs",
        "ceph",
        "cifs",
        "davfs",
        "davfs2",
        "glusterfs",
        "ncpfs",
        "nfs",
        "nfs4",
        "smb3",
        "smbfs",
        "sshfs",
        "webdav",
    }
)
_LINUX_LOCAL_FILESYSTEM_TYPES = frozenset(
    {
        "bcachefs",
        "btrfs",
        "ecryptfs",
        "ext2",
        "ext3",
        "ext4",
        "f2fs",
        "jfs",
        "xfs",
        "zfs",
    }
)
_HOME_SYNC_ROOT_NAMES = frozenset(
    {
        "box",
        "box sync",
        "creative cloud files",
        "dropbox",
        "google drive",
        "icloud drive",
        "mega",
        "onedrive",
        "pcloud drive",
        "public",
        "resilio sync",
        "sync.com",
    }
)


class _DarwinFSID(ctypes.Structure):
    _fields_ = [("values", ctypes.c_int32 * 2)]


class _DarwinStatFS(ctypes.Structure):
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", _DarwinFSID),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


class _WindowsFileTime(ctypes.Structure):
    _fields_ = [
        ("low", ctypes.c_uint32),
        ("high", ctypes.c_uint32),
    ]


class _WindowsByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_uint32),
        ("creation_time", _WindowsFileTime),
        ("last_access_time", _WindowsFileTime),
        ("last_write_time", _WindowsFileTime),
        ("volume_serial_number", ctypes.c_uint32),
        ("file_size_high", ctypes.c_uint32),
        ("file_size_low", ctypes.c_uint32),
        ("number_of_links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


@dataclass(frozen=True)
class _WindowsRegularFileInformation:
    identity: tuple[int, int]
    byte_size: int
    last_write_time: int


@dataclass(frozen=True)
class _WindowsEnumeratedMetadata:
    st_mode: int
    st_size: int
    st_file_attributes: int
    st_dev: int
    st_ino: int
    st_mtime_ns: int


@dataclass(frozen=True)
class ExtractionLayout:
    output_root: Path
    extraction_root: Path
    raw_root: Path
    metadata_root: Path
    manifest_root: Path
    temp_root: Path


@dataclass(frozen=True)
class AnalysisLayout:
    final_root: Path
    staging_root: Path


@dataclass(frozen=True)
class ExtendedACLState:
    entry_count: int
    inherited_entry_count: int


@dataclass(frozen=True)
class _LinuxMountRecord:
    mount_point: Path
    filesystem_type: str
    source: str
    mount_options: frozenset[str]
    super_options: frozenset[str]


@dataclass(frozen=True)
class _SafeDirectoryEntry:
    path: Path
    metadata: os.stat_result | _WindowsEnumeratedMetadata


@dataclass(frozen=True)
class _AnchoredOutputState:
    descriptor: int
    identity: tuple[int, int]


@dataclass(frozen=True)
class _WindowsBoundOutputState:
    handle: int
    identity: tuple[int, int]
    visible_root: Path
    descendant_handles: dict[str, tuple[Path, int, tuple[int, int]]] = field(default_factory=dict)


_ANCHORED_OUTPUT_STATE: ContextVar[_AnchoredOutputState | None] = ContextVar(
    "tvtime_anchored_output_state",
    default=None,
)
_WINDOWS_BOUND_OUTPUT_STATE: ContextVar[_WindowsBoundOutputState | None] = ContextVar(
    "tvtime_windows_bound_output_state",
    default=None,
)
_POSIX_CWD_ANCHOR_LOCK = threading.RLock()
_CWD_SAFE_AUXILIARY_THREAD_NAMES = frozenset({"recovery-control"})


def set_private_umask() -> None:
    """Make subsequently created files private on POSIX systems."""

    if os.name != "nt":
        os.umask(0o077)


def canonical_path(path: Path) -> Path:
    if _running_on_windows():
        return no_link_absolute_path(path)
    if _ANCHORED_OUTPUT_STATE.get() is not None and not path.expanduser().is_absolute():
        return no_link_absolute_path(path)
    return path.expanduser().resolve(strict=False)


def _require_anchored_working_directory() -> _AnchoredOutputState:
    state = _ANCHORED_OUTPUT_STATE.get()
    if state is None:
        raise UnsafePathError("A trusted output-root anchor was not active.")
    try:
        root_metadata = os.fstat(state.descriptor)
        cwd_metadata = os.stat(".", follow_symlinks=False)
    except OSError as exc:
        raise UnsafePathError("The trusted output-root anchor could not be validated.") from exc
    root_identity = (int(root_metadata.st_dev), int(root_metadata.st_ino))
    cwd_identity = (int(cwd_metadata.st_dev), int(cwd_metadata.st_ino))
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or not stat.S_ISDIR(cwd_metadata.st_mode)
        or root_identity != state.identity
        or cwd_identity != state.identity
    ):
        raise UnsafePathError("The trusted output-root anchor changed during recovery.")
    return state


def _require_dedicated_cwd_process() -> None:
    """Reject unknown concurrent threads before changing the process-wide cwd."""

    current = threading.current_thread()
    unsafe_threads = [
        thread.name
        for thread in threading.enumerate()
        if thread is not current
        and thread.is_alive()
        and not (thread.daemon and thread.name in _CWD_SAFE_AUXILIARY_THREAD_NAMES)
    ]
    if unsafe_threads:
        raise UnsafePathError(
            "Descriptor-rooted recovery requires a dedicated process without unrelated "
            "background threads. Run the CLI in its own process."
        )


def _anchored_relative_path(path: Path) -> Path | None:
    state = _ANCHORED_OUTPUT_STATE.get()
    expanded = path.expanduser()
    if state is None or expanded.is_absolute():
        return None
    _require_anchored_working_directory()
    if any(component == ".." for component in expanded.parts):
        raise UnsafePathError("A private recovery path escaped its trusted output root.")
    normalized = Path(*[component for component in expanded.parts if component not in {"", "."}])
    if not normalized.parts:
        normalized = Path(".")
    current = Path(".")
    for component in normalized.parts:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise UnsafePathError("A private recovery path could not be validated safely.") from exc
        if _is_link_or_reparse_metadata(metadata):
            raise UnsafePathError(
                "A private recovery path traversed a symbolic link or reparse point."
            )
    return normalized


def _normalize_trusted_darwin_root_alias(path: Path) -> Path:
    """Normalize Apple's immutable root aliases before enforcing no-link ancestry.

    macOS exposes ``/etc``, ``/tmp``, and ``/var`` as root-owned aliases into
    ``/private``. Python's temporary directory is normally below ``/var``. These
    fixed operating-system aliases are the only links accepted here; every
    application-controlled component remains subject to the no-link walk.
    """

    if sys.platform != "darwin":
        return path
    for alias, destination in _DARWIN_TRUSTED_ROOT_ALIASES.items():
        try:
            relative = path.relative_to(alias)
        except ValueError:
            continue
        try:
            metadata = alias.lstat()
            link_target = os.readlink(alias)
        except OSError as exc:
            raise UnsafePathError("A trusted macOS path alias could not be validated.") from exc
        resolved_target = Path(os.path.abspath(os.fspath(alias.parent / link_target)))
        if (
            not stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or resolved_target != destination
        ):
            raise UnsafePathError("A trusted macOS path alias had an unexpected identity.")
        return destination.joinpath(relative)
    return path


def no_link_absolute_path(path: Path) -> Path:
    """Return a lexical absolute path after rejecting every unsafe existing ancestor."""

    anchored = _anchored_relative_path(path)
    if anchored is not None:
        return anchored
    expanded = path.expanduser()
    absolute = Path(os.path.abspath(os.fspath(expanded)))
    absolute = _normalize_trusted_darwin_root_alias(absolute)
    if _running_on_windows():
        _windows_require_safe_existing_ancestors(absolute)
        return absolute
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            # No descendant can exist below the first missing component. Callers
            # create the remaining chain one secured component at a time.
            break
        except OSError as exc:
            raise UnsafePathError("A path ancestor could not be validated safely.") from exc
        if _is_link_or_reparse_metadata(metadata):
            raise UnsafePathError(
                f"Refusing a path through a symbolic link or reparse point: {current}"
            )
        require_non_hydrated_windows_metadata(metadata)
    return absolute


def _casefolded_path(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(path)))).casefold()


def _is_within_casefolded(candidate: Path, root: Path) -> bool:
    candidate_text = _casefolded_path(candidate)
    root_text = _casefolded_path(root)
    separator = os.sep.casefold()
    return candidate_text == root_text or candidate_text.startswith(
        root_text.rstrip("/\\") + separator
    )


def is_known_synced_or_shared_path(
    path: Path,
    *,
    home_directory: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Return whether a lexical path is a known cloud-sync or shared location."""

    values = os.environ if environment is None else environment
    try:
        candidate = Path(os.path.abspath(os.fspath(path.expanduser())))
    except (OSError, RuntimeError):
        # An unresolved home-relative path is not safe to classify as private local storage.
        return True

    home: Path | None
    if home_directory is not None:
        try:
            home = Path(os.path.abspath(os.fspath(home_directory.expanduser())))
        except (OSError, RuntimeError):
            home = None
    else:
        try:
            home = Path(os.path.abspath(os.fspath(Path.home())))
        except (OSError, RuntimeError):
            # The packaged Windows helper intentionally receives no profile environment.
            home = None

    if home is not None and _is_within_casefolded(candidate, home):
        relative = os.path.relpath(os.fspath(candidate), os.fspath(home))
        parts = tuple(part.casefold() for part in Path(relative).parts if part not in (".", ""))
        if parts:
            first = parts[0]
            if (
                first in _HOME_SYNC_ROOT_NAMES
                or first.startswith("onedrive - ")
                or first.startswith("dropbox (")
                or first.startswith("icloud drive (")
            ):
                return True
        if len(parts) >= 2 and parts[:2] in {
            ("library", "cloudstorage"),
            ("library", "fileprovider"),
            ("library", "mobile documents"),
        }:
            return True
        if len(parts) >= 3 and parts[:3] == (
            "library",
            "application support",
            "fileprovider",
        ):
            return True
    elif home is None:
        # Without a trusted home root, reject recognizable provider/shared components anywhere
        # in the absolute path. False positives fail closed instead of disabling the offline gate.
        parts = tuple(part.casefold() for part in candidate.parts if part not in (".", ""))
        if any(
            part in _HOME_SYNC_ROOT_NAMES
            or part.startswith("onedrive - ")
            or part.startswith("dropbox (")
            or part.startswith("icloud drive (")
            for part in parts
        ):
            return True
        if any(
            parts[index : index + 2]
            in {
                ("library", "cloudstorage"),
                ("library", "fileprovider"),
                ("library", "mobile documents"),
            }
            for index in range(max(0, len(parts) - 1))
        ):
            return True
        if any(
            parts[index : index + 3] == ("library", "application support", "fileprovider")
            for index in range(max(0, len(parts) - 2))
        ):
            return True

    for key in (
        "BOX_SYNC",
        "DROPBOX",
        "GOOGLE_DRIVE",
        "ICLOUD_DRIVE",
        "OneDrive",
        "OneDriveCommercial",
        "OneDriveConsumer",
        "PUBLIC",
    ):
        configured = values.get(key)
        if configured:
            try:
                configured_path = Path(configured).expanduser()
            except (OSError, RuntimeError):
                return True
            if _is_within_casefolded(candidate, configured_path):
                return True

    if sys.platform == "darwin" and (
        _is_within_casefolded(candidate, Path("/Network"))
        or _is_within_casefolded(candidate, Path("/Users/Shared"))
    ):
        return True
    return False


def _darwin_volume_is_local(path: Path) -> bool:
    libc = ctypes.CDLL(None, use_errno=True)
    # Intel macOS keeps the pre-64-bit-inode ``statfs`` ABI under the bare
    # symbol and exposes the current ``struct statfs`` layout through the
    # suffixed symbol. Apple silicon has only the current bare symbol. Prefer
    # the explicit modern ABI when it exists so an x86_64 helper running under
    # Rosetta does not read shifted fields and misclassify local APFS storage.
    statfs = getattr(libc, "statfs$INODE64", None)
    if statfs is None:
        statfs = getattr(libc, "statfs", None)
    if statfs is None:
        return False
    statfs.argtypes = [ctypes.c_char_p, ctypes.POINTER(_DarwinStatFS)]
    statfs.restype = ctypes.c_int
    filesystem = _DarwinStatFS()
    if statfs(os.fsencode(path), ctypes.byref(filesystem)) != 0:
        return False
    return bool(filesystem.f_flags & _DARWIN_MNT_LOCAL)


def _decode_linux_mount_path(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def _linux_mount_records(mountinfo_path: Path) -> tuple[_LinuxMountRecord, ...] | None:
    try:
        lines = mountinfo_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    records: list[_LinuxMountRecord] = []
    for line in lines:
        before, separator, after = line.partition(" - ")
        if not separator:
            return None
        fields = before.split()
        filesystem_fields = after.split()
        if len(fields) < 6 or len(filesystem_fields) < 3:
            return None
        mount_point = Path(_decode_linux_mount_path(fields[4]))
        if not mount_point.is_absolute():
            return None
        records.append(
            _LinuxMountRecord(
                mount_point=mount_point,
                filesystem_type=filesystem_fields[0].casefold(),
                source=_decode_linux_mount_path(filesystem_fields[1]),
                mount_options=frozenset(fields[5].casefold().split(",")),
                super_options=frozenset(filesystem_fields[2].casefold().split(",")),
            )
        )
    return tuple(records)


def _linux_mount_for_path(
    path: Path,
    records: Sequence[_LinuxMountRecord],
) -> _LinuxMountRecord | None:
    candidate = Path(os.path.realpath(path))
    matches: list[tuple[int, Path, _LinuxMountRecord]] = []
    for record in records:
        mount_point = Path(os.path.realpath(record.mount_point))
        try:
            candidate.relative_to(mount_point)
        except ValueError:
            continue
        matches.append((len(mount_point.parts), mount_point, record))
    if not matches:
        return None
    matching_mount_points = [os.fspath(mount_point) for _depth, mount_point, _record in matches]
    if len(set(matching_mount_points)) != len(matching_mount_points):
        return None
    deepest = max(depth for depth, _mount_point, _record in matches)
    candidates = [
        (mount_point, record) for depth, mount_point, record in matches if depth == deepest
    ]
    # Linux can expose stacked mounts with the same canonical mountpoint. Mount
    # ordering in /proc/self/mountinfo is not a trust signal, so duplicate
    # canonical records on the candidate's ancestry are ambiguous and fail closed.
    if len(candidates) != 1:
        return None
    return candidates[0][1]


def _linux_mount_source_looks_remote(source: str) -> bool:
    value = source.casefold()
    return (
        value.startswith(("//", "\\\\"))
        or "://" in value
        or (not value.startswith("/") and ":" in value)
    )


def _linux_volume_is_local(
    path: Path,
    *,
    mountinfo_path: Path = Path("/proc/self/mountinfo"),
) -> bool:
    records = _linux_mount_records(mountinfo_path)
    if records is None:
        return False
    selected = _linux_mount_for_path(path, records)
    if selected is None:
        return False
    return (
        selected.filesystem_type in _LINUX_LOCAL_FILESYSTEM_TYPES
        and selected.filesystem_type not in _REMOTE_FILESYSTEM_TYPES
        and not _linux_mount_source_looks_remote(selected.source)
    )


def _windows_volume_is_local(path: Path) -> bool:
    anchor = path.anchor
    if not anchor or anchor.startswith(("\\\\", "//")):
        return False
    try:
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(anchor)  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False
    return drive_type in (2, 3)


def _windows_require_source_ntfs_volume(path: Path) -> None:
    """Require the source volume whose 64-bit file identities we bind to be NTFS."""

    if not path.anchor or path.anchor.startswith(("\\\\", "//")):
        raise UnsafePathError("A Windows recovery source path was invalid.")
    root_handle = -1
    try:
        root_handle, _identity = _windows_open_locked_directory(Path(path.anchor))
        _windows_native.require_source_ntfs_volume(root_handle)
    except _windows_native.WindowsNativeError as exc:
        raise UnsafePathError(
            "Windows recovery sources must be on private local NTFS storage."
        ) from exc
    finally:
        _windows_close_handles((root_handle,))


def _volume_is_local(path: Path) -> bool:
    if sys.platform == "darwin":
        return _darwin_volume_is_local(path)
    if os.name == "nt":
        return _windows_volume_is_local(path)
    if sys.platform.startswith("linux"):
        return _linux_volume_is_local(path)
    return False


def _running_on_windows() -> bool:
    """Keep Windows-only code importable and independently contract-testable."""

    return os.name == "nt"


def require_non_hydrated_windows_metadata(metadata: os.stat_result) -> None:
    """Reject an entry whose contents are not confirmed fully present on Windows."""

    attributes = int(getattr(metadata, "st_file_attributes", 0) or 0)
    if _running_on_windows() and attributes & _WINDOWS_CLOUD_HYDRATION_ATTRIBUTES:
        raise UnsafePathError(
            "Refusing a cloud-backed file or directory that is not fully present on local storage."
        )


def _windows_enumerated_metadata(
    entry: _windows_native.WindowsDirectoryEntryInformation,
) -> _WindowsEnumeratedMetadata:
    mode = stat.S_IFDIR if entry.is_directory else stat.S_IFREG
    modified_ns = max(0, (entry.last_write_time - 116_444_736_000_000_000) * 100)
    return _WindowsEnumeratedMetadata(
        st_mode=mode,
        st_size=entry.byte_size,
        st_file_attributes=entry.attributes,
        st_dev=entry.identity[0],
        st_ino=entry.identity[1],
        st_mtime_ns=modified_ns,
    )


def _windows_enumerated_child(
    parent_handle: int,
    component: str,
) -> _windows_native.WindowsDirectoryEntryInformation:
    try:
        matches = tuple(
            entry
            for entry in _windows_native.directory_entries(parent_handle)
            if entry.name.casefold() == component.casefold()
            or (
                entry.short_name is not None and entry.short_name.casefold() == component.casefold()
            )
        )
    except _windows_native.WindowsNativeError as exc:
        raise UnsafePathError("A Windows directory could not be enumerated safely.") from exc
    if not matches:
        raise FileNotFoundError(component)
    if len(matches) != 1:
        raise UnsafePathError("A Windows directory contained an ambiguous path component.")
    entry = matches[0]
    if entry.is_reparse_point:
        raise UnsafePathError("Refusing a symbolic-link or reparse-point recovery source.")
    if entry.is_cloud_hydrated:
        raise UnsafePathError(
            "Refusing a cloud-backed file or directory that is not fully present on local storage."
        )
    return entry


def _windows_open_enumerated_directory(
    parent_handle: int,
    entry: _windows_native.WindowsDirectoryEntryInformation,
) -> int:
    """Open one enumerated child and bind it to the same visible identity."""

    if not entry.is_directory:
        raise UnsafePathError("A Windows path contained an unsafe non-directory component.")
    try:
        child = _windows_native.open_relative_directory(
            parent_handle,
            entry.name,
            writable=False,
        )
    except _windows_native.WindowsNativeError as exc:
        raise UnsafePathError(
            "A Windows recovery-source directory could not be opened safely."
        ) from exc
    try:
        identity = _windows_directory_identity(child)
        visible = _windows_enumerated_child(parent_handle, entry.name)
        if identity != entry.identity or identity != visible.identity:
            raise UnsafePathError(
                "A Windows recovery-source directory changed while it was opened."
            )
    except BaseException:
        _windows_close_handle(child)
        raise
    return child


def _windows_require_safe_existing_ancestors(path: Path) -> None:
    """Validate existing Win32 components without ordinary path-stat opens."""

    if not path.is_absolute() or not path.anchor or path.anchor.startswith(("\\\\", "//")):
        raise UnsafePathError("A Windows path was invalid.")
    root_handle = -1
    owned: list[int] = []
    try:
        root_handle, _identity = _windows_open_locked_directory(Path(path.anchor))
        current = root_handle
        components = path.parts[1:]
        for index, component in enumerate(components):
            try:
                _windows_native.validate_component(component)
                entry = _windows_enumerated_child(current, component)
            except FileNotFoundError:
                return
            except _windows_native.WindowsNativeError as exc:
                raise UnsafePathError("A Windows path component was invalid.") from exc
            if index == len(components) - 1:
                return
            child = _windows_open_enumerated_directory(current, entry)
            owned.append(child)
            current = child
    finally:
        _windows_close_handles((*reversed(owned), root_handle))


@contextmanager
def _windows_pinned_relative_parent(
    root_handle: int,
    components: Sequence[str],
) -> Iterator[tuple[int, _windows_native.WindowsDirectoryEntryInformation]]:
    """Pin every ancestor and yield one identity-bound final directory entry."""

    try:
        validated_components = _windows_native.validate_relative_parts(components)
    except _windows_native.WindowsNativeError as exc:
        raise UnsafePathError("A Windows recovery source path was invalid.") from exc
    if not validated_components:
        raise UnsafePathError("A Windows recovery source path was invalid.")
    current = root_handle
    owned: list[int] = []
    try:
        for component in validated_components[:-1]:
            entry = _windows_enumerated_child(current, component)
            child = _windows_open_enumerated_directory(current, entry)
            owned.append(child)
            current = child
        yield current, _windows_enumerated_child(current, validated_components[-1])
    finally:
        _windows_close_handles(reversed(owned))


@contextmanager
def _windows_pinned_absolute_parent(
    path: Path,
) -> Iterator[tuple[int, _windows_native.WindowsDirectoryEntryInformation]]:
    if not path.is_absolute() or not path.anchor or path.anchor.startswith(("\\\\", "//")):
        raise UnsafePathError("A Windows recovery source path was invalid.")
    components = path.parts[1:]
    if not components:
        raise UnsafePathError("A Windows volume root was not a regular recovery source file.")
    root_handle = -1
    try:
        root_handle, _identity = _windows_open_locked_directory(Path(path.anchor))
        with _windows_pinned_relative_parent(root_handle, components) as binding:
            yield binding
    finally:
        _windows_close_handles((root_handle,))


@contextmanager
def _windows_pinned_absolute_directory_handle(
    path: Path,
    *,
    writable: bool = False,
) -> Iterator[int]:
    if not path.is_absolute() or not path.anchor or path.anchor.startswith(("\\\\", "//")):
        raise UnsafePathError("A Windows recovery source path was invalid.")
    root_handle = -1
    directory_handle = -1
    try:
        root_handle, _identity = _windows_open_locked_directory(
            Path(path.anchor),
            allow_child_creation=writable and len(path.parts) == 1,
        )
        if len(path.parts) == 1:
            yield root_handle
            return
        with _windows_pinned_relative_parent(root_handle, path.parts[1:]) as (
            parent_handle,
            entry,
        ):
            if not entry.is_directory:
                raise UnsafePathError("A directory tree contained an unsafe directory.")
            try:
                directory_handle = _windows_native.open_relative_retained_directory(
                    parent_handle,
                    entry.name,
                    writable=writable,
                )
            except _windows_native.WindowsNativeError as exc:
                raise UnsafePathError("A directory tree could not be opened safely.") from exc
            identity = _windows_directory_identity(directory_handle)
            visible = _windows_enumerated_child(parent_handle, entry.name)
            if identity != entry.identity or identity != visible.identity:
                raise UnsafePathError("A directory tree changed while it was opened.")
            yield directory_handle
    finally:
        _windows_close_handles((directory_handle, root_handle))


def _windows_enumerated_path_metadata(path: Path) -> _WindowsEnumeratedMetadata:
    """Return identity-bearing metadata from a pinned parent directory enumeration."""

    with _windows_pinned_absolute_parent(path) as (_parent_handle, entry):
        return _windows_enumerated_metadata(entry)


def recovery_path_metadata(path: Path) -> os.stat_result | _WindowsEnumeratedMetadata:
    """Inspect one recovery path without following links or recalling Windows placeholders."""

    candidate = no_link_absolute_path(path)
    if not _running_on_windows():
        return candidate.lstat()
    if len(candidate.parts) == 1:
        with _windows_pinned_absolute_directory_handle(candidate) as handle:
            information = _windows_native.handle_information(handle)
            mode = stat.S_IFDIR if information.is_directory else stat.S_IFREG
            return _WindowsEnumeratedMetadata(
                st_mode=mode,
                st_size=information.byte_size,
                st_file_attributes=information.attributes,
                st_dev=information.identity[0],
                st_ino=information.identity[1],
                st_mtime_ns=max(
                    0,
                    (information.last_write_time - 116_444_736_000_000_000) * 100,
                ),
            )
    return _windows_enumerated_path_metadata(candidate)


def recovery_path_exists(path: Path) -> bool:
    try:
        recovery_path_metadata(path)
    except FileNotFoundError:
        return False
    return True


def recovery_path_is_directory(path: Path) -> bool:
    try:
        return stat.S_ISDIR(recovery_path_metadata(path).st_mode)
    except FileNotFoundError:
        return False


def recovery_path_is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(recovery_path_metadata(path).st_mode)
    except FileNotFoundError:
        return False


def _safe_directory_entries(
    directory: Path,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> tuple[tuple[_SafeDirectoryEntry, ...], tuple[_SafeDirectoryEntry, ...]]:
    """Classify one directory without following links or querying entry targets."""

    if _running_on_windows():
        try:
            with _windows_pinned_absolute_directory_handle(directory) as handle:
                observed = []
                for entry_number, entry in enumerate(
                    _windows_native.iter_directory_entries(handle),
                    1,
                ):
                    if cancellation_check is not None and entry_number % 2_000 == 0:
                        cancellation_check()
                    if entry.is_reparse_point:
                        raise UnsafePathError(
                            "A directory tree contained a symbolic link or reparse point."
                        )
                    if entry.is_cloud_hydrated:
                        raise UnsafePathError(
                            "Refusing a cloud-backed file or directory that is not fully present "
                            "on local storage."
                        )
                    metadata = _windows_enumerated_metadata(entry)
                    observed.append(
                        _SafeDirectoryEntry(path=directory / entry.name, metadata=metadata)
                    )
        except UnsafePathError:
            raise
        except _windows_native.WindowsNativeError as exc:
            raise UnsafePathError("A directory tree could not be enumerated safely.") from exc
    else:
        try:
            directory_metadata = directory.lstat()
            if _is_link_or_reparse_metadata(directory_metadata) or not stat.S_ISDIR(
                directory_metadata.st_mode
            ):
                raise UnsafePathError("A directory tree contained an unsafe directory.")
            with os.scandir(directory) as entries:
                observed = []
                for entry_number, entry in enumerate(entries, 1):
                    if entry_number > _windows_native.MAXIMUM_DIRECTORY_ENTRIES:
                        raise UnsafePathError("A directory exceeded the safe entry limit.")
                    if cancellation_check is not None and entry_number % 2_000 == 0:
                        cancellation_check()
                    metadata = entry.stat(follow_symlinks=False)
                    if _is_link_or_reparse_metadata(metadata):
                        raise UnsafePathError(
                            "A directory tree contained a symbolic link or reparse point."
                        )
                    if not stat.S_ISDIR(metadata.st_mode) and not stat.S_ISREG(metadata.st_mode):
                        raise UnsafePathError(
                            "A directory tree contained an unexpected filesystem entry."
                        )
                    observed.append(
                        _SafeDirectoryEntry(path=directory / entry.name, metadata=metadata)
                    )
        except UnsafePathError:
            raise
        except OSError as exc:
            raise UnsafePathError("A directory tree could not be enumerated safely.") from exc

    ordered = sorted(observed, key=lambda item: item.path.name.encode("utf-8"))
    directories = tuple(item for item in ordered if stat.S_ISDIR(item.metadata.st_mode))
    files = tuple(item for item in ordered if stat.S_ISREG(item.metadata.st_mode))
    return directories, files


def _require_safe_local_directory_tree(
    root: Path,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> None:
    """Exhaustively reject linked, special, or cloud-backed descendants."""

    pending = [root]
    while pending:
        current = pending.pop()
        if cancellation_check is not None:
            cancellation_check()
        directories, _files = _safe_directory_entries(
            current,
            cancellation_check=cancellation_check,
        )
        pending.extend(entry.path for entry in reversed(directories))


def require_fresh_output_platform_support() -> None:
    """Require one platform with a reviewed fresh-root anchoring implementation."""

    if _running_on_windows():
        # Loading both libraries here keeps failure before password entry or
        # plaintext creation. The atomic operation is owned by
        # windows_native.create_fresh_directory.
        _windows_kernel32()
        _windows_ntdll()


def require_encrypted_ios_source_platform_support() -> None:
    """Require the reviewed native source-binding primitives before password entry."""

    if _running_on_windows():
        try:
            _windows_native.require_supported_runtime()
        except _windows_native.WindowsNativeError as exc:
            raise UnsafePathError(
                "Encrypted iOS recovery requires a supported 64-bit Windows 11 installation."
            ) from exc


def _windows_kernel32() -> Any:
    if not _running_on_windows():
        raise UnsafePathError("Windows directory-handle binding is unavailable on this platform.")
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise UnsafePathError("Windows directory-handle binding was unavailable.")
    try:
        return loader("kernel32", use_last_error=True)
    except (OSError, TypeError) as exc:
        raise UnsafePathError("Windows directory-handle binding was unavailable.") from exc


def _windows_ntdll() -> Any:
    if not _running_on_windows():
        raise UnsafePathError("Windows atomic directory creation is unavailable on this platform.")
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise UnsafePathError("Windows atomic directory creation was unavailable.")
    try:
        return loader("ntdll", use_last_error=True)
    except (OSError, TypeError) as exc:
        raise UnsafePathError("Windows atomic directory creation was unavailable.") from exc


def _windows_create_private_directory_relative(parent_handle: int, name: str) -> int:
    """Translate the single native relative-directory capability creator."""

    try:
        return _windows_native.create_fresh_directory(parent_handle, name)
    except _windows_native.WindowsObjectExistsError as exc:
        raise OutputExistsError(
            "The destination already exists. Choose a fresh private recovery folder."
        ) from exc
    except _windows_native.WindowsNativeError as exc:
        raise UnsafePathError("The fresh Windows destination could not be created safely.") from exc


def _windows_error(message: str) -> UnsafePathError:
    try:
        error_number = int(ctypes.get_last_error())
    except (AttributeError, TypeError, ValueError):
        error_number = 0
    detail = f" (Windows error {error_number})" if error_number else ""
    return UnsafePathError(f"{message}{detail}")


def _windows_handle_value(value: object) -> int:
    if isinstance(value, int):
        return value
    candidate = getattr(value, "value", None)
    if isinstance(candidate, int):
        return candidate
    return -1


def _windows_create_file_directory_handle(
    path: Path,
    *,
    allow_rename: bool = False,
    allow_child_creation: bool = False,
    share_delete: bool = False,
) -> int:
    """Open one directory while deliberately denying delete/rename sharing."""

    kernel32 = _windows_kernel32()
    create_file = kernel32.CreateFileW
    with suppress(AttributeError):
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
    try:
        share_mode = _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE
        if share_delete:
            share_mode |= _WINDOWS_FILE_SHARE_DELETE
        # GetFileInformationByHandleEx directory enumeration requires list
        # access on the held capability.  Keep that capability read-only and
        # continue denying delete sharing so the visible directory cannot be
        # exchanged while descendants are validated.
        desired_access = (
            _WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_FILE_LIST_DIRECTORY | _WINDOWS_READ_CONTROL
        )
        if allow_rename:
            desired_access |= _WINDOWS_DELETE
        if allow_child_creation:
            desired_access |= _WINDOWS_DIRECTORY_CHILD_CREATION_ACCESS
        opened = create_file(
            os.fspath(path),
            desired_access,
            share_mode,
            None,
            _WINDOWS_OPEN_EXISTING,
            _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
            | _WINDOWS_FILE_FLAG_OPEN_NO_RECALL
            | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise UnsafePathError("A Windows directory handle could not be opened safely.") from exc
    handle = _windows_handle_value(opened)
    if handle in {-1, 0, _WINDOWS_INVALID_HANDLE_VALUE}:
        raise _windows_error("A Windows directory handle could not be opened safely.")
    return handle


def _windows_create_file_regular_handle(path: Path) -> int:
    """Open one regular file without traversing a reparse point or permitting mutation."""

    kernel32 = _windows_kernel32()
    create_file = kernel32.CreateFileW
    with suppress(AttributeError):
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
    try:
        opened = create_file(
            os.fspath(path),
            _WINDOWS_GENERIC_READ,
            _WINDOWS_FILE_SHARE_READ,
            None,
            _WINDOWS_OPEN_EXISTING,
            _WINDOWS_FILE_FLAG_OPEN_NO_RECALL | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise UnsafePathError("A required private data file could not be opened safely.") from exc
    handle = _windows_handle_value(opened)
    if handle in {-1, 0, _WINDOWS_INVALID_HANDLE_VALUE}:
        raise _windows_error("A required private data file could not be opened safely.")
    return handle


def _windows_create_private_file_descriptor(
    path: Path,
    *,
    exclusive: bool,
    temporary: bool = False,
    allow_path_reopen: bool = False,
) -> int:
    """Create one private file relative to a held, identity-bound parent."""

    if not _running_on_windows():
        raise UnsafePathError("Windows private staging is unavailable on this platform.")
    candidate = no_link_absolute_path(path)
    native_handle = -1
    descriptor = -1
    state = _WINDOWS_BOUND_OUTPUT_STATE.get()
    try:
        if state is not None:
            if candidate == state.visible_root or not _is_within_casefolded(
                candidate, state.visible_root
            ):
                raise UnsafePathError("A private Windows file escaped its held output root.")
            parent_key = _casefolded_path(candidate.parent)
            root_key = _casefolded_path(state.visible_root)
            if parent_key != root_key and parent_key not in state.descendant_handles:
                raise UnsafePathError(
                    "A private Windows file parent was not retained before creation."
                )
            relative_parts = candidate.parts[len(state.visible_root.parts) :]
            native_handle = _windows_native.create_relative_regular_file_path(
                state.handle,
                relative_parts,
                exclusive=exclusive,
                temporary=temporary,
                allow_path_reopen=allow_path_reopen,
            )
        else:
            with _windows_pinned_absolute_directory_handle(
                candidate.parent,
                writable=True,
            ) as parent_handle:
                _windows_native.require_private_ntfs_volume(parent_handle)
                native_handle = _windows_native.create_or_replace_regular_file(
                    parent_handle,
                    candidate.name,
                    exclusive=exclusive,
                    temporary=temporary,
                    allow_path_reopen=allow_path_reopen,
                )
        try:
            descriptor = _windows_native.handle_to_file_descriptor(
                native_handle,
                flags=os.O_RDWR | getattr(os, "O_BINARY", 0),
            )
        finally:
            # handle_to_file_descriptor consumes the native handle whether it
            # succeeds or fails.
            native_handle = -1
        return descriptor
    except _windows_native.WindowsObjectExistsError as exc:
        raise FileExistsError("A private Windows file already existed.") from exc
    except _windows_native.WindowsNativeError as exc:
        raise UnsafePathError("A private Windows file could not be created safely.") from exc
    except BaseException:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        elif native_handle > 0:
            with suppress(Exception):
                _windows_close_handle(native_handle)
        raise


def windows_create_private_staging_descriptor(path: Path) -> int:
    """Create a private file whose exact handle can atomically promote it."""

    return _windows_create_private_file_descriptor(
        path,
        exclusive=True,
        temporary=True,
    )


def windows_create_private_capture_descriptor(path: Path) -> int:
    """Create a pinned private file that a path-only capture tool may reopen."""

    return _windows_create_private_file_descriptor(
        path,
        exclusive=True,
        allow_path_reopen=True,
    )


def windows_open_private_output_descriptor(path: Path, *, exclusive: bool) -> int:
    """Open one ordinary private output without mutating an unvalidated file."""

    return _windows_create_private_file_descriptor(
        path,
        exclusive=exclusive,
    )


def _windows_rename_handle_no_replace(
    native_handle: int,
    destination: Path,
) -> None:
    """Rename one exact Windows file or directory handle without replacement."""

    parent_handle = -1
    try:
        parent_handle, _parent_identity = _windows_open_locked_directory(
            destination.parent,
            allow_child_creation=True,
        )
        try:
            _windows_native.rename_handle_relative(
                native_handle,
                parent_handle,
                (destination.name,),
                replace=False,
            )
        except _windows_native.WindowsObjectExistsError as exc:
            raise OutputExistsError(
                "The destination appeared before atomic promotion. Nothing was overwritten."
            ) from exc
        except _windows_native.WindowsNativeError as exc:
            raise UnsafePathError("The private Windows file could not be promoted safely.") from exc
    finally:
        _windows_close_handles((parent_handle,))


def _windows_promote_held_file_no_replace(
    source: Path,
    destination: Path,
    *,
    held_descriptor: int,
) -> None:
    """Rename through the exact held staging handle without permitting replacement."""

    try:
        import msvcrt

        native_handle = int(msvcrt.get_osfhandle(held_descriptor))
    except (ImportError, OSError, TypeError, ValueError) as exc:
        raise UnsafePathError("The private Windows staging handle was unavailable.") from exc
    _windows_rename_handle_no_replace(native_handle, destination)
    if source.exists() or source.is_symlink():
        raise UnsafePathError("The private Windows staging name remained after promotion.")


def _windows_suspend_bound_descendants(
    state: _WindowsBoundOutputState,
    source: Path,
) -> list[tuple[Path, tuple[int, int]]]:
    """Close child directory capabilities that would block their parent's rename."""

    source_key = _casefolded_path(source)
    selected: list[tuple[str, Path, int, tuple[int, int], Path]] = []
    for key, (visible, handle, identity) in state.descendant_handles.items():
        if key == source_key:
            continue
        try:
            relative = visible.relative_to(source)
        except ValueError:
            continue
        selected.append((key, visible, handle, identity, relative))
    selected.sort(key=lambda item: len(item[4].parts), reverse=True)

    for _key, visible, handle, identity, _relative in selected:
        if _windows_directory_identity(handle) != identity:
            raise UnsafePathError("A held Windows recovery directory identity changed.")
        _require_windows_visible_directory_identity(visible, expected_identity=identity)

    suspended: list[tuple[Path, tuple[int, int]]] = []
    for key, _visible, handle, identity, relative in selected:
        try:
            _windows_close_handle(handle)
        except BaseException:
            _windows_resume_bound_descendants(state, source, suspended)
            raise
        state.descendant_handles.pop(key, None)
        suspended.append((relative, identity))
    return suspended


def _windows_resume_bound_descendants(
    state: _WindowsBoundOutputState,
    base: Path,
    suspended: list[tuple[Path, tuple[int, int]]],
) -> None:
    """Reopen moved child directories and require their exact prior identities."""

    for relative, expected_identity in sorted(
        suspended,
        key=lambda item: len(item[0].parts),
    ):
        visible = base / relative
        handle, identity = _windows_open_locked_directory(
            visible,
            allow_rename=True,
            allow_child_creation=True,
        )
        try:
            _windows_require_private_acl(handle)
            if identity != expected_identity:
                raise UnsafePathError(
                    "A Windows recovery directory changed during atomic promotion."
                )
            _require_windows_visible_directory_identity(
                visible,
                expected_identity=expected_identity,
            )
            state.descendant_handles[_casefolded_path(visible)] = (
                visible,
                handle,
                identity,
            )
        except BaseException:
            _windows_close_handle(handle)
            raise


def _windows_promote_bound_directory_no_replace(source: Path, destination: Path) -> None:
    """Promote a retained directory and rebind every retained descendant path."""

    state = _WINDOWS_BOUND_OUTPUT_STATE.get()
    if state is None:
        raise UnsafePathError("A trusted Windows output-root handle was not active.")
    source_key = _casefolded_path(source)
    entry = state.descendant_handles.get(source_key)
    if entry is None:
        raise UnsafePathError("The Windows staging directory was not retained for promotion.")
    _visible, handle, identity = entry
    if _windows_directory_identity(handle) != identity:
        raise UnsafePathError("The Windows staging directory identity changed before promotion.")
    suspended = _windows_suspend_bound_descendants(state, source)
    try:
        _windows_rename_handle_no_replace(handle, destination)
    except BaseException:
        _windows_resume_bound_descendants(state, source, suspended)
        raise
    if source.exists() or source.is_symlink():
        raise UnsafePathError("The private Windows staging directory remained after promotion.")

    state.descendant_handles.pop(source_key, None)
    state.descendant_handles[_casefolded_path(destination)] = (
        destination,
        handle,
        identity,
    )
    _windows_resume_bound_descendants(state, destination, suspended)
    _require_windows_visible_directory_identity(destination, expected_identity=identity)


def _windows_regular_file_information(handle: int) -> _WindowsRegularFileInformation:
    """Return stable native identity and mutation metadata for one held regular file."""

    if not isinstance(handle, int) or isinstance(handle, bool) or handle <= 0:
        raise UnsafePathError("A trusted Windows file handle was not available.")
    information = _WindowsByHandleFileInformation()
    kernel32 = _windows_kernel32()
    get_information = kernel32.GetFileInformationByHandle
    with suppress(AttributeError):
        get_information.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_WindowsByHandleFileInformation),
        ]
        get_information.restype = ctypes.c_int
    try:
        succeeded = get_information(ctypes.c_void_p(handle), ctypes.byref(information))
    except (OSError, TypeError, ValueError) as exc:
        raise UnsafePathError(
            "A required private data file could not be validated safely."
        ) from exc
    if not succeeded:
        raise _windows_error("A required private data file could not be validated safely.")
    attributes = int(information.file_attributes)
    if attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY:
        raise UnsafePathError("A required private data file was not a regular file.")
    if attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
        raise UnsafePathError("A required private data file was a reparse point.")
    if attributes & _WINDOWS_CLOUD_HYDRATION_ATTRIBUTES:
        raise UnsafePathError(
            "A required private data file was not fully present on local storage."
        )
    file_index = (int(information.file_index_high) << 32) | int(information.file_index_low)
    byte_size = (int(information.file_size_high) << 32) | int(information.file_size_low)
    last_write_time = (int(information.last_write_time.high) << 32) | int(
        information.last_write_time.low
    )
    return _WindowsRegularFileInformation(
        identity=(int(information.volume_serial_number), file_index),
        byte_size=byte_size,
        last_write_time=last_write_time,
    )


@contextmanager
def _windows_locked_relative_regular_file_descriptor(
    root_handle: int,
    components: Sequence[str],
) -> Iterator[tuple[int, _WindowsRegularFileInformation]]:
    """Read one identity-bound relative file while every ancestor remains pinned."""

    handle = -1
    descriptor = -1
    with _windows_pinned_relative_parent(root_handle, components) as (parent_handle, entry):
        if entry.is_directory:
            raise UnsafePathError("A required private data file was not a regular file.")
        try:
            try:
                handle = _windows_native.open_relative_regular_file(parent_handle, entry.name)
            except _windows_native.WindowsNativeError as exc:
                raise UnsafePathError(
                    "A required private data file could not be opened safely."
                ) from exc
            before = _windows_regular_file_information(handle)
            visible = _windows_enumerated_child(parent_handle, entry.name)
            if (
                before.identity != entry.identity
                or before.identity != visible.identity
                or before.byte_size != entry.byte_size
                or before.byte_size != visible.byte_size
                or before.last_write_time != entry.last_write_time
                or before.last_write_time != visible.last_write_time
            ):
                raise UnsafePathError("A required private data file changed while it was opened.")
            try:
                import msvcrt

                descriptor = msvcrt.open_osfhandle(
                    handle,
                    os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0),
                )
            except (ImportError, OSError, TypeError, ValueError) as exc:
                raise UnsafePathError(
                    "A required private data file could not be opened safely."
                ) from exc
            handle = -1  # Ownership moved to the CRT descriptor.
            yield descriptor, before
            try:
                native_handle = msvcrt.get_osfhandle(descriptor)
            except (OSError, TypeError, ValueError) as exc:
                raise UnsafePathError(
                    "A required private data file could not be validated safely."
                ) from exc
            after = _windows_regular_file_information(int(native_handle))
            visible_after = _windows_enumerated_child(parent_handle, entry.name)
            if (
                after != before
                or after.identity != visible_after.identity
                or after.byte_size != visible_after.byte_size
                or after.last_write_time != visible_after.last_write_time
            ):
                raise UnsafePathError("A required private data file changed while it was read.")
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    raise UnsafePathError(
                        "A required private data file could not be closed safely."
                    ) from exc
            elif handle > 0:
                _windows_close_handle(handle)


@contextmanager
def _windows_locked_regular_file_descriptor(
    path: Path,
) -> Iterator[tuple[int, _WindowsRegularFileInformation]]:
    """Hold a relative-open file and its complete absolute ancestor chain."""

    if not path.is_absolute() or not path.anchor or path.anchor.startswith(("\\\\", "//")):
        raise UnsafePathError("A required private data file path was invalid.")
    root_handle = -1
    try:
        root_handle, _identity = _windows_open_locked_directory(Path(path.anchor))
        with _windows_locked_relative_regular_file_descriptor(
            root_handle,
            path.parts[1:],
        ) as binding:
            yield binding
    finally:
        _windows_close_handles((root_handle,))


def _windows_directory_identity(handle: int) -> tuple[int, int]:
    """Return a stable volume/file identity and reject reparse or non-directory handles."""

    if not isinstance(handle, int) or isinstance(handle, bool) or handle <= 0:
        raise UnsafePathError("A trusted Windows directory handle was not available.")
    information = _WindowsByHandleFileInformation()
    kernel32 = _windows_kernel32()
    get_information = kernel32.GetFileInformationByHandle
    with suppress(AttributeError):
        get_information.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_WindowsByHandleFileInformation),
        ]
        get_information.restype = ctypes.c_int
    try:
        succeeded = get_information(
            ctypes.c_void_p(handle),
            ctypes.byref(information),
        )
    except (OSError, TypeError, ValueError) as exc:
        raise UnsafePathError("A Windows directory handle could not be validated.") from exc
    if not succeeded:
        raise _windows_error("A Windows directory handle could not be validated.")
    attributes = int(information.file_attributes)
    if not attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY:
        raise UnsafePathError("A trusted Windows directory handle did not name a directory.")
    if attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
        raise UnsafePathError("Refusing a Windows directory reparse point.")
    if attributes & _WINDOWS_CLOUD_HYDRATION_ATTRIBUTES:
        raise UnsafePathError("A Windows directory was not fully present on local storage.")
    file_index = (int(information.file_index_high) << 32) | int(information.file_index_low)
    return int(information.volume_serial_number), file_index


def _windows_close_handle(handle: int) -> None:
    if not isinstance(handle, int) or isinstance(handle, bool) or handle <= 0:
        return
    kernel32 = _windows_kernel32()
    close_handle = kernel32.CloseHandle
    with suppress(AttributeError):
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
    try:
        succeeded = close_handle(ctypes.c_void_p(handle))
    except (OSError, TypeError, ValueError) as exc:
        raise UnsafePathError("A Windows directory handle could not be closed safely.") from exc
    if not succeeded:
        raise _windows_error("A Windows directory handle could not be closed safely.")


def _windows_close_handles(handles: Iterable[int]) -> None:
    """Attempt every close without replacing an exception already leaving the protected body."""

    active_error = sys.exc_info()[1]
    cleanup_error: BaseException | None = None
    for handle in handles:
        if handle <= 0:
            continue
        try:
            _windows_close_handle(handle)
        except BaseException as exc:
            if cleanup_error is None:
                cleanup_error = exc
    if active_error is None and cleanup_error is not None:
        raise cleanup_error


def _windows_require_private_acl(handle: int) -> None:
    try:
        _windows_native.validate_private_acl(handle)
    except _windows_native.WindowsNativeError as exc:
        raise UnsafePathError("A private Windows recovery artifact was not owner-only.") from exc


def _windows_open_locked_directory(
    path: Path,
    *,
    allow_rename: bool = False,
    allow_child_creation: bool = False,
    share_delete: bool = False,
) -> tuple[int, tuple[int, int]]:
    handle = _windows_create_file_directory_handle(
        path,
        allow_rename=allow_rename,
        allow_child_creation=allow_child_creation,
        share_delete=share_delete,
    )
    try:
        if re.fullmatch(r"[A-Za-z]:[\\/]*", os.fspath(path)) is not None:
            try:
                _windows_native.require_source_ntfs_volume(handle)
            except _windows_native.WindowsNativeError as exc:
                raise UnsafePathError(
                    "Windows recovery paths must be on private local NTFS storage."
                ) from exc
        return handle, _windows_directory_identity(handle)
    except BaseException:
        with suppress(Exception):
            _windows_close_handle(handle)
        raise


def _windows_hold_bound_descendant_directory(path: Path) -> None:
    """Retain a no-delete-sharing handle for every directory below a bound root."""

    state = _WINDOWS_BOUND_OUTPUT_STATE.get()
    if state is None:
        return
    candidate = no_link_absolute_path(path)
    if not _is_within_casefolded(candidate, state.visible_root):
        raise UnsafePathError("A Windows recovery directory escaped its held output root.")
    key = _casefolded_path(candidate)
    root_key = _casefolded_path(state.visible_root)
    if key == root_key:
        _require_windows_visible_directory_identity(candidate, expected_identity=state.identity)
        return
    if key in state.descendant_handles:
        _visible, handle, identity = state.descendant_handles[key]
        if _windows_directory_identity(handle) != identity:
            raise UnsafePathError("A held Windows recovery directory identity changed.")
        _require_windows_visible_directory_identity(candidate, expected_identity=identity)
        return
    parent_key = _casefolded_path(candidate.parent)
    if parent_key != root_key and parent_key not in state.descendant_handles:
        raise UnsafePathError(
            "A Windows recovery directory parent was not retained before its child."
        )
    handle, identity = _windows_open_locked_directory(
        candidate,
        allow_rename=True,
        allow_child_creation=True,
    )
    try:
        _windows_require_private_acl(handle)
        _require_windows_visible_directory_identity(candidate, expected_identity=identity)
        state.descendant_handles[key] = (candidate, handle, identity)
    except BaseException:
        _windows_close_handle(handle)
        raise


def _windows_create_and_hold_bound_descendant_directory(path: Path) -> None:
    """Atomically create a private child through its retained parent handle."""

    state = _WINDOWS_BOUND_OUTPUT_STATE.get()
    if state is None:
        raise UnsafePathError("A trusted Windows output-root handle was not active.")
    candidate = no_link_absolute_path(path)
    if not _is_within_casefolded(candidate, state.visible_root) or candidate == state.visible_root:
        raise UnsafePathError("A Windows recovery directory escaped its held output root.")
    parent_key = _casefolded_path(candidate.parent)
    root_key = _casefolded_path(state.visible_root)
    if parent_key == root_key:
        parent_handle = state.handle
    else:
        parent_entry = state.descendant_handles.get(parent_key)
        if parent_entry is None:
            raise UnsafePathError(
                "A Windows recovery directory parent was not retained before its child."
            )
        _parent_visible, parent_handle, parent_identity = parent_entry
        if _windows_directory_identity(parent_handle) != parent_identity:
            raise UnsafePathError("A held Windows recovery directory identity changed.")
    handle = _windows_create_private_directory_relative(parent_handle, candidate.name)
    try:
        identity = _windows_directory_identity(handle)
        _require_windows_visible_directory_identity(candidate, expected_identity=identity)
        state.descendant_handles[_casefolded_path(candidate)] = (candidate, handle, identity)
    except BaseException:
        _windows_close_handle(handle)
        raise


def _windows_close_bound_descendant_directories(state: _WindowsBoundOutputState) -> None:
    validation_error: BaseException | None = None
    ordered = sorted(
        state.descendant_handles.items(),
        key=lambda item: item[0].count(os.sep),
        reverse=True,
    )
    try:
        for _key, (visible, handle, identity) in ordered:
            try:
                if _windows_directory_identity(handle) != identity:
                    raise UnsafePathError("A held Windows recovery directory identity changed.")
                _require_windows_visible_directory_identity(
                    visible,
                    expected_identity=identity,
                )
            except BaseException as exc:
                if validation_error is None:
                    validation_error = exc
    finally:
        for _key, (_visible, handle, _identity) in ordered:
            try:
                _windows_close_handle(handle)
            except BaseException as exc:
                if validation_error is None:
                    validation_error = exc
        state.descendant_handles.clear()
    if validation_error is not None:
        raise validation_error


def _windows_take_bound_descendant_directory(path: Path) -> tuple[int, tuple[int, int]] | None:
    """Detach one validated ephemeral directory handle from bound state."""

    state = _WINDOWS_BOUND_OUTPUT_STATE.get()
    if state is None:
        return None
    candidate = no_link_absolute_path(path)
    key = _casefolded_path(candidate)
    entry = state.descendant_handles.get(key)
    if entry is None:
        return None
    for other_key, (
        other_visible,
        _other_handle,
        _other_identity,
    ) in state.descendant_handles.items():
        if other_key != key and _is_within_casefolded(other_visible, candidate):
            raise UnsafePathError(
                "A temporary Windows recovery directory still retained a child capability."
            )

    visible, handle, identity = entry
    validation_error: BaseException | None = None
    try:
        if _windows_directory_identity(handle) != identity:
            raise UnsafePathError("A held Windows recovery directory identity changed.")
        _require_windows_visible_directory_identity(visible, expected_identity=identity)
    except BaseException as exc:
        validation_error = exc
    finally:
        state.descendant_handles.pop(key, None)
    if validation_error is not None:
        with suppress(Exception):
            _windows_close_handle(handle)
        raise validation_error
    return handle, identity


def _windows_release_bound_descendant_directory(path: Path) -> None:
    """Release one empty ephemeral directory before its scoped cleanup."""

    detached = _windows_take_bound_descendant_directory(path)
    if detached is None:
        return
    handle, _identity = detached
    _windows_close_handle(handle)


def _windows_delete_private_tree_handle(
    path: Path,
    *,
    handle: int,
    expected_identity: tuple[int, int],
) -> None:
    """Delete one exact private tree and its root through a held handle."""

    try:
        _windows_require_private_acl(handle)
        if _windows_directory_identity(handle) != expected_identity:
            raise UnsafePathError("A private Windows temporary directory identity changed.")
        _require_windows_visible_directory_identity(
            path,
            expected_identity=expected_identity,
        )
        try:
            _windows_native.delete_private_tree(handle)
        except _windows_native.WindowsNativeError as exc:
            raise UnsafePathError(
                "A private Windows temporary directory could not be removed safely."
            ) from exc
    finally:
        _windows_close_handles((handle,))
    if recovery_path_exists(path):
        raise UnsafePathError("A private Windows temporary directory remained after cleanup.")


def windows_delete_bound_private_tree(path: Path) -> None:
    """Delete a retained Windows subtree without destructive path traversal."""

    state = _WINDOWS_BOUND_OUTPUT_STATE.get()
    if state is None:
        raise UnsafePathError("A trusted Windows output-root handle was not active.")
    candidate = no_link_absolute_path(path)
    root_key = _casefolded_path(candidate)
    root_entry = state.descendant_handles.get(root_key)
    if root_entry is None:
        raise UnsafePathError("A private Windows temporary directory handle was unavailable.")
    descendants = [
        (key, entry)
        for key, entry in state.descendant_handles.items()
        if key != root_key and _is_within_casefolded(entry[0], candidate)
    ]
    for _key, (visible, handle, identity) in [*descendants, (root_key, root_entry)]:
        if _windows_directory_identity(handle) != identity:
            raise UnsafePathError("A held Windows recovery directory identity changed.")
        _windows_require_private_acl(handle)
        _require_windows_visible_directory_identity(visible, expected_identity=identity)
    ordered_descendants = sorted(
        descendants,
        key=lambda item: len(item[1][0].parts),
        reverse=True,
    )
    handles_to_close: list[int] = []
    for key, (_visible, handle, _identity) in ordered_descendants:
        state.descendant_handles.pop(key, None)
        handles_to_close.append(handle)
    _windows_close_handles(handles_to_close)
    visible, root_handle, root_identity = state.descendant_handles.pop(root_key)
    _windows_delete_private_tree_handle(
        visible,
        handle=root_handle,
        expected_identity=root_identity,
    )


MAXIMUM_WINDOWS_RETAINED_DESCENDANT_DIRECTORIES = 4_096


def _windows_hold_existing_descendant_directories(
    root: Path,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> None:
    """Pin every existing directory in a selected private tree before traversal."""

    pending = [root]
    retained = 0
    while pending:
        if cancellation_check is not None:
            cancellation_check()
        current = pending.pop()
        directories, _files = _safe_directory_entries(
            current,
            cancellation_check=cancellation_check,
        )
        for entry in directories:
            retained += 1
            if retained > MAXIMUM_WINDOWS_RETAINED_DESCENDANT_DIRECTORIES:
                raise UnsafePathError(
                    "The selected Windows recovery tree contained too many directories."
                )
            _windows_hold_bound_descendant_directory(entry.path)
        pending.extend(entry.path for entry in reversed(directories))


def _require_windows_visible_directory_identity(
    path: Path,
    *,
    expected_identity: tuple[int, int],
) -> None:
    visible_handle = -1
    try:
        # This is a transient identity check, not a retention lock. Sharing
        # delete lets it coexist with the retained handle's DELETE access;
        # the retained handle still omits FILE_SHARE_DELETE and therefore
        # continues to deny rename/replacement by every other opener.
        visible_handle, visible_identity = _windows_open_locked_directory(
            path,
            share_delete=True,
        )
        if visible_identity != expected_identity:
            raise UnsafePathError("The visible Windows directory identity changed during recovery.")
    finally:
        _windows_close_handles((visible_handle,))


def _close_bound_directory_handle(handle: int) -> None:
    if _running_on_windows():
        _windows_close_handle(handle)
    else:
        os.close(handle)


def bound_directory_free_bytes(path: Path, *, handle: int) -> int:
    """Measure free space through a bound directory where the platform permits it."""

    if _running_on_windows():
        # The held no-delete-sharing handle prevents the visible directory root
        # from being renamed or replaced while Windows resolves this query.
        _windows_directory_identity(handle)
        return int(shutil.disk_usage(path).free)
    filesystem = os.fstatvfs(handle)
    return int(filesystem.f_bavail) * int(filesystem.f_frsize)


def require_private_local_destination(path: Path) -> Path:
    """Validate the nearest existing parent and reject known sync/shared locations."""

    candidate = no_link_absolute_path(path)
    if is_known_synced_or_shared_path(candidate):
        raise UnsafePathError(
            "Refusing a cloud-synced or shared destination. Choose private local storage."
        )
    existing = candidate
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    if not existing.is_dir() or existing.is_symlink():
        raise UnsafePathError("Could not confirm a safe existing destination parent.")
    if not _volume_is_local(existing):
        raise UnsafePathError("The destination volume could not be confirmed as local storage.")
    return existing


def require_local_recovery_source(path: Path) -> Path:
    """Reject remote, shared, linked, or cloud-hydrated recovery sources."""

    candidate = no_link_absolute_path(path)
    if is_known_synced_or_shared_path(candidate):
        raise UnsafePathError(
            "Refusing a cloud-synced or shared recovery source. Choose private local storage."
        )
    if not _volume_is_local(candidate):
        raise UnsafePathError("The recovery source volume could not be confirmed as local storage.")
    if _running_on_windows():
        _windows_require_source_ntfs_volume(candidate)
    try:
        metadata = (
            _windows_enumerated_path_metadata(candidate)
            if _running_on_windows()
            else candidate.lstat()
        )
    except FileNotFoundError as exc:
        raise UserInputError("The selected recovery source was not found.") from exc
    except OSError as exc:
        raise UnsafePathError(
            "The selected recovery source could not be inspected safely."
        ) from exc
    if _is_link_or_reparse_metadata(metadata):
        raise UnsafePathError("Refusing a symbolic-link or reparse-point recovery source.")
    require_non_hydrated_windows_metadata(metadata)
    return candidate


def optional_local_recovery_regular_file(
    path: Path,
    *,
    volume_already_validated: bool = False,
) -> Path | None:
    """Return one protected local regular file, or ``None`` when it is absent."""

    candidate = no_link_absolute_path(path)
    if is_known_synced_or_shared_path(candidate):
        raise UnsafePathError(
            "Refusing a cloud-synced or shared recovery source. Choose private local storage."
        )
    if not volume_already_validated and not _volume_is_local(candidate):
        raise UnsafePathError("The recovery source volume could not be confirmed as local storage.")
    if _running_on_windows() and not volume_already_validated:
        _windows_require_source_ntfs_volume(candidate)
    try:
        metadata = (
            _windows_enumerated_path_metadata(candidate)
            if _running_on_windows()
            else candidate.lstat()
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise UnsafePathError(
            "The selected recovery source could not be inspected safely."
        ) from exc
    if _is_link_or_reparse_metadata(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise UnsafePathError("A selected recovery source was not a regular file.")
    require_non_hydrated_windows_metadata(metadata)
    if _running_on_windows():
        with _windows_locked_regular_file_descriptor(candidate):
            pass
    return candidate


def _validated_directory_identity(identity: tuple[int, int]) -> tuple[int, int]:
    if len(identity) != 2 or any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in identity
    ):
        raise UnsafePathError("The expected destination directory identity was invalid.")
    return identity


def require_bound_destination_parent(
    output: Path,
    *,
    destination_parent_descriptor: int,
    expected_identity: tuple[int, int],
) -> Path:
    """Bind a fresh output's exact path parent to an already-open directory handle."""

    if destination_parent_descriptor < 0:
        raise UnsafePathError("A trusted destination directory handle was not available.")
    expected_identity = _validated_directory_identity(expected_identity)
    candidate = no_link_absolute_path(output)
    parent = candidate.parent

    if _running_on_windows():
        descriptor_identity = _windows_directory_identity(destination_parent_descriptor)
        if descriptor_identity != expected_identity:
            raise UnsafePathError("The destination directory handle identity did not match.")
        _require_windows_visible_directory_identity(
            parent,
            expected_identity=descriptor_identity,
        )
        return parent

    try:
        descriptor_metadata = os.fstat(destination_parent_descriptor)
    except OSError as exc:
        raise UnsafePathError("The destination directory handle could not be validated.") from exc
    descriptor_identity = (
        int(descriptor_metadata.st_dev),
        int(descriptor_metadata.st_ino),
    )
    if not stat.S_ISDIR(descriptor_metadata.st_mode) or descriptor_identity != expected_identity:
        raise UnsafePathError("The destination directory handle identity did not match.")

    try:
        parent_metadata = parent.lstat()
    except OSError as exc:
        raise UnsafePathError("The destination parent path could not be validated.") from exc
    if (
        _is_link_or_reparse_metadata(parent_metadata)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or (int(parent_metadata.st_dev), int(parent_metadata.st_ino)) != descriptor_identity
    ):
        raise UnsafePathError("The destination parent path changed after it was selected.")
    return parent


@contextmanager
def held_destination_parent(
    output: Path,
) -> Iterator[tuple[int, tuple[int, int], Path]]:
    """Hold the exact immediate parent across preflight, password entry, and recovery.

    POSIX uses a no-follow directory descriptor. Windows holds every ancestor
    and the exact parent without delete sharing until recovery finishes.
    """

    visible_output = no_link_absolute_path(output)
    parent = visible_output.parent
    if _running_on_windows():
        try:
            with _windows_pinned_absolute_directory_handle(
                parent,
                writable=True,
            ) as handle:
                identity = _windows_directory_identity(handle)
                try:
                    _windows_native.require_recovery_capabilities(handle)
                except _windows_native.WindowsNativeError as exc:
                    raise UnsafePathError(
                        "Windows recovery requires a local NTFS destination with persistent "
                        "access controls."
                    ) from exc
                require_bound_destination_parent(
                    visible_output,
                    destination_parent_descriptor=handle,
                    expected_identity=identity,
                )
                yield handle, identity, visible_output
        except FileNotFoundError as exc:
            raise UnsafePathError(
                "The immediate destination parent must already exist. Create or select that "
                "private encrypted parent folder, then choose a new child name."
            ) from exc
        return

    try:
        parent_metadata = parent.lstat()
    except FileNotFoundError as exc:
        raise UnsafePathError(
            "The immediate destination parent must already exist. Create or select that private "
            "encrypted parent folder, then choose a new child name."
        ) from exc
    except OSError as exc:
        raise UnsafePathError(
            "The immediate destination parent could not be opened safely."
        ) from exc
    if _is_link_or_reparse_metadata(parent_metadata) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise UnsafePathError("The immediate destination parent was not a safe regular directory.")

    handle = -1
    try:
        try:
            handle = os.open(parent, _descriptor_flags(stat.S_IFDIR))
        except OSError as exc:
            raise UnsafePathError(
                "The immediate destination parent could not be opened safely."
            ) from exc
        opened = os.fstat(handle)
        identity = (int(opened.st_dev), int(opened.st_ino))
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (
                int(parent_metadata.st_dev),
                int(parent_metadata.st_ino),
            )
            != identity
        ):
            raise UnsafePathError("The immediate destination parent changed while it was opened.")
        require_bound_destination_parent(
            visible_output,
            destination_parent_descriptor=handle,
            expected_identity=identity,
        )
        yield handle, identity, visible_output
    finally:
        if handle >= 0:
            _close_bound_directory_handle(handle)


def _open_bound_fresh_output_root(
    output_root: Path,
    *,
    destination_parent_descriptor: int,
    expected_identity: tuple[int, int],
) -> tuple[int, tuple[int, int]]:
    require_fresh_output_platform_support()
    parent = require_bound_destination_parent(
        output_root,
        destination_parent_descriptor=destination_parent_descriptor,
        expected_identity=expected_identity,
    )
    if output_root.parent != parent or output_root.name in {"", ".", ".."}:
        raise UnsafePathError("The output was not a direct child of its selected destination.")
    if _running_on_windows():
        descriptor = _windows_create_private_directory_relative(
            destination_parent_descriptor,
            output_root.name,
        )
        try:
            identity = _windows_directory_identity(descriptor)
            _require_windows_visible_directory_identity(
                output_root,
                expected_identity=identity,
            )
            return descriptor, identity
        except BaseException:
            _windows_close_handle(descriptor)
            raise
    try:
        os.mkdir(output_root.name, mode=0o700, dir_fd=destination_parent_descriptor)
    except FileExistsError as exc:
        raise OutputExistsError(
            "The destination already exists. Choose a new dedicated folder so nothing is "
            "overwritten."
        ) from exc
    except OSError as exc:
        raise UnsafePathError("The fresh destination could not be created safely.") from exc

    flags = getattr(os, "O_SEARCH", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(
            output_root.name,
            flags,
            dir_fd=destination_parent_descriptor,
        )
        created = harden_private_descriptor(
            descriptor,
            expected_type=stat.S_IFDIR,
            mode=0o700,
        )
        path_metadata = output_root.lstat()
        if _is_link_or_reparse_metadata(path_metadata) or (
            int(path_metadata.st_dev),
            int(path_metadata.st_ino),
        ) != (int(created.st_dev), int(created.st_ino)):
            raise UnsafePathError("The fresh destination changed while it was being secured.")
        return descriptor, (int(created.st_dev), int(created.st_ino))
    except OSError as exc:
        if descriptor >= 0:
            _close_bound_directory_handle(descriptor)
        raise UnsafePathError("The fresh destination could not be secured safely.") from exc
    except BaseException:
        if descriptor >= 0:
            _close_bound_directory_handle(descriptor)
        raise


def _require_visible_output_identity(
    output_root: Path,
    *,
    destination_parent_descriptor: int,
    expected_parent_identity: tuple[int, int],
    expected_output_identity: tuple[int, int],
) -> None:
    require_bound_destination_parent(
        output_root,
        destination_parent_descriptor=destination_parent_descriptor,
        expected_identity=expected_parent_identity,
    )
    if _running_on_windows():
        _require_windows_visible_directory_identity(
            output_root,
            expected_identity=expected_output_identity,
        )
        return
    try:
        metadata = output_root.lstat()
    except OSError as exc:
        raise UnsafePathError("The completed destination was no longer visible safely.") from exc
    if (
        _is_link_or_reparse_metadata(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
        or (int(metadata.st_dev), int(metadata.st_ino)) != expected_output_identity
    ):
        raise UnsafePathError("The completed destination identity changed during recovery.")


@contextmanager
def _anchored_relative_temporary_directories() -> Iterator[None]:
    """Prevent tempfile from turning private relative directories into absolute paths."""

    original_mkdtemp = tempfile.mkdtemp

    def relative_mkdtemp(
        suffix: str | None = None,
        prefix: str | None = None,
        dir: str | os.PathLike[str] | None = None,
    ) -> str:
        if any(value is not None and not isinstance(value, str) for value in (suffix, prefix)) or (
            dir is not None and not isinstance(dir, (str, os.PathLike))
        ):
            raise UnsafePathError("A private temporary path request was malformed.")
        configured_parent = dir if dir is not None else tempfile.tempdir
        if not configured_parent:
            raise UnsafePathError("A private temporary directory was not explicitly anchored.")
        parent = no_link_absolute_path(Path(configured_parent))
        if parent.is_absolute():
            raise UnsafePathError("A private temporary directory escaped its trusted output root.")
        for _attempt in range(128):
            candidate = safe_join(
                parent,
                f"{prefix or 'tmp'}{secrets.token_hex(16)}{suffix or ''}",
            )
            try:
                candidate.mkdir(mode=0o700)
            except FileExistsError:
                continue
            secure_directory(candidate)
            return str(candidate)
        raise UnsafePathError("A private temporary directory could not be allocated safely.")

    tempfile.mkdtemp = relative_mkdtemp
    try:
        yield
    finally:
        tempfile.mkdtemp = original_mkdtemp


@contextmanager
def anchored_bound_output_root(
    output_root: Path,
    *,
    destination_parent_descriptor: int,
    expected_parent_identity: tuple[int, int],
) -> Iterator[Path]:
    """Create and anchor a fresh output root for one dedicated recovery process.

    Every descendant path used while this context is active must remain relative.
    Relative filesystem operations then resolve from the held cwd/root identity even
    if another process renames or replaces the visible path.
    """

    require_fresh_output_platform_support()
    visible_root = no_link_absolute_path(output_root)

    if _running_on_windows():
        root_handle = -1
        root_identity = (0, 0)
        token = None
        windows_state: _WindowsBoundOutputState | None = None
        try:
            root_handle, root_identity = _open_bound_fresh_output_root(
                visible_root,
                destination_parent_descriptor=destination_parent_descriptor,
                expected_identity=expected_parent_identity,
            )
            windows_state = _WindowsBoundOutputState(
                handle=root_handle,
                identity=root_identity,
                visible_root=visible_root,
            )
            token = _WINDOWS_BOUND_OUTPUT_STATE.set(windows_state)
            yield visible_root
        finally:
            validation_error: BaseException | None = None
            if root_handle >= 0:
                try:
                    if _windows_directory_identity(root_handle) != root_identity:
                        raise UnsafePathError(
                            "The trusted Windows output-root handle identity changed."
                        )
                    _require_visible_output_identity(
                        visible_root,
                        destination_parent_descriptor=destination_parent_descriptor,
                        expected_parent_identity=expected_parent_identity,
                        expected_output_identity=root_identity,
                    )
                except BaseException as exc:
                    validation_error = exc
            if windows_state is not None:
                try:
                    _windows_close_bound_descendant_directories(windows_state)
                except BaseException as exc:
                    if validation_error is None:
                        validation_error = exc
            if token is not None:
                _WINDOWS_BOUND_OUTPUT_STATE.reset(token)
            if root_handle >= 0:
                try:
                    _windows_close_handle(root_handle)
                except BaseException as exc:
                    if validation_error is None:
                        validation_error = exc
            if validation_error is not None:
                raise validation_error
        return

    saved_cwd_descriptor = -1
    root_descriptor = -1
    token = None
    temporary_context = None
    with _POSIX_CWD_ANCHOR_LOCK:
        try:
            _require_dedicated_cwd_process()
            saved_cwd_descriptor = os.open(".", _descriptor_flags(stat.S_IFDIR))
            root_descriptor, root_identity = _open_bound_fresh_output_root(
                visible_root,
                destination_parent_descriptor=destination_parent_descriptor,
                expected_identity=expected_parent_identity,
            )
            os.fchdir(root_descriptor)
            token = _ANCHORED_OUTPUT_STATE.set(
                _AnchoredOutputState(descriptor=root_descriptor, identity=root_identity)
            )
            _require_anchored_working_directory()
            temporary_context = _anchored_relative_temporary_directories()
            temporary_context.__enter__()
            yield Path(".")
        finally:
            validation_error: BaseException | None = None
            if root_descriptor >= 0 and token is not None:
                try:
                    _require_anchored_working_directory()
                except BaseException as exc:
                    validation_error = exc
            if temporary_context is not None:
                try:
                    temporary_context.__exit__(None, None, None)
                except BaseException as exc:
                    if validation_error is None:
                        validation_error = exc
            if token is not None:
                _ANCHORED_OUTPUT_STATE.reset(token)
            if saved_cwd_descriptor >= 0:
                try:
                    os.fchdir(saved_cwd_descriptor)
                except BaseException as exc:
                    if validation_error is None:
                        validation_error = exc
            if root_descriptor >= 0:
                try:
                    _require_visible_output_identity(
                        visible_root,
                        destination_parent_descriptor=destination_parent_descriptor,
                        expected_parent_identity=expected_parent_identity,
                        expected_output_identity=root_identity,
                    )
                except BaseException as exc:
                    if validation_error is None:
                        validation_error = exc
            for descriptor in (saved_cwd_descriptor, root_descriptor):
                if descriptor < 0:
                    continue
                try:
                    os.close(descriptor)
                except BaseException as exc:
                    if validation_error is None:
                        validation_error = exc
            if validation_error is not None:
                raise validation_error


def _require_visible_existing_directory_identity(
    path: Path,
    *,
    expected_identity: tuple[int, int],
) -> None:
    if _running_on_windows():
        _require_windows_visible_directory_identity(path, expected_identity=expected_identity)
        return
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise UnsafePathError("The selected extraction was no longer visible safely.") from exc
    if (
        _is_link_or_reparse_metadata(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
        or (int(metadata.st_dev), int(metadata.st_ino)) != expected_identity
    ):
        raise UnsafePathError("The selected extraction identity changed while it was processed.")


@contextmanager
def anchored_existing_extraction_root(
    extraction_root: Path,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> Iterator[Path]:
    """Hold one existing extraction root for standalone analysis or reporting.

    On POSIX, all descendant operations run relative to the exact opened inode.
    On Windows, every ancestor and the root remain held without delete sharing.
    The visible path must still name the same root when the operation finishes.
    """

    visible_root = require_local_recovery_source(extraction_root)
    if _running_on_windows():
        token = None
        root_identity = (0, 0)
        windows_state: _WindowsBoundOutputState | None = None
        with _windows_pinned_absolute_directory_handle(
            visible_root,
            writable=True,
        ) as root_handle:
            _windows_require_private_acl(root_handle)
            root_identity = _windows_directory_identity(root_handle)
            try:
                windows_state = _WindowsBoundOutputState(
                    handle=root_handle,
                    identity=root_identity,
                    visible_root=visible_root,
                )
                token = _WINDOWS_BOUND_OUTPUT_STATE.set(windows_state)
                _windows_hold_existing_descendant_directories(
                    visible_root,
                    cancellation_check=cancellation_check,
                )
                yield visible_root
            finally:
                validation_error: BaseException | None = None
                try:
                    if _windows_directory_identity(root_handle) != root_identity:
                        raise UnsafePathError(
                            "The trusted Windows extraction-root handle identity changed."
                        )
                    _require_visible_existing_directory_identity(
                        visible_root,
                        expected_identity=root_identity,
                    )
                except BaseException as exc:
                    validation_error = exc
                if windows_state is not None:
                    try:
                        _windows_close_bound_descendant_directories(windows_state)
                    except BaseException as exc:
                        if validation_error is None:
                            validation_error = exc
                if token is not None:
                    _WINDOWS_BOUND_OUTPUT_STATE.reset(token)
                if validation_error is not None:
                    raise validation_error
        return

    saved_cwd_descriptor = -1
    root_descriptor = -1
    root_identity = (0, 0)
    token = None
    temporary_context = None
    with _POSIX_CWD_ANCHOR_LOCK:
        try:
            _require_dedicated_cwd_process()
            try:
                before = visible_root.lstat()
            except OSError as exc:
                raise UnsafePathError(
                    "The selected extraction root could not be opened safely."
                ) from exc
            if _is_link_or_reparse_metadata(before) or not stat.S_ISDIR(before.st_mode):
                raise UnsafePathError("The selected extraction root was not a regular directory.")
            saved_cwd_descriptor = os.open(".", _descriptor_flags(stat.S_IFDIR))
            root_descriptor = os.open(visible_root, _descriptor_flags(stat.S_IFDIR))
            opened = os.fstat(root_descriptor)
            root_identity = (int(opened.st_dev), int(opened.st_ino))
            if (
                not stat.S_ISDIR(opened.st_mode)
                or (int(before.st_dev), int(before.st_ino)) != root_identity
            ):
                raise UnsafePathError("The selected extraction root changed while it was opened.")
            os.fchdir(root_descriptor)
            token = _ANCHORED_OUTPUT_STATE.set(
                _AnchoredOutputState(descriptor=root_descriptor, identity=root_identity)
            )
            _require_anchored_working_directory()
            temporary_context = _anchored_relative_temporary_directories()
            temporary_context.__enter__()
            yield Path(".")
        finally:
            validation_error: BaseException | None = None
            if root_descriptor >= 0 and token is not None:
                try:
                    _require_anchored_working_directory()
                except BaseException as exc:
                    validation_error = exc
            if temporary_context is not None:
                try:
                    temporary_context.__exit__(None, None, None)
                except BaseException as exc:
                    if validation_error is None:
                        validation_error = exc
            if token is not None:
                _ANCHORED_OUTPUT_STATE.reset(token)
            if saved_cwd_descriptor >= 0:
                try:
                    os.fchdir(saved_cwd_descriptor)
                except BaseException as exc:
                    if validation_error is None:
                        validation_error = exc
            if root_descriptor >= 0:
                try:
                    _require_visible_existing_directory_identity(
                        visible_root,
                        expected_identity=root_identity,
                    )
                except BaseException as exc:
                    if validation_error is None:
                        validation_error = exc
            for descriptor in (saved_cwd_descriptor, root_descriptor):
                if descriptor < 0:
                    continue
                try:
                    os.close(descriptor)
                except BaseException as exc:
                    if validation_error is None:
                        validation_error = exc
            if validation_error is not None:
                raise validation_error


def _path_ancestry_tails(path: Path) -> tuple[tuple[tuple[int, int], tuple[str, ...]], ...]:
    """Bind every existing ancestor identity to its remaining lexical tail.

    A path string is not a filesystem identity: case-insensitive volumes and
    bind/nullfs mounts can expose the same directory through different spellings.
    The tail lets ``is_within`` compare the relationship below a shared physical
    ancestor without mistaking an ordinary common root for overlap.
    """

    current = no_link_absolute_path(path)
    tail: tuple[str, ...] = ()
    result: list[tuple[tuple[int, int], tuple[str, ...]]] = []
    while True:
        try:
            metadata = recovery_path_metadata(current)
        except FileNotFoundError:
            if current == current.parent:
                break
            tail = (current.name.casefold(), *tail)
            current = current.parent
            continue
        except OSError as exc:
            raise UnsafePathError("A path identity could not be validated safely.") from exc
        if _is_link_or_reparse_metadata(metadata):
            raise UnsafePathError("A path identity traversed a link or reparse point.")
        result.append(((int(metadata.st_dev), int(metadata.st_ino)), tail))
        if current == current.parent:
            break
        tail = (current.name.casefold(), *tail)
        current = current.parent
    return tuple(result)


def _tail_is_within(path_tail: tuple[str, ...], parent_tail: tuple[str, ...]) -> bool:
    return len(parent_tail) <= len(path_tail) and path_tail[: len(parent_tail)] == parent_tail


def is_within(path: Path, parent: Path) -> bool:
    """Return whether ``path`` is physically at or beneath ``parent``.

    The lexical case-folded check is intentionally conservative on
    case-sensitive filesystems. The identity check additionally catches
    case aliases and bind/nullfs aliases wherever both paths share an existing
    physical ancestor.
    """

    safe_path = no_link_absolute_path(path)
    safe_parent = no_link_absolute_path(parent)
    if _is_within_casefolded(safe_path, safe_parent):
        return True

    path_ancestry = _path_ancestry_tails(safe_path)
    parent_ancestry = _path_ancestry_tails(safe_parent)
    for path_identity, path_tail in path_ancestry:
        for parent_identity, parent_tail in parent_ancestry:
            if path_identity == parent_identity and _tail_is_within(path_tail, parent_tail):
                return True
    return False


def nearest_git_root(path: Path) -> Path | None:
    if _ANCHORED_OUTPUT_STATE.get() is not None and not path.expanduser().is_absolute():
        candidate = no_link_absolute_path(path)
        if not recovery_path_is_directory(candidate):
            candidate = candidate.parent
        while not recovery_path_exists(candidate) and candidate != Path("."):
            candidate = candidate.parent
        current = candidate
        while True:
            if recovery_path_exists(current / ".git"):
                return current
            if current == Path("."):
                return None
            current = current.parent
    candidate = canonical_path(path)
    if not recovery_path_is_directory(candidate):
        candidate = candidate.parent
    while not recovery_path_exists(candidate) and candidate != candidate.parent:
        candidate = candidate.parent
    for current in (candidate, *candidate.parents):
        if recovery_path_exists(current / ".git"):
            return current
    return None


def _darwin_acl_libc() -> Any:
    """Load the descriptor-based Darwin ACL API without adding a package dependency."""

    if sys.platform != "darwin":
        raise RuntimeError("Darwin ACL APIs are unavailable on this platform")
    global _DARWIN_ACL_LIBC
    if _DARWIN_ACL_LIBC is not None:
        return _DARWIN_ACL_LIBC

    acl_pointer = ctypes.c_void_p
    libc = ctypes.CDLL(None, use_errno=True)
    libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.acl_get_fd_np.restype = acl_pointer
    libc.acl_get_entry.argtypes = [acl_pointer, ctypes.c_int, ctypes.POINTER(acl_pointer)]
    libc.acl_get_entry.restype = ctypes.c_int
    libc.acl_get_flagset_np.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(acl_pointer),
    ]
    libc.acl_get_flagset_np.restype = ctypes.c_int
    libc.acl_get_flag_np.argtypes = [acl_pointer, ctypes.c_int]
    libc.acl_get_flag_np.restype = ctypes.c_int
    libc.acl_init.argtypes = [ctypes.c_int]
    libc.acl_init.restype = acl_pointer
    libc.acl_set_fd_np.argtypes = [ctypes.c_int, acl_pointer, ctypes.c_int]
    libc.acl_set_fd_np.restype = ctypes.c_int
    libc.acl_free.argtypes = [ctypes.c_void_p]
    libc.acl_free.restype = ctypes.c_int
    _DARWIN_ACL_LIBC = libc
    return libc


def _raise_acl_os_error(operation: str) -> None:
    code = ctypes.get_errno() or errno.EIO
    raise OSError(code, f"{operation} failed: {os.strerror(code)}")


def extended_acl_state(descriptor: int) -> ExtendedACLState:
    """Return Darwin extended-ACL counts for an open descriptor.

    Other supported platforms retain their existing permission model. On Darwin,
    an absent ACL and an allocated zero-entry ACL both return zero counts; every
    retrieval or enumeration error fails closed.
    """

    if sys.platform != "darwin":
        return ExtendedACLState(entry_count=0, inherited_entry_count=0)

    libc = _darwin_acl_libc()
    ctypes.set_errno(0)
    acl = libc.acl_get_fd_np(descriptor, _DARWIN_ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return ExtendedACLState(entry_count=0, inherited_entry_count=0)
        _raise_acl_os_error("acl_get_fd_np")

    try:
        entry_count = 0
        inherited_entry_count = 0
        selector = _DARWIN_ACL_FIRST_ENTRY
        entry = ctypes.c_void_p()
        while True:
            ctypes.set_errno(0)
            result = libc.acl_get_entry(acl, selector, ctypes.byref(entry))
            if result == -1:
                if ctypes.get_errno() in {errno.EINVAL, errno.ENOENT}:
                    break
                _raise_acl_os_error("acl_get_entry")
            if result != 0 or not entry:
                raise OSError(errno.EIO, "acl_get_entry returned an invalid entry")

            entry_count += 1
            flagset = ctypes.c_void_p()
            ctypes.set_errno(0)
            if libc.acl_get_flagset_np(entry, ctypes.byref(flagset)) != 0:
                _raise_acl_os_error("acl_get_flagset_np")
            ctypes.set_errno(0)
            inherited = libc.acl_get_flag_np(flagset, _DARWIN_ACL_ENTRY_INHERITED)
            if inherited == -1:
                _raise_acl_os_error("acl_get_flag_np")
            inherited_entry_count += int(inherited == 1)
            selector = _DARWIN_ACL_NEXT_ENTRY
        return ExtendedACLState(
            entry_count=entry_count,
            inherited_entry_count=inherited_entry_count,
        )
    finally:
        libc.acl_free(acl)


def _clear_darwin_extended_acl(descriptor: int) -> None:
    if sys.platform != "darwin":
        return
    libc = _darwin_acl_libc()
    ctypes.set_errno(0)
    empty_acl = libc.acl_init(0)
    if not empty_acl:
        _raise_acl_os_error("acl_init")
    try:
        ctypes.set_errno(0)
        if libc.acl_set_fd_np(descriptor, empty_acl, _DARWIN_ACL_TYPE_EXTENDED) != 0:
            _raise_acl_os_error("acl_set_fd_np")
    finally:
        libc.acl_free(empty_acl)


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return (getattr(metadata, "st_dev", 0), getattr(metadata, "st_ino", 0))


def _require_expected_type(metadata: os.stat_result, expected_type: int) -> None:
    if stat.S_IFMT(metadata.st_mode) != expected_type:
        raise UnsafePathError("A private recovery artifact had an unsafe file type.")


def require_private_descriptor(
    descriptor: int,
    *,
    expected_type: int,
    expected_mode: int | None = None,
) -> os.stat_result:
    """Validate ownership, mode, and Darwin ACL state on an open descriptor."""

    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise UnsafePathError("Private recovery permissions could not be verified.") from exc
    _require_expected_type(metadata, expected_type)
    if os.name == "nt":
        try:
            import msvcrt

            _windows_require_private_acl(int(msvcrt.get_osfhandle(descriptor)))
        except (ImportError, OSError, TypeError, ValueError) as exc:
            raise UnsafePathError(
                "Private Windows recovery permissions could not be verified."
            ) from exc
    else:
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise UnsafePathError("A private recovery artifact was not private to this user.")
        if expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise UnsafePathError("A private recovery artifact had unexpected permissions.")
    if sys.platform == "darwin":
        try:
            acl_state = extended_acl_state(descriptor)
        except OSError as exc:
            raise UnsafePathError("Private recovery ACLs could not be verified safely.") from exc
        if acl_state.entry_count:
            raise UnsafePathError("A private recovery artifact retained an extended ACL.")
    return metadata


def harden_private_descriptor(
    descriptor: int,
    *,
    expected_type: int,
    mode: int,
) -> os.stat_result:
    """Remove Darwin extended ACLs and set an exact private mode on one descriptor."""

    try:
        before = os.fstat(descriptor)
    except OSError as exc:
        raise UnsafePathError("Private recovery permissions could not be applied.") from exc
    _require_expected_type(before, expected_type)
    if os.name != "nt" and before.st_uid != os.geteuid():
        raise UnsafePathError("Refusing to change permissions on an unowned artifact.")

    try:
        if sys.platform == "darwin" and extended_acl_state(descriptor).entry_count:
            _clear_darwin_extended_acl(descriptor)
        if os.name != "nt":
            os.fchmod(descriptor, mode)
    except OSError as exc:
        raise UnsafePathError("Private recovery permissions could not be applied safely.") from exc

    after = require_private_descriptor(
        descriptor,
        expected_type=expected_type,
        expected_mode=mode if os.name != "nt" else None,
    )
    if _identity(before) != _identity(after):
        raise UnsafePathError("A private recovery artifact changed while securing it.")
    return after


def _descriptor_flags(expected_type: int) -> int:
    if expected_type == stat.S_IFDIR:
        flags = getattr(os, "O_SEARCH", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    else:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    return flags


def require_private_path(
    path: Path,
    *,
    expected_type: int,
    expected_mode: int | None = None,
) -> os.stat_result:
    """Open a path without following links and validate its descriptor-bound privacy state."""

    path = no_link_absolute_path(path)
    if _running_on_windows():
        if expected_type == stat.S_IFDIR:
            with _windows_pinned_absolute_directory_handle(path) as handle:
                _windows_require_private_acl(handle)
                return _windows_enumerated_path_metadata(path)
        if expected_type == stat.S_IFREG:
            with _windows_locked_regular_file_descriptor(path) as (descriptor, _native):
                return require_private_descriptor(
                    descriptor,
                    expected_type=expected_type,
                    expected_mode=expected_mode,
                )
        raise UnsafePathError("A private recovery artifact had an unsafe file type.")
    try:
        before = path.lstat()
    except OSError as exc:
        raise UnsafePathError("A private recovery artifact was unavailable.") from exc
    if _is_link_or_reparse_point(path):
        raise UnsafePathError("A private recovery artifact redirected through a link.")
    _require_expected_type(before, expected_type)
    descriptor = -1
    try:
        descriptor = os.open(path, _descriptor_flags(expected_type))
        opened = os.fstat(descriptor)
        if _identity(before) != _identity(opened):
            raise UnsafePathError("A private recovery artifact changed while it was opened.")
        verified = require_private_descriptor(
            descriptor,
            expected_type=expected_type,
            expected_mode=expected_mode,
        )
        after = path.lstat()
        if _identity(verified) != _identity(after) or _is_link_or_reparse_point(path):
            raise UnsafePathError("A private recovery artifact changed during validation.")
        return verified
    except OSError as exc:
        raise UnsafePathError("A private recovery artifact could not be opened safely.") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _harden_private_path(path: Path, *, expected_type: int, mode: int) -> os.stat_result:
    path = no_link_absolute_path(path)
    if _is_link_or_reparse_point(path):
        raise UnsafePathError("Refusing to secure a symbolic link or reparse point.")
    if os.name == "nt":
        try:
            path.chmod(mode)
            return path.lstat()
        except OSError:
            # Windows ACLs are not represented by POSIX modes. Platform guidance
            # retains the existing encrypted-destination requirement.
            return path.lstat()

    before = path.lstat()
    _require_expected_type(before, expected_type)
    descriptor = -1
    try:
        descriptor = os.open(path, _descriptor_flags(expected_type))
        opened = os.fstat(descriptor)
        if _identity(before) != _identity(opened):
            raise UnsafePathError("A private recovery artifact changed while it was opened.")
        secured = harden_private_descriptor(
            descriptor,
            expected_type=expected_type,
            mode=mode,
        )
        after = path.lstat()
        if _identity(secured) != _identity(after) or _is_link_or_reparse_point(path):
            raise UnsafePathError("A private recovery artifact changed while securing it.")
        return secured
    except OSError as exc:
        raise UnsafePathError("A private recovery artifact could not be secured safely.") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def secure_directory(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise UnsafePathError(f"Refusing to use a symbolic-link directory: {expanded}")
    resolved = no_link_absolute_path(expanded)

    # pathlib's parents=True creates the whole missing chain before callers can
    # clear inherited ACLs. Build it one component at a time instead, securing
    # each new directory before it can contain the next directory or any bytes.
    missing: list[Path] = []
    existing = resolved
    while True:
        try:
            metadata = existing.lstat()
        except FileNotFoundError:
            missing.append(existing)
            if existing == existing.parent:
                raise UnsafePathError(
                    f"Could not find a safe parent directory for: {resolved}"
                ) from None
            existing = existing.parent
            continue
        if _is_link_or_reparse_point(existing) or not stat.S_ISDIR(metadata.st_mode):
            raise UnsafePathError(f"Expected a regular directory ancestor: {existing}")
        break

    if not missing:
        _harden_private_path(resolved, expected_type=stat.S_IFDIR, mode=0o700)
        if _running_on_windows():
            _windows_hold_bound_descendant_directory(resolved)
        return resolved

    for directory in reversed(missing):
        if _running_on_windows() and _WINDOWS_BOUND_OUTPUT_STATE.get() is not None:
            _windows_create_and_hold_bound_descendant_directory(directory)
            continue
        # A concurrent replacement is acceptable only if the descriptor-bound
        # hardening below proves it is the intended owned directory.
        with suppress(FileExistsError):
            directory.mkdir(mode=0o700)
        _harden_private_path(directory, expected_type=stat.S_IFDIR, mode=0o700)
        if _running_on_windows():
            _windows_hold_bound_descendant_directory(directory)
    return resolved


@contextmanager
def private_temporary_directory(
    *,
    parent: Path,
    prefix: str,
) -> Iterator[Path]:
    """Create a private temporary directory with a bounded Windows capability lifetime."""

    if not prefix or any(character in prefix for character in ("/", "\\", "\x00")):
        raise ValueError("A private temporary-directory prefix must be one safe path component.")
    if _running_on_windows():
        secure_parent = secure_directory(parent)
        state = _WINDOWS_BOUND_OUTPUT_STATE.get()
        directory: Path | None = None
        local_handle = -1
        expected_identity: tuple[int, int] | None = None
        for _attempt in range(128):
            candidate = secure_parent / f"{prefix}{secrets.token_hex(16)}"
            try:
                if state is not None:
                    _windows_create_and_hold_bound_descendant_directory(candidate)
                    _visible, _handle, expected_identity = state.descendant_handles[
                        _casefolded_path(candidate)
                    ]
                else:
                    with _windows_pinned_absolute_directory_handle(
                        secure_parent,
                        writable=True,
                    ) as parent_handle:
                        _windows_native.require_private_ntfs_volume(parent_handle)
                        local_handle = _windows_native.create_fresh_directory(
                            parent_handle,
                            candidate.name,
                        )
                    expected_identity = _windows_directory_identity(local_handle)
                directory = candidate
                break
            except (OutputExistsError, _windows_native.WindowsObjectExistsError):
                continue
            except _windows_native.WindowsNativeError as exc:
                raise UnsafePathError(
                    "A private Windows temporary directory could not be created safely."
                ) from exc
        if directory is None or expected_identity is None:
            raise UnsafePathError("A private temporary directory could not be allocated safely.")
        try:
            yield directory
        finally:
            if state is not None:
                windows_delete_bound_private_tree(directory)
            else:
                cleanup_handle = local_handle
                local_handle = -1
                _windows_delete_private_tree_handle(
                    directory,
                    handle=cleanup_handle,
                    expected_identity=expected_identity,
                )
        return
    with tempfile.TemporaryDirectory(prefix=prefix, dir=parent) as temporary:
        directory = secure_directory(Path(temporary))
        try:
            yield directory
        finally:
            _windows_release_bound_descendant_directory(directory)


def _is_link_or_reparse_point(path: Path) -> bool:
    """Return whether an existing path redirects traversal to another location."""

    try:
        metadata = recovery_path_metadata(path) if _running_on_windows() else path.lstat()
    except FileNotFoundError:
        return False
    return _is_link_or_reparse_metadata(metadata)


def _is_link_or_reparse_metadata(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _reject_linked_components(root: Path, target: Path) -> None:
    """Reject symbolic links or Windows reparse points beneath a trusted root."""

    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Output path escaped its root: {target}") from exc
    current = root
    for component in relative.parts:
        current /= component
        if _is_link_or_reparse_point(current):
            raise ValueError(f"Refusing path through a symbolic link or reparse point: {current}")


def iter_regular_files(root: Path) -> Iterator[Path]:
    """Yield regular files without traversing symbolic links or reparse points."""

    expanded_root = no_link_absolute_path(root)
    trusted_root = expanded_root
    require_private_path(trusted_root, expected_type=stat.S_IFDIR)

    pending = [trusted_root]
    while pending:
        current = pending.pop()
        require_private_path(current, expected_type=stat.S_IFDIR)
        directories, files = _safe_directory_entries(current)
        for entry in directories:
            require_private_path(entry.path, expected_type=stat.S_IFDIR)
        for entry in files:
            try:
                _reject_linked_components(trusted_root, entry.path)
            except ValueError as exc:
                raise UnsafePathError("The extracted file tree contained an unsafe path.") from exc
            require_private_path(entry.path, expected_type=stat.S_IFREG)
            yield entry.path
        pending.extend(entry.path for entry in reversed(directories))


def secure_file(path: Path) -> None:
    _harden_private_path(path, expected_type=stat.S_IFREG, mode=0o600)


def validate_backup_directory(path: Path) -> Path:
    backup = require_local_recovery_source(path)
    try:
        backup_metadata = (
            _windows_enumerated_path_metadata(backup) if _running_on_windows() else backup.lstat()
        )
    except OSError as exc:
        raise UserInputError("The backup directory was not found.") from exc
    if not stat.S_ISDIR(backup_metadata.st_mode):
        raise UserInputError(f"Backup directory was not found: {backup}")
    for required_name in ("Manifest.plist", "Manifest.db"):
        required = backup / required_name
        if (
            optional_local_recovery_regular_file(
                required,
                volume_already_validated=True,
            )
            is None
        ):
            raise UserInputError(
                f"{required_name} was not found as a regular backup file: {backup}"
            )
    return backup


def prepare_extraction_layout(
    backup: Path,
    output: Path,
) -> ExtractionLayout:
    backup = validate_backup_directory(backup)
    expanded_output = output.expanduser()
    if expanded_output.is_symlink():
        raise UnsafePathError(f"Refusing to use a symbolic-link output path: {expanded_output}")
    output_root = no_link_absolute_path(expanded_output)
    require_private_local_destination(output_root)
    if is_within(output_root, backup) or is_within(backup, output_root):
        raise UnsafePathError("The backup and output directories must not overlap.")

    if output_root.exists():
        raise OutputExistsError(
            f"Output path already exists: {output_root}. "
            "Choose a new dedicated folder so existing permissions and files remain untouched."
        )

    extraction_root = output_root / EXTRACTION_DIRECTORY_NAME
    git_root = nearest_git_root(extraction_root)
    if git_root is not None:
        raise UnsafePathError(
            "Refusing to place decrypted data inside a Git repository "
            f"({git_root}). Choose a separate encrypted destination."
        )
    if extraction_root.exists() or extraction_root.is_symlink():
        raise OutputExistsError(
            f"Extraction output already exists: {extraction_root}. "
            "Choose a new destination so results cannot be overwritten or mixed."
        )

    secure_directory(output_root)
    extraction_root = secure_directory(extraction_root)
    raw_root = secure_directory(extraction_root / "raw")
    metadata_root = secure_directory(extraction_root / "metadata")
    manifest_root = secure_directory(extraction_root / "manifest")
    temp_root = secure_directory(extraction_root / ".tmp")
    return ExtractionLayout(
        output_root=output_root,
        extraction_root=extraction_root,
        raw_root=raw_root,
        metadata_root=metadata_root,
        manifest_root=manifest_root,
        temp_root=temp_root,
    )


def prepare_anchored_extraction_layout(
    backup: Path,
    output_root: Path = Path("."),
) -> ExtractionLayout:
    """Create descendants beneath the active POSIX or Windows held output root."""

    if _running_on_windows():
        state = _WINDOWS_BOUND_OUTPUT_STATE.get()
        if state is None:
            raise UnsafePathError("A trusted Windows output-root handle was not active.")
        candidate = no_link_absolute_path(output_root)
        if _casefolded_path(candidate) != _casefolded_path(state.visible_root):
            raise UnsafePathError("The Windows extraction root escaped its held output handle.")
        if _windows_directory_identity(state.handle) != state.identity:
            raise UnsafePathError("The trusted Windows output-root handle identity changed.")
        _require_windows_visible_directory_identity(
            candidate,
            expected_identity=state.identity,
        )
        bound_output_root = candidate
    else:
        _require_anchored_working_directory()
        if output_root != Path("."):
            raise UnsafePathError("POSIX anchored extraction requires a relative output root.")
        bound_output_root = Path(".")
    backup = validate_backup_directory(backup)
    if not backup.is_absolute():
        raise UnsafePathError("The source backup was not bound to an absolute path.")
    try:
        with os.scandir(bound_output_root) as entries:
            if next(entries, None) is not None:
                raise OutputExistsError(
                    "The fresh destination unexpectedly contained data before extraction."
                )
    except OSError as exc:
        raise UnsafePathError("The fresh destination could not be inspected safely.") from exc

    secured_output_root = secure_directory(bound_output_root)
    extraction_root = secure_directory(secured_output_root / EXTRACTION_DIRECTORY_NAME)
    raw_root = secure_directory(extraction_root / "raw")
    metadata_root = secure_directory(extraction_root / "metadata")
    manifest_root = secure_directory(extraction_root / "manifest")
    temp_root = secure_directory(extraction_root / ".tmp")
    return ExtractionLayout(
        output_root=secured_output_root,
        extraction_root=extraction_root,
        raw_root=raw_root,
        metadata_root=metadata_root,
        manifest_root=manifest_root,
        temp_root=temp_root,
    )


def validate_extraction_directory(path: Path) -> Path:
    extraction = require_local_recovery_source(path)
    if not recovery_path_is_directory(extraction):
        raise UserInputError(f"Extraction directory was not found: {extraction}")
    require_private_path(extraction, expected_type=stat.S_IFDIR)
    try:
        raw = safe_join(extraction, "raw")
        metadata = safe_join(extraction, "metadata")
    except ValueError as exc:
        raise UnsafePathError("The extraction directory contained an unsafe path.") from exc
    if not recovery_path_is_directory(raw):
        raise UnsafePathError(f"Expected extracted raw data at: {raw}")
    require_private_path(raw, expected_type=stat.S_IFDIR)
    require_private_path(metadata, expected_type=stat.S_IFDIR)
    run_state = metadata / "run_state.json"
    if not recovery_path_is_regular_file(run_state):
        raise PartialExtractionError(
            "The extraction has no trustworthy complete run marker. Preserve it for diagnosis and "
            "run a fresh recovery into a new output folder."
        )
    try:
        state = read_json_regular(
            run_state,
            maximum_bytes=MAXIMUM_COMPLETION_MARKER_BYTES,
            require_private=True,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, UnsafePathError) as exc:
        raise PartialExtractionError(
            "The extraction complete run marker could not be validated. Preserve this output and "
            "run a fresh recovery into a new output folder."
        ) from exc
    count_keys = (
        "files_expected",
        "files_extracted",
        "bytes_extracted",
        "selected_declared_bytes",
        "size_discrepancy_count",
    )
    if (
        not isinstance(state, dict)
        or state.get("schema_version") != EXTRACTION_RUN_STATE_SCHEMA_VERSION
        or state.get("contract") != EXTRACTION_RUN_STATE_CONTRACT
        or state.get("status") != "complete"
        or any(
            not isinstance(state.get(key), int)
            or isinstance(state.get(key), bool)
            or state[key] < 0
            for key in count_keys
        )
        or state["files_expected"] != state["files_extracted"]
        or state["size_discrepancy_count"] > state["files_expected"]
    ):
        raise PartialExtractionError(
            "The extraction is marked incomplete. Preserve it for diagnosis and run a fresh "
            "recovery into a new output folder."
        )
    # Imported lazily to keep the low-level path module independent while still
    # requiring every v0.2 complete marker to carry the source-byte identity.
    from .integrity import source_snapshot_from_mapping

    try:
        source_snapshot_from_mapping(state.get("source_snapshot"))
    except PartialExtractionError as exc:
        raise PartialExtractionError(
            "The extraction complete run marker did not bind its raw data. Preserve this output "
            "and run a fresh recovery into a new output folder."
        ) from exc
    git_root = nearest_git_root(extraction)
    if git_root is not None:
        raise UnsafePathError(
            "Refusing to process decrypted data inside a Git repository "
            f"({git_root}). Move it to private storage first."
        )
    return extraction


def prepare_analysis_layout(extraction: Path) -> AnalysisLayout:
    """Create a private staging directory that is promoted only after full analysis."""

    extraction = validate_extraction_directory(extraction)
    final_root = extraction / "analysis"
    staging_root = extraction / ".analysis-incomplete"
    if final_root.exists() or final_root.is_symlink():
        raise OutputExistsError(
            f"Analysis output already exists: {final_root}. "
            "Use a fresh extraction or move the old analysis aside."
        )
    if staging_root.exists() or staging_root.is_symlink():
        raise OutputExistsError(
            "An incomplete analysis staging directory already exists. Preserve it for diagnosis "
            "and run recovery again into a fresh destination."
        )
    return AnalysisLayout(
        final_root=final_root,
        staging_root=secure_directory(staging_root),
    )


def _validate_portable_component(value: str, *, label: str) -> str:
    if not value or value in {".", ".."}:
        raise ValueError(f"Unsafe {label}: {value!r}")
    if value != value.rstrip(" ."):
        raise ValueError(f"Unsafe {label} with a trailing space or dot: {value!r}")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"Unsafe control character in {label}: {value!r}")
    if any(character in WINDOWS_INVALID_CHARACTERS for character in value):
        raise ValueError(f"Unsafe cross-platform character in {label}: {value!r}")
    base_name = value.split(".", 1)[0].upper()
    if base_name in WINDOWS_RESERVED_NAMES:
        raise ValueError(f"Unsafe reserved Windows name in {label}: {value!r}")
    return value


def safe_manifest_relative_path(value: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError(f"Unsafe backup path: {value!r}")
    posix = PurePosixPath(value)
    if posix.is_absolute() or not posix.parts or posix.as_posix() != value:
        raise ValueError(f"Unsafe backup path: {value!r}")
    for part in posix.parts:
        _validate_portable_component(part, label="backup path component")
    return Path(*posix.parts)


def safe_domain_component(value: str) -> str:
    if not isinstance(value, str) or "/" in value or "\\" in value or "\x00" in value:
        raise ValueError(f"Unsafe backup domain: {value!r}")
    return _validate_portable_component(value, label="backup domain")


def validate_file_id(value: str) -> str:
    if not isinstance(value, str) or FILE_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("Manifest file ID was not a 40-character hexadecimal value")
    return value.lower()


def safe_join(root: Path, *parts: str | Path) -> Path:
    root = no_link_absolute_path(root)
    if _ANCHORED_OUTPUT_STATE.get() is not None and not root.is_absolute():
        if any(Path(part).is_absolute() or ".." in Path(part).parts for part in parts):
            raise ValueError("Output path escaped its trusted root.")
        target = root.joinpath(*parts)
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"Output path escaped its root: {target}") from exc
        _reject_linked_components(root, target)
        return no_link_absolute_path(target)
    target = Path(os.path.abspath(os.fspath(root.joinpath(*parts))))
    _reject_linked_components(root, target)
    safe_target = no_link_absolute_path(target)
    if not is_within(safe_target, root):
        raise ValueError(f"Output path escaped its root: {target}")
    return safe_target


def private_source_id(key: object, subkey: object) -> str:
    value = f"{key!s}\x00{subkey!s}".encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(value).hexdigest()[:24]


def sanitize_public_url(value: str) -> str:
    """Remove credentials, fragments, and nonessential query data from a URL."""

    if not isinstance(value, str) or not value.startswith(("https://", "http://")):
        return ""
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        if parsed.username is not None or parsed.password is not None:
            return ""
        port = parsed.port
    except ValueError:
        return ""

    hostname = parsed.hostname.lower()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname if port is None else f"{hostname}:{port}"
    query = ""
    if parsed.hostname.lower() in {"youtube.com", "www.youtube.com", "m.youtube.com"}:
        video_ids = [item for item in parse_qsl(parsed.query) if item[0] == "v" and item[1]]
        if video_ids:
            query = urlencode([video_ids[0]])
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))


def _open_flags() -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _reader_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


_REGULAR_FILE_STABLE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _same_opened_file(before: os.stat_result, opened: os.stat_result) -> bool:
    """Require one regular descriptor to match the complete stable path snapshot."""

    return all(
        getattr(before, field, None) == getattr(opened, field, None)
        for field in _REGULAR_FILE_STABLE_FIELDS
    )


@contextmanager
def regular_text_reader(
    path: Path,
    *,
    newline: str | None = None,
    require_private: bool = False,
) -> Iterator[TextIO]:
    """Open a regular UTF-8 file without following a link or Windows reparse point."""

    with regular_binary_reader(path, require_private=require_private) as (binary, _opened):
        handle = io.TextIOWrapper(binary, encoding="utf-8", newline=newline)
        try:
            yield handle
        finally:
            try:
                handle.detach()
            except (OSError, ValueError) as exc:
                raise UnsafePathError(
                    "A required private data file could not be read safely."
                ) from exc


@contextmanager
def regular_binary_reader(
    path: Path,
    *,
    require_private: bool = False,
) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """Hold one stable no-follow regular-file descriptor through a caller's bounded reads."""

    if _running_on_windows():
        with _windows_locked_regular_file_descriptor(path) as (descriptor, native_before):
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or opened.st_size != native_before.byte_size:
                    raise UnsafePathError("A required private data file was not a regular file.")
                if require_private:
                    require_private_descriptor(descriptor, expected_type=stat.S_IFREG)
                handle = os.fdopen(descriptor, "rb", buffering=0, closefd=False)
            except OSError as exc:
                raise UnsafePathError(
                    "A required private data file could not be opened safely."
                ) from exc
            try:
                try:
                    yield handle, opened
                finally:
                    handle.close()
                    after = os.fstat(descriptor)
                    if not _same_opened_file(opened, after):
                        raise UnsafePathError(
                            "A required private data file changed while it was read."
                        )
                    if require_private:
                        require_private_descriptor(descriptor, expected_type=stat.S_IFREG)
            except OSError as exc:
                raise UnsafePathError(
                    "A required private data file could not be read safely."
                ) from exc
        return

    try:
        before = path.lstat()
    except OSError as exc:
        raise UnsafePathError("A required private data file was unavailable.") from exc
    if _is_link_or_reparse_metadata(before) or not stat.S_ISREG(before.st_mode):
        raise UnsafePathError("A required private data file was not a regular file.")

    descriptor = -1
    try:
        descriptor = os.open(path, _reader_flags())
        opened = os.fstat(descriptor)
        if not _same_opened_file(before, opened):
            raise UnsafePathError("A required private data file changed while it was opened.")
        if require_private:
            require_private_descriptor(descriptor, expected_type=stat.S_IFREG)
        handle = os.fdopen(descriptor, "rb", buffering=0)
        descriptor = -1
    except OSError as exc:
        raise UnsafePathError("A required private data file could not be opened safely.") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    try:
        try:
            yield handle, opened
        finally:
            try:
                after = os.fstat(handle.fileno())
                if require_private:
                    require_private_descriptor(handle.fileno(), expected_type=stat.S_IFREG)
                path_after = path.lstat()
            except OSError as exc:
                raise UnsafePathError(
                    "A required private data file changed while it was read."
                ) from exc
            finally:
                handle.close()
            if (
                any(
                    getattr(opened, field, None) != getattr(after, field, None)
                    for field in _REGULAR_FILE_STABLE_FIELDS
                )
                or _is_link_or_reparse_metadata(path_after)
                or any(
                    getattr(after, field, None) != getattr(path_after, field, None)
                    for field in _REGULAR_FILE_STABLE_FIELDS
                )
            ):
                raise UnsafePathError("A required private data file changed while it was read.")
    except OSError as exc:
        raise UnsafePathError("A required private data file could not be read safely.") from exc


def read_regular_bytes(
    path: Path,
    *,
    maximum_bytes: int,
    require_private: bool = False,
) -> bytes:
    """Read exact bounded bytes from one stable no-follow regular-file identity."""

    if maximum_bytes <= 0:
        raise ValueError("maximum_bytes must be positive")
    payload = bytearray()
    try:
        with regular_binary_reader(path, require_private=require_private) as (handle, opened):
            if opened.st_size <= 0 or opened.st_size > maximum_bytes:
                raise UnsafePathError(
                    "A required private data file had an unsafe file type or byte size."
                )
            while len(payload) <= maximum_bytes:
                chunk = handle.read(min(1024 * 1024, maximum_bytes + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
    except OSError as exc:
        raise UnsafePathError("A required private data file could not be read safely.") from exc

    if len(payload) != opened.st_size or len(payload) > maximum_bytes:
        raise UnsafePathError("A required private data file changed while it was read.")
    return bytes(payload)


def read_json_regular(
    path: Path,
    *,
    maximum_bytes: int | None = None,
    require_private: bool = False,
) -> Any:
    """Read JSON through the same descriptor-based no-follow checks as CSV input."""

    if maximum_bytes is not None and maximum_bytes <= 0:
        raise ValueError("maximum_bytes must be positive")
    if maximum_bytes is not None:
        payload = read_regular_bytes(
            path,
            maximum_bytes=maximum_bytes,
            require_private=require_private,
        )
        return json.loads(payload.decode("utf-8"))
    with regular_text_reader(path, require_private=require_private) as handle:
        return json.load(handle)


def _fsync_parent_directory(path: Path) -> None:
    """Durably record a rename where directory fsync is supported."""

    if os.name == "nt":
        # Windows has no portable directory-fsync API. The fully flushed sibling
        # followed by os.replace is the strongest portable fallback here.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        require_private_descriptor(descriptor, expected_type=stat.S_IFDIR)
        os.fsync(descriptor)
    except OSError as exc:
        if exc.errno not in {
            errno.EINVAL,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        }:
            raise
    finally:
        os.close(descriptor)


def _atomic_no_replace_error(error_number: int, destination: Path) -> None:
    if error_number in {errno.EEXIST, getattr(errno, "ENOTEMPTY", errno.EEXIST)}:
        raise OutputExistsError(
            "The destination appeared before atomic promotion. Nothing was overwritten; "
            "preserve the incomplete output and retry into a fresh destination."
        )
    if error_number in {
        errno.EINVAL,
        getattr(errno, "ENOSYS", errno.EINVAL),
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }:
        raise UnsafePathError(
            "This filesystem does not provide atomic no-overwrite promotion. The incomplete "
            "output was preserved; retry on a supported private local filesystem."
        )
    raise OSError(error_number, os.strerror(error_number), os.fspath(destination))


def _darwin_rename_no_replace(
    source_parent_descriptor: int,
    destination_parent_descriptor: int,
    source_name: str,
    destination_name: str,
    destination: Path,
) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameatx = libc.renameatx_np
    except (AttributeError, OSError) as exc:
        raise UnsafePathError(
            "Atomic no-overwrite promotion was unavailable on this macOS system."
        ) from exc
    renameatx.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameatx.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameatx(
        source_parent_descriptor,
        os.fsencode(source_name),
        destination_parent_descriptor,
        os.fsencode(destination_name),
        _DARWIN_RENAME_EXCL,
    )
    if result != 0:
        _atomic_no_replace_error(ctypes.get_errno() or errno.EIO, destination)


def _linux_rename_no_replace(
    source_parent_descriptor: int,
    destination_parent_descriptor: int,
    source_name: str,
    destination_name: str,
    destination: Path,
) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError) as exc:
        raise UnsafePathError(
            "Atomic no-overwrite promotion was unavailable on this Linux system."
        ) from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameat2(
        source_parent_descriptor,
        os.fsencode(source_name),
        destination_parent_descriptor,
        os.fsencode(destination_name),
        _LINUX_RENAME_NOREPLACE,
    )
    if result != 0:
        _atomic_no_replace_error(ctypes.get_errno() or errno.EIO, destination)


def _rename_directory_no_replace(
    *,
    source_parent_descriptor: int,
    destination_parent_descriptor: int,
    source: Path,
    destination: Path,
) -> None:
    if sys.platform == "darwin":
        _darwin_rename_no_replace(
            source_parent_descriptor,
            destination_parent_descriptor,
            source.name,
            destination.name,
            destination,
        )
        return
    if sys.platform.startswith("linux"):
        _linux_rename_no_replace(
            source_parent_descriptor,
            destination_parent_descriptor,
            source.name,
            destination.name,
            destination,
        )
        return
    raise UnsafePathError(
        "Atomic no-overwrite directory promotion is unsupported on this platform."
    )


def _promote_path_no_replace_atomic(
    source: Path,
    destination: Path,
    *,
    expected_type: int,
    expected_identity: tuple[int, int] | None = None,
    held_descriptor: int | None = None,
    durable: bool = False,
) -> None:
    """Atomically rename one private path without replacing any destination."""

    if expected_type not in {stat.S_IFDIR, stat.S_IFREG}:
        raise ValueError("Atomic no-overwrite promotion received an unsupported file type.")
    if expected_identity is not None:
        expected_identity = _validated_directory_identity(expected_identity)

    source = no_link_absolute_path(source)
    destination = no_link_absolute_path(destination)
    if (
        source.name in {"", ".", ".."}
        or destination.name in {"", ".", ".."}
        or source == destination
    ):
        raise UnsafePathError("Atomic no-overwrite promotion requires distinct safe paths.")

    if _running_on_windows():
        source_metadata = require_private_path(source, expected_type=expected_type)
        if expected_identity is not None and _identity(source_metadata) != expected_identity:
            raise UnsafePathError("The staged path identity changed before atomic promotion.")
        try:
            destination.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise UnsafePathError(
                "The promotion destination could not be checked before promotion."
            ) from exc
        else:
            raise OutputExistsError(
                "The destination appeared before atomic promotion. Nothing was overwritten; "
                "preserve the incomplete output and retry into a fresh destination."
            )
        if held_descriptor is not None:
            if expected_type != stat.S_IFREG:
                raise UnsafePathError(
                    "A held Windows descriptor can promote only a regular staging file."
                )
            _windows_promote_held_file_no_replace(
                source,
                destination,
                held_descriptor=held_descriptor,
            )
        elif expected_type == stat.S_IFDIR and _WINDOWS_BOUND_OUTPUT_STATE.get() is not None:
            _windows_promote_bound_directory_no_replace(source, destination)
        else:
            try:
                # Windows os.rename is atomic and refuses an existing destination.
                os.rename(source, destination)
            except OSError as exc:
                if isinstance(exc, FileExistsError) or getattr(exc, "winerror", None) in {80, 183}:
                    raise OutputExistsError(
                        "The destination appeared before atomic promotion. Nothing was "
                        "overwritten; preserve the incomplete output and retry into a fresh "
                        "destination."
                    ) from exc
                raise
        promoted = require_private_path(destination, expected_type=expected_type)
        if _identity(promoted) != _identity(source_metadata):
            raise UnsafePathError("The promoted path identity changed unexpectedly.")
        return

    source_parent = source.parent
    destination_parent = destination.parent
    try:
        source_parent_before = source_parent.lstat()
        destination_parent_before = destination_parent.lstat()
    except OSError as exc:
        raise UnsafePathError("A promotion parent was unavailable.") from exc
    if (
        _is_link_or_reparse_metadata(source_parent_before)
        or not stat.S_ISDIR(source_parent_before.st_mode)
        or _is_link_or_reparse_metadata(destination_parent_before)
        or not stat.S_ISDIR(destination_parent_before.st_mode)
    ):
        raise UnsafePathError("A promotion parent was not a safe regular directory.")

    source_parent_descriptor = -1
    destination_parent_descriptor = -1
    source_descriptor = -1
    try:
        source_parent_descriptor = os.open(
            source_parent,
            _descriptor_flags(stat.S_IFDIR),
        )
        destination_parent_descriptor = os.open(
            destination_parent,
            _descriptor_flags(stat.S_IFDIR),
        )
        opened_source_parent = require_private_descriptor(
            source_parent_descriptor,
            expected_type=stat.S_IFDIR,
        )
        opened_destination_parent = require_private_descriptor(
            destination_parent_descriptor,
            expected_type=stat.S_IFDIR,
        )
        if _identity(source_parent_before) != _identity(opened_source_parent) or _identity(
            destination_parent_before
        ) != _identity(opened_destination_parent):
            raise UnsafePathError("A promotion parent changed while it was opened.")
        if int(opened_source_parent.st_dev) != int(opened_destination_parent.st_dev):
            raise UnsafePathError("Atomic promotion requires paths on the same filesystem.")

        try:
            source_descriptor = os.open(
                source.name,
                _descriptor_flags(expected_type),
                dir_fd=source_parent_descriptor,
            )
        except OSError as exc:
            raise UnsafePathError("The staged path could not be opened safely.") from exc
        source_metadata = require_private_descriptor(
            source_descriptor,
            expected_type=expected_type,
        )
        if expected_identity is not None and _identity(source_metadata) != expected_identity:
            raise UnsafePathError("The staged path identity changed before atomic promotion.")
        try:
            os.stat(
                destination.name,
                dir_fd=destination_parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise UnsafePathError(
                "The promotion destination could not be checked before promotion."
            ) from exc
        else:
            raise OutputExistsError(
                "The destination appeared before atomic promotion. Nothing was overwritten; "
                "preserve the incomplete output and retry into a fresh destination."
            )

        _rename_directory_no_replace(
            source_parent_descriptor=source_parent_descriptor,
            destination_parent_descriptor=destination_parent_descriptor,
            source=source,
            destination=destination,
        )
        promoted = os.stat(
            destination.name,
            dir_fd=destination_parent_descriptor,
            follow_symlinks=False,
        )
        _require_expected_type(promoted, expected_type)
        if _identity(promoted) != _identity(source_metadata):
            raise UnsafePathError("The promoted path identity changed unexpectedly.")
        source_parent_after = source_parent.lstat()
        destination_parent_after = destination_parent.lstat()
        if (
            _is_link_or_reparse_metadata(source_parent_after)
            or _identity(source_parent_after) != _identity(opened_source_parent)
            or _is_link_or_reparse_metadata(destination_parent_after)
            or _identity(destination_parent_after) != _identity(opened_destination_parent)
        ):
            raise UnsafePathError("A promotion parent changed during atomic promotion.")
        if durable:
            for descriptor in {
                source_parent_descriptor,
                destination_parent_descriptor,
            }:
                try:
                    os.fsync(descriptor)
                except OSError as exc:
                    if exc.errno not in {
                        errno.EINVAL,
                        getattr(errno, "ENOTSUP", errno.EINVAL),
                        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
                    }:
                        raise
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if destination_parent_descriptor >= 0:
            os.close(destination_parent_descriptor)
        if source_parent_descriptor >= 0:
            os.close(source_parent_descriptor)


def promote_directory_no_replace_atomic(
    source: Path,
    destination: Path,
    *,
    durable: bool = False,
) -> None:
    """Atomically rename one private directory without replacing any destination."""

    _promote_path_no_replace_atomic(
        source,
        destination,
        expected_type=stat.S_IFDIR,
        durable=durable,
    )


def promote_file_no_replace_atomic(
    source: Path,
    destination: Path,
    *,
    expected_identity: tuple[int, int] | None = None,
    held_descriptor: int | None = None,
    durable: bool = False,
) -> None:
    """Atomically rename one private regular file without replacing any destination."""

    _promote_path_no_replace_atomic(
        source,
        destination,
        expected_type=stat.S_IFREG,
        expected_identity=expected_identity,
        held_descriptor=held_descriptor,
        durable=durable,
    )


def replace_path_atomic(source: Path, destination: Path, *, durable: bool = False) -> None:
    """Promote a sibling path with one atomic replace and optional parent durability."""

    os.replace(source, destination)
    if durable:
        _fsync_parent_directory(destination.parent)


@contextmanager
def private_text_writer(path: Path, *, newline: str | None = None) -> Iterator[TextIO]:
    secure_directory(path.parent)
    descriptor = -1
    try:
        descriptor = (
            windows_open_private_output_descriptor(path, exclusive=False)
            if _running_on_windows()
            else os.open(path, _open_flags(), 0o600)
        )
        harden_private_descriptor(
            descriptor,
            expected_type=stat.S_IFREG,
            mode=0o600,
        )
        with os.fdopen(descriptor, "w", newline=newline, encoding="utf-8") as handle:
            descriptor = -1
            yield handle
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    secure_file(path)


def write_text_private(path: Path, value: str) -> None:
    # Recovery artifacts have byte-exact integrity contracts. Disable platform
    # newline translation so the same UTF-8/LF content is written on Windows.
    with private_text_writer(path, newline="") as handle:
        handle.write(value)


def write_json_private(path: Path, value: Any) -> None:
    write_text_private(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def write_json_private_atomic(
    path: Path,
    value: Any,
    *,
    before_replace: Callable[[], None] | None = None,
) -> None:
    """Write private JSON through a flushed sibling and atomically replace the target."""

    secure_directory(path.parent)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.partial")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    flags |= getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = (
            windows_create_private_staging_descriptor(temporary)
            if _running_on_windows()
            else os.open(temporary, flags, 0o600)
        )
        harden_private_descriptor(
            descriptor,
            expected_type=stat.S_IFREG,
            mode=0o600,
        )
        payload = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        secure_file(temporary)
        if before_replace is not None:
            before_replace()
        replace_path_atomic(temporary, path, durable=True)
        secure_file(path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()


def write_bytes_private(path: Path, value: bytes, *, exclusive: bool = False) -> None:
    secure_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = (
            windows_open_private_output_descriptor(path, exclusive=exclusive)
            if _running_on_windows()
            else os.open(path, flags, 0o600)
        )
        harden_private_descriptor(
            descriptor,
            expected_type=stat.S_IFREG,
            mode=0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(value)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    secure_file(path)


def write_csv_private(
    path: Path,
    rows: Iterable[Mapping[str, Any]],
    fields: Sequence[str],
    *,
    spreadsheet_safe: bool = True,
) -> list[dict[str, int | str]]:
    escaped_cells: list[dict[str, int | str]] = []
    with private_text_writer(path, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row_number, row in enumerate(rows, 1):
            protected = {
                key: spreadsheet_safe_cell(value) if spreadsheet_safe else value
                for key, value in row.items()
            }
            for field in fields:
                value = row.get(field)
                if spreadsheet_safe and spreadsheet_cell_needs_escape(value):
                    escaped_cells.append({"row": row_number, "field": field})
            writer.writerow(protected)
    return escaped_cells
