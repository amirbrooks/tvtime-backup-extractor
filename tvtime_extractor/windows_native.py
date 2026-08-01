from __future__ import annotations

import contextlib
import ctypes
import os
import platform
import re
import sys
from collections.abc import Iterator, Sequence
from ctypes import wintypes
from dataclasses import dataclass


class WindowsNativeError(OSError):
    """A sanitized failure from the small Windows filesystem capability layer."""

    def __init__(self, message: str, *, winerror: int = 0, ntstatus: int = 0) -> None:
        super().__init__(winerror, message)
        self.winerror = winerror
        self.ntstatus = ntstatus


class WindowsObjectExistsError(WindowsNativeError):
    pass


class WindowsUnsupportedError(WindowsNativeError):
    pass


class WindowsPrivateOwnerRebindRequired(WindowsNativeError):
    """The held directory needs the distinct owner-rebinding capability."""


@dataclass(frozen=True)
class WindowsVolumeCapabilities:
    filesystem_name: str
    filesystem_flags: int


@dataclass(frozen=True)
class WindowsHandleInformation:
    attributes: int
    identity: tuple[int, int]
    byte_size: int
    last_write_time: int

    @property
    def is_directory(self) -> bool:
        return bool(self.attributes & FILE_ATTRIBUTE_DIRECTORY)

    @property
    def is_reparse_point(self) -> bool:
        return bool(self.attributes & FILE_ATTRIBUTE_REPARSE_POINT)

    @property
    def is_cloud_hydrated(self) -> bool:
        return bool(self.attributes & FILE_ATTRIBUTE_CLOUD_HYDRATION)


@dataclass(frozen=True)
class WindowsDirectoryEntryInformation:
    name: str
    attributes: int
    identity: tuple[int, int]
    byte_size: int
    last_write_time: int
    short_name: str | None = None

    @property
    def is_directory(self) -> bool:
        return bool(self.attributes & FILE_ATTRIBUTE_DIRECTORY)

    @property
    def is_reparse_point(self) -> bool:
        return bool(self.attributes & FILE_ATTRIBUTE_REPARSE_POINT)

    @property
    def is_cloud_hydrated(self) -> bool:
        return bool(self.attributes & FILE_ATTRIBUTE_CLOUD_HYDRATION)


class _FILETIME(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("file_attributes", wintypes.DWORD),
        ("creation_time", _FILETIME),
        ("last_access_time", _FILETIME),
        ("last_write_time", _FILETIME),
        ("volume_serial_number", wintypes.DWORD),
        ("file_size_high", wintypes.DWORD),
        ("file_size_low", wintypes.DWORD),
        ("number_of_links", wintypes.DWORD),
        ("file_index_high", wintypes.DWORD),
        ("file_index_low", wintypes.DWORD),
    ]


class _FILE_ID_BOTH_DIR_INFO_HEADER(ctypes.Structure):
    _fields_ = [
        # Use fixed Win32 widths so the record layout remains contract-testable
        # from non-Windows hosts.  ``ctypes.wintypes.DWORD`` follows the host C
        # ``unsigned long`` width on Unix and is therefore eight bytes on macOS.
        ("next_entry_offset", ctypes.c_uint32),
        ("file_index", ctypes.c_uint32),
        ("creation_time", ctypes.c_int64),
        ("last_access_time", ctypes.c_int64),
        ("last_write_time", ctypes.c_int64),
        ("change_time", ctypes.c_int64),
        ("end_of_file", ctypes.c_int64),
        ("allocation_size", ctypes.c_int64),
        ("file_attributes", ctypes.c_uint32),
        ("file_name_length", ctypes.c_uint32),
        ("ea_size", ctypes.c_uint32),
        ("short_name_length", ctypes.c_uint8),
        ("short_name", ctypes.c_uint16 * 12),
        ("file_id", ctypes.c_int64),
    ]


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


class _OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(_UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID),
    ]


class _IO_STATUS_BLOCK_UNION(ctypes.Union):
    _fields_ = [("Status", wintypes.LONG), ("Pointer", wintypes.LPVOID)]  # noqa: RUF012


class _IO_STATUS_BLOCK(ctypes.Structure):
    _anonymous_ = ("result",)
    _fields_ = [("result", _IO_STATUS_BLOCK_UNION), ("Information", ctypes.c_size_t)]


class _TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class _ACL_SIZE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


class _ACE_HEADER(ctypes.Structure):
    _fields_ = [
        ("AceType", ctypes.c_ubyte),
        ("AceFlags", ctypes.c_ubyte),
        ("AceSize", wintypes.WORD),
    ]


class _ACCESS_ALLOWED_ACE(ctypes.Structure):
    _fields_ = [
        ("Header", _ACE_HEADER),
        ("Mask", wintypes.DWORD),
        ("SidStart", wintypes.DWORD),
    ]


class _FILE_RENAME_INFO(ctypes.Structure):
    _fields_ = [
        ("ReplaceIfExists", wintypes.BOOLEAN),
        ("RootDirectory", wintypes.HANDLE),
        ("FileNameLength", wintypes.DWORD),
        ("FileName", wintypes.WCHAR * 1),
    ]


class _FILE_DISPOSITION_INFO(ctypes.Structure):
    _fields_ = [("DeleteFile", wintypes.BOOL)]


INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_TEMPORARY = 0x00000100
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_OFFLINE = 0x00001000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
FILE_ATTRIBUTE_CLOUD_HYDRATION = (
    FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_NO_RECALL = 0x00100000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_WRITE_THROUGH = 0x80000000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

FILE_READ_DATA = 0x00000001
FILE_LIST_DIRECTORY = 0x00000001
FILE_WRITE_DATA = 0x00000002
FILE_ADD_FILE = 0x00000002
FILE_APPEND_DATA = 0x00000004
FILE_ADD_SUBDIRECTORY = 0x00000004
FILE_READ_EA = 0x00000008
FILE_WRITE_EA = 0x00000010
FILE_EXECUTE = 0x00000020
FILE_TRAVERSE = 0x00000020
FILE_READ_ATTRIBUTES = 0x00000080
FILE_WRITE_ATTRIBUTES = 0x00000100

DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
SYNCHRONIZE = 0x00100000
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000

FILE_OPEN = 0x00000001
FILE_CREATE = 0x00000002
FILE_OPEN_IF = 0x00000003
FILE_OVERWRITE_IF = 0x00000005

FILE_DIRECTORY_FILE = 0x00000001
FILE_WRITE_THROUGH = 0x00000002
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_OPEN_REPARSE_POINT = 0x00200000
FILE_OPEN_NO_RECALL = 0x00400000

FILE_ID_BOTH_DIRECTORY_INFO = 10
FILE_ID_BOTH_DIRECTORY_RESTART_INFO = 11
ERROR_NO_MORE_FILES = 18
FILE_BEGIN = 0
FILE_DISPOSITION_INFO_CLASS = 4
WINDOWS_DIRECTORY_ENUMERATION_BUFFER_BYTES = 64 * 1024
MAXIMUM_DIRECTORY_ENTRIES = 250_000

OBJ_CASE_INSENSITIVE = 0x00000040
STATUS_OBJECT_NAME_COLLISION = 0xC0000035
STATUS_OBJECT_NAME_EXISTS = 0x40000000
FILE_OPENED = 0x00000001
FILE_CREATED = 0x00000002

TOKEN_QUERY = 0x0008
TOKEN_USER_CLASS = 1
SDDL_REVISION_1 = 1
FILE_PERSISTENT_ACLS = 0x00000008
FILE_RENAME_INFO_CLASS = 3
SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x00000004
OWNER_SECURITY_INFORMATION = 0x00000001
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
ACL_SIZE_INFORMATION_CLASS = 2
SE_DACL_PROTECTED = 0x1000
ACCESS_ALLOWED_ACE_TYPE = 0x00
INHERITED_ACE = 0x10
FILE_ALL_ACCESS = 0x001F01FF
SYSTEM_SID = "S-1-5-18"

_SAFE_COMPONENT = re.compile(r"^[^\\/:*?\"<>|\x00]+$")


def _require_windows() -> None:
    if os.name != "nt":
        raise WindowsUnsupportedError("Windows native filesystem support is unavailable.")


def require_filesystem_runtime() -> None:
    _require_windows()
    if ctypes.sizeof(ctypes.c_void_p) != 8 or platform.machine().casefold() not in {
        "amd64",
        "x86_64",
    }:
        raise WindowsUnsupportedError("Windows recovery requires 64-bit x64 Python.")
    version = sys.getwindowsversion()
    if version.major < 10 or version.build < 17763:
        raise WindowsUnsupportedError("Windows recovery requires Windows 10 version 1809 or later.")


def require_supported_runtime() -> None:
    """Require the narrower Windows 11 runtime used by encrypted iOS recovery."""

    require_filesystem_runtime()
    version = sys.getwindowsversion()
    if version.major < 10 or version.build < 22000:
        raise WindowsUnsupportedError("Encrypted iOS recovery requires Windows 11 or later.")


def validate_component(name: str) -> str:
    if not isinstance(name, str) or name in {"", ".", ".."} or not _SAFE_COMPONENT.fullmatch(name):
        raise WindowsNativeError("A Windows capability path component was invalid.")
    return name


def validate_relative_parts(parts: Sequence[str]) -> tuple[str, ...]:
    if not parts:
        raise WindowsNativeError("A Windows capability path was empty.")
    return tuple(validate_component(part) for part in parts)


def _dll(name: str) -> ctypes.WinDLL:
    _require_windows()
    try:
        return ctypes.WinDLL(name, use_last_error=True)
    except OSError as exc:
        raise WindowsUnsupportedError("A required Windows system library was unavailable.") from exc


def _handle_value(value: object) -> int:
    if isinstance(value, int):
        return value
    candidate = getattr(value, "value", None)
    return int(candidate) if isinstance(candidate, int) else -1


def _last_error(message: str) -> WindowsNativeError:
    return WindowsNativeError(message, winerror=int(ctypes.get_last_error() or 0))


def close_handle(handle: int) -> None:
    if not isinstance(handle, int) or isinstance(handle, bool) or handle <= 0:
        return
    kernel32 = _dll("kernel32")
    close = kernel32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    if not close(wintypes.HANDLE(handle)):
        raise _last_error("A Windows capability handle could not be closed safely.")


def handle_information(handle: int) -> WindowsHandleInformation:
    if not isinstance(handle, int) or isinstance(handle, bool) or handle <= 0:
        raise WindowsNativeError("A Windows capability handle was invalid.")
    kernel32 = _dll("kernel32")
    function = kernel32.GetFileInformationByHandle
    function.argtypes = [wintypes.HANDLE, ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION)]
    function.restype = wintypes.BOOL
    information = _BY_HANDLE_FILE_INFORMATION()
    if not function(wintypes.HANDLE(handle), ctypes.byref(information)):
        raise _last_error("A Windows capability handle could not be validated.")
    return WindowsHandleInformation(
        attributes=int(information.file_attributes),
        identity=(
            int(information.volume_serial_number),
            (int(information.file_index_high) << 32) | int(information.file_index_low),
        ),
        byte_size=(int(information.file_size_high) << 32) | int(information.file_size_low),
        last_write_time=(
            (int(information.last_write_time.high) << 32) | int(information.last_write_time.low)
        ),
    )


def _directory_entries_from_buffer(
    payload: bytes,
    *,
    volume_serial_number: int,
) -> tuple[WindowsDirectoryEntryInformation, ...]:
    """Decode one bounded FILE_ID_BOTH_DIR_INFO buffer without trusting offsets."""

    header_bytes = ctypes.sizeof(_FILE_ID_BOTH_DIR_INFO_HEADER)
    offset = 0
    entries: list[WindowsDirectoryEntryInformation] = []
    while True:
        if offset < 0 or offset + header_bytes > len(payload):
            raise WindowsNativeError("Windows directory metadata had an unsafe shape.")
        header = _FILE_ID_BOTH_DIR_INFO_HEADER.from_buffer_copy(payload, offset)
        name_bytes = int(header.file_name_length)
        name_start = offset + header_bytes
        name_end = name_start + name_bytes
        if name_bytes <= 0 or name_bytes % 2 or name_end > len(payload):
            raise WindowsNativeError("Windows directory metadata had an unsafe name.")
        try:
            name = payload[name_start:name_end].decode("utf-16-le", errors="strict")
        except UnicodeDecodeError as exc:
            raise WindowsNativeError("Windows directory metadata had an unsafe name.") from exc
        if "\x00" in name:
            raise WindowsNativeError("Windows directory metadata had an unsafe name.")
        short_name_bytes = int(header.short_name_length)
        short_name_size = ctypes.sizeof(header.short_name)
        if short_name_bytes < 0 or short_name_bytes > short_name_size or short_name_bytes % 2:
            raise WindowsNativeError("Windows directory metadata had an unsafe short name.")
        short_name: str | None = None
        if short_name_bytes:
            short_name_start = offset + _FILE_ID_BOTH_DIR_INFO_HEADER.short_name.offset
            try:
                short_name = payload[short_name_start : short_name_start + short_name_bytes].decode(
                    "utf-16-le", errors="strict"
                )
            except UnicodeDecodeError as exc:
                raise WindowsNativeError(
                    "Windows directory metadata had an unsafe short name."
                ) from exc
            if "\x00" in short_name:
                raise WindowsNativeError("Windows directory metadata had an unsafe short name.")
        byte_size = int(header.end_of_file)
        last_write_time = int(header.last_write_time)
        if byte_size < 0 or last_write_time < 0:
            raise WindowsNativeError("Windows directory metadata had unsafe file values.")
        entries.append(
            WindowsDirectoryEntryInformation(
                name=name,
                attributes=int(header.file_attributes),
                identity=(
                    int(volume_serial_number),
                    int(header.file_id) & ((1 << 64) - 1),
                ),
                byte_size=byte_size,
                last_write_time=last_write_time,
                short_name=short_name,
            )
        )
        next_offset = int(header.next_entry_offset)
        if next_offset == 0:
            return tuple(entries)
        if (
            next_offset % 8
            or next_offset < header_bytes + name_bytes
            or offset + next_offset <= offset
            or offset + next_offset > len(payload)
        ):
            raise WindowsNativeError("Windows directory metadata had an unsafe shape.")
        offset += next_offset


def iter_directory_entries(handle: int) -> Iterator[WindowsDirectoryEntryInformation]:
    """Stream one bounded held-directory enumeration without target-opening queries."""

    directory = handle_information(handle)
    if not directory.is_directory or directory.is_reparse_point or directory.is_cloud_hydrated:
        raise WindowsNativeError("A Windows capability path was not a safe directory.")
    kernel32 = _dll("kernel32")
    function = kernel32.GetFileInformationByHandleEx
    function.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    function.restype = wintypes.BOOL
    entry_count = 0
    information_class = FILE_ID_BOTH_DIRECTORY_RESTART_INFO
    while True:
        buffer = ctypes.create_string_buffer(WINDOWS_DIRECTORY_ENUMERATION_BUFFER_BYTES)
        ctypes.set_last_error(0)
        if not function(
            wintypes.HANDLE(handle),
            information_class,
            buffer,
            len(buffer),
        ):
            error = int(ctypes.get_last_error() or 0)
            if error == ERROR_NO_MORE_FILES:
                break
            raise WindowsNativeError(
                "A Windows directory could not be enumerated safely.",
                winerror=error,
            )
        decoded = _directory_entries_from_buffer(
            bytes(buffer),
            volume_serial_number=directory.identity[0],
        )
        if not decoded:
            raise WindowsNativeError("Windows directory enumeration made no safe progress.")
        for entry in decoded:
            if entry.name in {".", ".."}:
                continue
            validate_component(entry.name)
            if entry.short_name is not None:
                validate_component(entry.short_name)
            entry_count += 1
            if entry_count > MAXIMUM_DIRECTORY_ENTRIES:
                raise WindowsNativeError("A Windows directory exceeded the safe entry limit.")
            yield entry
        information_class = FILE_ID_BOTH_DIRECTORY_INFO


def directory_entries(handle: int) -> tuple[WindowsDirectoryEntryInformation, ...]:
    """Materialize one bounded enumeration for narrow identity lookups and tests."""

    return tuple(iter_directory_entries(handle))


def volume_capabilities(handle: int) -> WindowsVolumeCapabilities:
    kernel32 = _dll("kernel32")
    function = kernel32.GetVolumeInformationByHandleW
    function.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    function.restype = wintypes.BOOL
    flags = wintypes.DWORD()
    filesystem = ctypes.create_unicode_buffer(64)
    if not function(
        wintypes.HANDLE(handle),
        None,
        0,
        None,
        None,
        ctypes.byref(flags),
        filesystem,
        len(filesystem),
    ):
        raise _last_error("The Windows destination filesystem could not be inspected safely.")
    return WindowsVolumeCapabilities(
        filesystem_name=filesystem.value,
        filesystem_flags=int(flags.value),
    )


def require_private_ntfs_volume(handle: int) -> None:
    capabilities = volume_capabilities(handle)
    if capabilities.filesystem_name.casefold() != "ntfs":
        raise WindowsUnsupportedError("Windows recovery requires a local NTFS destination.")
    if not capabilities.filesystem_flags & FILE_PERSISTENT_ACLS:
        raise WindowsUnsupportedError(
            "The Windows destination does not preserve and enforce access-control lists."
        )


def require_source_ntfs_volume(handle: int) -> None:
    """Restrict source identity binding to NTFS's collision-safe 64-bit file IDs."""

    capabilities = volume_capabilities(handle)
    if capabilities.filesystem_name.casefold() != "ntfs":
        raise WindowsUnsupportedError(
            "Windows recovery sources must be on private local NTFS storage."
        )
    if not capabilities.filesystem_flags & FILE_PERSISTENT_ACLS:
        raise WindowsUnsupportedError(
            "The Windows recovery source does not preserve access-control lists."
        )


def require_recovery_capabilities(handle: int) -> None:
    """Probe the non-mutating Windows contract before any password is requested."""

    require_filesystem_runtime()
    information = handle_information(handle)
    if not information.is_directory or information.is_reparse_point:
        raise WindowsUnsupportedError("The Windows destination parent was not a safe directory.")
    require_private_ntfs_volume(handle)
    with private_security_descriptor() as descriptor:
        if not descriptor:
            raise WindowsUnsupportedError("Private Windows access controls could not be prepared.")
    required_symbols = {
        "ntdll": ("NtCreateFile", "RtlNtStatusToDosError"),
        "kernel32": (
            "FlushFileBuffers",
            "GetFinalPathNameByHandleW",
            "SetFileInformationByHandle",
        ),
    }
    try:
        for library, symbols in required_symbols.items():
            loaded = _dll(library)
            for symbol in symbols:
                getattr(loaded, symbol)
    except AttributeError as exc:
        raise WindowsUnsupportedError(
            "A required Windows filesystem capability was unavailable."
        ) from exc


def _current_user_sid_string() -> str:
    advapi32 = _dll("advapi32")
    kernel32 = _dll("kernel32")
    get_process = kernel32.GetCurrentProcess
    get_process.argtypes = []
    get_process.restype = wintypes.HANDLE
    process = get_process()
    token = wintypes.HANDLE()
    open_token = advapi32.OpenProcessToken
    open_token.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    open_token.restype = wintypes.BOOL
    if not open_token(process, TOKEN_QUERY, ctypes.byref(token)):
        raise _last_error("The current Windows account could not be identified safely.")
    try:
        get_information = advapi32.GetTokenInformation
        get_information.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        get_information.restype = wintypes.BOOL
        required = wintypes.DWORD()
        get_information(token, TOKEN_USER_CLASS, None, 0, ctypes.byref(required))
        if required.value <= 0:
            raise _last_error("The current Windows account could not be identified safely.")
        buffer = ctypes.create_string_buffer(required.value)
        if not get_information(
            token,
            TOKEN_USER_CLASS,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise _last_error("The current Windows account could not be identified safely.")
        token_user = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_USER)).contents
        sid_text = wintypes.LPWSTR()
        convert = advapi32.ConvertSidToStringSidW
        convert.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
        convert.restype = wintypes.BOOL
        if not convert(token_user.User, ctypes.byref(sid_text)):
            raise _last_error("The current Windows account SID could not be encoded safely.")
        try:
            return str(sid_text.value)
        finally:
            local_free = kernel32.LocalFree
            local_free.argtypes = [wintypes.HLOCAL]
            local_free.restype = wintypes.HLOCAL
            local_free(sid_text)
    finally:
        close_handle(_handle_value(token))


@contextlib.contextmanager
def private_security_descriptor() -> Iterator[wintypes.LPVOID]:
    """Create a protected current-user-and-SYSTEM descriptor for one atomic create."""

    sid = _current_user_sid_string()
    sddl = f"O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})"
    advapi32 = _dll("advapi32")
    kernel32 = _dll("kernel32")
    descriptor = wintypes.LPVOID()
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    if not convert(sddl, SDDL_REVISION_1, ctypes.byref(descriptor), None):
        raise _last_error("Private Windows access controls could not be prepared.")
    try:
        yield descriptor
    finally:
        if descriptor:
            local_free = kernel32.LocalFree
            local_free.argtypes = [wintypes.HLOCAL]
            local_free.restype = wintypes.HLOCAL
            local_free(descriptor)


def _handle_has_owner(handle: int, expected_owner: wintypes.LPVOID) -> bool:
    """Compare a pinned object's owner without resolving its visible path again."""

    advapi32 = _dll("advapi32")
    kernel32 = _dll("kernel32")
    owner = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    get_security = advapi32.GetSecurityInfo
    get_security.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    get_security.restype = wintypes.DWORD
    result = int(
        get_security(
            wintypes.HANDLE(handle),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
    )
    if result:
        raise WindowsNativeError(
            "Private Windows access controls could not be inspected.",
            winerror=result,
        )
    try:
        if not descriptor or not owner:
            raise WindowsNativeError("A private Windows access-control owner was missing.")
        equal_sid = advapi32.EqualSid
        equal_sid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
        equal_sid.restype = wintypes.BOOL
        return bool(equal_sid(owner, expected_owner))
    finally:
        if descriptor:
            local_free = kernel32.LocalFree
            local_free.argtypes = [wintypes.HLOCAL]
            local_free.restype = wintypes.HLOCAL
            local_free(descriptor)


def apply_private_acl(handle: int, *, owner_rebind: bool = False) -> None:
    """Bind a pinned directory to the private descriptor's owner and protected DACL.

    DACL-only repair preserves an already-correct owner. The caller must reopen
    with the separate owner-write capability only after this handle proves it is
    needed, so owner-controlled directories remain repairable.
    """

    if not isinstance(handle, int) or isinstance(handle, bool) or handle <= 0:
        raise WindowsNativeError("A Windows capability handle was invalid.")
    if not isinstance(owner_rebind, bool):
        raise TypeError("owner_rebind must be a boolean.")
    advapi32 = _dll("advapi32")
    get_dacl = advapi32.GetSecurityDescriptorDacl
    get_dacl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    get_dacl.restype = wintypes.BOOL
    get_owner = advapi32.GetSecurityDescriptorOwner
    get_owner.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    get_owner.restype = wintypes.BOOL
    set_security = advapi32.SetSecurityInfo
    set_security.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    set_security.restype = wintypes.DWORD
    with private_security_descriptor() as descriptor:
        owner = wintypes.LPVOID()
        owner_defaulted = wintypes.BOOL()
        if not get_owner(descriptor, ctypes.byref(owner), ctypes.byref(owner_defaulted)):
            raise _last_error("Private Windows access controls could not be prepared.")
        if not owner:
            raise WindowsNativeError("A private Windows access-control owner was missing.")
        if not owner_rebind and not _handle_has_owner(handle, owner):
            raise WindowsPrivateOwnerRebindRequired(
                "Private Windows access controls needed owner rebinding."
            )
        dacl_present = wintypes.BOOL()
        dacl = wintypes.LPVOID()
        dacl_defaulted = wintypes.BOOL()
        if not get_dacl(
            descriptor,
            ctypes.byref(dacl_present),
            ctypes.byref(dacl),
            ctypes.byref(dacl_defaulted),
        ):
            raise _last_error("Private Windows access controls could not be prepared.")
        if not dacl_present.value or not dacl:
            raise WindowsNativeError("A private Windows access-control list was missing.")
        security_information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        if owner_rebind:
            security_information |= OWNER_SECURITY_INFORMATION
        result = int(
            set_security(
                wintypes.HANDLE(handle),
                SE_FILE_OBJECT,
                security_information,
                owner if owner_rebind else None,
                None,
                dacl,
                None,
            )
        )
        if result:
            raise WindowsNativeError(
                "Private Windows access controls could not be applied.",
                winerror=result,
            )
    validate_private_acl(handle)


def _sid_string(sid: wintypes.LPVOID) -> str:
    if not sid:
        raise WindowsNativeError("A private Windows access-control identity was missing.")
    advapi32 = _dll("advapi32")
    kernel32 = _dll("kernel32")
    converted = wintypes.LPWSTR()
    function = advapi32.ConvertSidToStringSidW
    function.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    function.restype = wintypes.BOOL
    if not function(sid, ctypes.byref(converted)):
        raise _last_error("A private Windows access-control identity could not be inspected.")
    try:
        return str(converted.value)
    finally:
        local_free = kernel32.LocalFree
        local_free.argtypes = [wintypes.HLOCAL]
        local_free.restype = wintypes.HLOCAL
        local_free(converted)


def validate_private_acl(handle: int) -> None:
    """Require one protected DACL containing only full-control user and SYSTEM ACEs."""

    if not isinstance(handle, int) or isinstance(handle, bool) or handle <= 0:
        raise WindowsNativeError("A Windows capability handle was invalid.")
    advapi32 = _dll("advapi32")
    kernel32 = _dll("kernel32")
    owner = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    get_security = advapi32.GetSecurityInfo
    get_security.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    get_security.restype = wintypes.DWORD
    result = int(
        get_security(
            wintypes.HANDLE(handle),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
    )
    if result:
        raise WindowsNativeError(
            "Private Windows access controls could not be inspected.",
            winerror=result,
        )
    try:
        if not descriptor or not dacl:
            raise WindowsNativeError("A private Windows access-control list was missing.")
        get_control = advapi32.GetSecurityDescriptorControl
        get_control.argtypes = [
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        get_control.restype = wintypes.BOOL
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not get_control(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise _last_error("Private Windows access controls could not be validated.")
        if not int(control.value) & SE_DACL_PROTECTED:
            raise WindowsNativeError("Private Windows access controls allowed inheritance.")

        get_acl_information = advapi32.GetAclInformation
        get_acl_information.argtypes = [
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.c_int,
        ]
        get_acl_information.restype = wintypes.BOOL
        acl_information = _ACL_SIZE_INFORMATION()
        if not get_acl_information(
            dacl,
            ctypes.byref(acl_information),
            ctypes.sizeof(acl_information),
            ACL_SIZE_INFORMATION_CLASS,
        ):
            raise _last_error("Private Windows access controls could not be validated.")
        if int(acl_information.AceCount) != 2:
            raise WindowsNativeError("Private Windows access controls granted unexpected access.")

        current_sid = _current_user_sid_string().casefold()
        expected_sids = {current_sid, SYSTEM_SID.casefold()}
        actual_sids: set[str] = set()
        get_ace = advapi32.GetAce
        get_ace.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
        ]
        get_ace.restype = wintypes.BOOL
        for index in range(int(acl_information.AceCount)):
            ace_pointer = wintypes.LPVOID()
            if not get_ace(dacl, index, ctypes.byref(ace_pointer)):
                raise _last_error("Private Windows access controls could not be validated.")
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(_ACCESS_ALLOWED_ACE)).contents
            if (
                int(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE
                or int(ace.Header.AceFlags) & INHERITED_ACE
                or int(ace.Mask) != FILE_ALL_ACCESS
            ):
                raise WindowsNativeError(
                    "Private Windows access controls granted unexpected access."
                )
            sid_address = ctypes.addressof(ace) + _ACCESS_ALLOWED_ACE.SidStart.offset
            actual_sids.add(_sid_string(wintypes.LPVOID(sid_address)).casefold())
        if actual_sids != expected_sids or _sid_string(owner).casefold() != current_sid:
            raise WindowsNativeError("Private Windows access controls had an unexpected owner.")
    finally:
        if descriptor:
            local_free = kernel32.LocalFree
            local_free.argtypes = [wintypes.HLOCAL]
            local_free.restype = wintypes.HLOCAL
            local_free(descriptor)


def _ntstatus_error(status: int, message: str) -> WindowsNativeError:
    normalized = int(status) & 0xFFFFFFFF
    if normalized in {STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_EXISTS}:
        return WindowsObjectExistsError(message, ntstatus=normalized)
    ntdll = _dll("ntdll")
    convert = ntdll.RtlNtStatusToDosError
    convert.argtypes = [wintypes.LONG]
    convert.restype = wintypes.ULONG
    winerror = int(convert(wintypes.LONG(status)))
    return WindowsNativeError(message, winerror=winerror, ntstatus=normalized)


def _nt_create_relative(
    parent_handle: int,
    name: str,
    *,
    desired_access: int,
    share_access: int,
    disposition: int,
    options: int,
    file_attributes: int,
    security_descriptor: wintypes.LPVOID | None,
) -> tuple[int, int]:
    validate_component(name)
    if not isinstance(parent_handle, int) or isinstance(parent_handle, bool) or parent_handle <= 0:
        raise WindowsNativeError("A trusted Windows parent handle was unavailable.")
    name_buffer = ctypes.create_unicode_buffer(name)
    byte_length = len(name.encode("utf-16-le"))
    unicode_name = _UNICODE_STRING(
        Length=byte_length,
        MaximumLength=byte_length + 2,
        Buffer=ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    attributes = _OBJECT_ATTRIBUTES(
        Length=ctypes.sizeof(_OBJECT_ATTRIBUTES),
        RootDirectory=wintypes.HANDLE(parent_handle),
        ObjectName=ctypes.pointer(unicode_name),
        Attributes=OBJ_CASE_INSENSITIVE,
        SecurityDescriptor=security_descriptor,
        SecurityQualityOfService=None,
    )
    io_status = _IO_STATUS_BLOCK()
    opened = wintypes.HANDLE()
    ntdll = _dll("ntdll")
    create = ntdll.NtCreateFile
    create.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_OBJECT_ATTRIBUTES),
        ctypes.POINTER(_IO_STATUS_BLOCK),
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    ]
    create.restype = wintypes.LONG
    status = int(
        create(
            ctypes.byref(opened),
            desired_access,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            file_attributes,
            share_access,
            disposition,
            options,
            None,
            0,
        )
    )
    if status < 0:
        raise _ntstatus_error(status, "A Windows capability object could not be created safely.")
    handle = _handle_value(opened)
    if handle in {-1, 0, INVALID_HANDLE_VALUE}:
        raise WindowsNativeError("A Windows capability operation returned an invalid handle.")
    return handle, int(io_status.Information)


def create_fresh_directory(parent_handle: int, name: str) -> int:
    with private_security_descriptor() as descriptor:
        handle, _ = _nt_create_relative(
            parent_handle,
            name,
            desired_access=(
                FILE_LIST_DIRECTORY
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | DELETE
                | READ_CONTROL
                | WRITE_DAC
                | SYNCHRONIZE
            ),
            share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
            disposition=FILE_CREATE,
            options=(FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT),
            file_attributes=FILE_ATTRIBUTE_NORMAL,
            security_descriptor=descriptor,
        )
    try:
        information = handle_information(handle)
        if not information.is_directory or information.is_reparse_point:
            raise WindowsNativeError("The fresh Windows destination was not a regular directory.")
        validate_private_acl(handle)
    except BaseException:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise
    return handle


def _open_relative_directory(
    parent_handle: int,
    name: str,
    *,
    writable: bool,
    acl_repair: bool,
    owner_rebind: bool,
    share_delete: bool,
) -> int:
    if writable and acl_repair:
        raise ValueError(
            "A Windows directory capability cannot combine data writes with ACL repair."
        )
    if owner_rebind and not acl_repair:
        raise ValueError("A Windows owner rebind requires the ACL repair capability.")
    if acl_repair:
        # Security metadata and stable handle information need no list or
        # traversal access to the directory contents.
        desired = FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | SYNCHRONIZE
        if owner_rebind:
            desired |= WRITE_OWNER
    else:
        desired = (
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
        )
    if writable:
        desired |= FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_ATTRIBUTES | WRITE_DAC
    share_access = FILE_SHARE_READ | FILE_SHARE_WRITE
    if share_delete:
        share_access |= FILE_SHARE_DELETE
    handle, _ = _nt_create_relative(
        parent_handle,
        name,
        desired_access=desired,
        share_access=share_access,
        disposition=FILE_OPEN,
        options=(FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT),
        file_attributes=FILE_ATTRIBUTE_NORMAL,
        security_descriptor=None,
    )
    try:
        information = handle_information(handle)
        if (
            not information.is_directory
            or information.is_reparse_point
            or information.is_cloud_hydrated
        ):
            raise WindowsNativeError("A Windows capability path traversed an unsafe directory.")
    except BaseException:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise
    return handle


def open_relative_directory(parent_handle: int, name: str, *, writable: bool) -> int:
    """Open a transient traversal handle that can coexist with retained capabilities."""

    return _open_relative_directory(
        parent_handle,
        name,
        writable=writable,
        acl_repair=False,
        owner_rebind=False,
        share_delete=True,
    )


def open_relative_retained_directory(
    parent_handle: int,
    name: str,
    *,
    writable: bool,
) -> int:
    """Open and pin a final directory against rename or replacement."""

    return _open_relative_directory(
        parent_handle,
        name,
        writable=writable,
        acl_repair=False,
        owner_rebind=False,
        share_delete=False,
    )


def open_relative_acl_repair_directory(
    parent_handle: int,
    name: str,
    *,
    owner_rebind: bool = False,
    coexist_with_retained_delete: bool = False,
) -> int:
    """Open one directory for ACL repair without child or data-write access.

    Delete sharing is safe only when another retained capability already pins
    the exact directory against rename and replacement.
    """

    return _open_relative_directory(
        parent_handle,
        name,
        writable=False,
        acl_repair=True,
        owner_rebind=owner_rebind,
        share_delete=coexist_with_retained_delete,
    )


def _open_relative_regular_file(
    parent_handle: int,
    name: str,
    *,
    acl_repair: bool,
    owner_rebind: bool,
) -> int:
    if owner_rebind and not acl_repair:
        raise ValueError("A Windows owner rebind requires the ACL repair capability.")
    if acl_repair:
        # Repair can change only security-descriptor metadata. No file-content
        # read/write, attribute-write, or delete access is requested.
        desired_access = FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | SYNCHRONIZE
        share_access = FILE_SHARE_READ | FILE_SHARE_WRITE
        if owner_rebind:
            desired_access |= WRITE_OWNER
    else:
        desired_access = GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE
        share_access = FILE_SHARE_READ
    handle, _ = _nt_create_relative(
        parent_handle,
        name,
        desired_access=desired_access,
        share_access=share_access,
        disposition=FILE_OPEN,
        options=(
            FILE_NON_DIRECTORY_FILE
            | FILE_SYNCHRONOUS_IO_NONALERT
            | FILE_OPEN_REPARSE_POINT
            | FILE_OPEN_NO_RECALL
        ),
        file_attributes=FILE_ATTRIBUTE_NORMAL,
        security_descriptor=None,
    )
    try:
        information = handle_information(handle)
        if (
            information.is_directory
            or information.is_reparse_point
            or information.is_cloud_hydrated
        ):
            raise WindowsNativeError("A Windows capability file was not a regular file.")
    except BaseException:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise
    return handle


def open_relative_regular_file(parent_handle: int, name: str) -> int:
    """Open one private regular file for read-only, no-recall access."""

    return _open_relative_regular_file(
        parent_handle,
        name,
        acl_repair=False,
        owner_rebind=False,
    )


def open_relative_retained_regular_file(
    parent_handle: int,
    name: str,
    *,
    owner_rebind: bool = False,
) -> int:
    """Pin one regular file while granting only ACL-repair metadata writes."""

    return _open_relative_regular_file(
        parent_handle,
        name,
        acl_repair=True,
        owner_rebind=owner_rebind,
    )


def _open_relative_for_delete(
    parent_handle: int,
    name: str,
    *,
    directory: bool,
) -> int:
    desired_access = DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
    options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT
    if directory:
        desired_access |= FILE_LIST_DIRECTORY | FILE_TRAVERSE
        options |= FILE_DIRECTORY_FILE
    else:
        options |= FILE_NON_DIRECTORY_FILE | FILE_OPEN_NO_RECALL
    handle, _ = _nt_create_relative(
        parent_handle,
        name,
        desired_access=desired_access,
        # Deny delete sharing so this exact child cannot be renamed out of the
        # held tree while its descendants are being removed.
        share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
        disposition=FILE_OPEN,
        options=options,
        file_attributes=FILE_ATTRIBUTE_NORMAL,
        security_descriptor=None,
    )
    try:
        information = handle_information(handle)
        if information.is_directory != directory:
            raise WindowsNativeError("A private Windows cleanup entry changed type.")
    except BaseException:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise
    return handle


def _mark_handle_for_deletion(handle: int) -> None:
    information = _FILE_DISPOSITION_INFO(DeleteFile=True)
    kernel32 = _dll("kernel32")
    function = kernel32.SetFileInformationByHandle
    function.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    function.restype = wintypes.BOOL
    if not function(
        wintypes.HANDLE(handle),
        FILE_DISPOSITION_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise _last_error("A private Windows temporary entry could not be removed safely.")


def delete_private_tree(root_handle: int) -> None:
    """Delete one exact held tree without performing a destructive path reopen."""

    root = handle_information(root_handle)
    if not root.is_directory or root.is_reparse_point or root.is_cloud_hydrated:
        raise WindowsNativeError("A private Windows temporary root was unsafe.")
    stack: list[tuple[int, tuple[WindowsDirectoryEntryInformation, ...], int, bool]] = [
        (root_handle, directory_entries(root_handle), 0, False)
    ]
    observed_entries = 0
    try:
        while stack:
            directory_handle, entries, index, owned = stack[-1]
            if index >= len(entries):
                _mark_handle_for_deletion(directory_handle)
                stack.pop()
                if owned:
                    close_handle(directory_handle)
                continue
            entry = entries[index]
            stack[-1] = (directory_handle, entries, index + 1, owned)
            observed_entries += 1
            if observed_entries > MAXIMUM_DIRECTORY_ENTRIES:
                raise WindowsNativeError("A private Windows temporary tree was too large.")
            if entry.is_cloud_hydrated:
                raise WindowsNativeError("A private Windows temporary entry was not local.")
            child_handle = _open_relative_for_delete(
                directory_handle,
                entry.name,
                directory=entry.is_directory,
            )
            try:
                child = handle_information(child_handle)
                if (
                    child.identity != entry.identity
                    or child.is_reparse_point != entry.is_reparse_point
                    or child.is_cloud_hydrated
                ):
                    raise WindowsNativeError(
                        "A private Windows temporary entry changed before cleanup."
                    )
                if entry.is_directory and not entry.is_reparse_point:
                    child_entries = directory_entries(child_handle)
                    stack.append((child_handle, child_entries, 0, True))
                    child_handle = -1
                else:
                    _mark_handle_for_deletion(child_handle)
            finally:
                if child_handle > 0:
                    close_handle(child_handle)
    except BaseException:
        for handle, _entries, _index, owned in reversed(stack):
            if owned:
                with contextlib.suppress(Exception):
                    close_handle(handle)
        raise


def _truncate_regular_file(handle: int) -> None:
    """Truncate one already-validated held file without reopening its path."""

    kernel32 = _dll("kernel32")
    seek = kernel32.SetFilePointerEx
    seek.argtypes = [
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    ]
    seek.restype = wintypes.BOOL
    if not seek(wintypes.HANDLE(handle), 0, None, FILE_BEGIN):
        raise _last_error("A private Windows file could not be prepared safely.")
    truncate = kernel32.SetEndOfFile
    truncate.argtypes = [wintypes.HANDLE]
    truncate.restype = wintypes.BOOL
    if not truncate(wintypes.HANDLE(handle)):
        raise _last_error("A private Windows file could not be prepared safely.")


def create_or_replace_regular_file(
    parent_handle: int,
    name: str,
    *,
    exclusive: bool,
    temporary: bool = False,
    allow_path_reopen: bool = False,
) -> int:
    """Create a private file, or validate and then truncate an existing file."""

    attributes = FILE_ATTRIBUTE_NORMAL | (FILE_ATTRIBUTE_TEMPORARY if temporary else 0)
    desired_access = (
        GENERIC_READ
        | GENERIC_WRITE
        | FILE_READ_ATTRIBUTES
        | FILE_WRITE_ATTRIBUTES
        | READ_CONTROL
        | WRITE_DAC
        | SYNCHRONIZE
    )
    if not allow_path_reopen:
        desired_access |= DELETE
    with private_security_descriptor() as descriptor:
        handle, _ = _nt_create_relative(
            parent_handle,
            name,
            desired_access=desired_access,
            share_access=(FILE_SHARE_READ | FILE_SHARE_WRITE) if allow_path_reopen else 0,
            # FILE_OVERWRITE_IF mutates an existing file before its ACL can be
            # validated.  FILE_OPEN_IF holds it unchanged until validation,
            # after which truncation occurs through this exact handle.
            disposition=FILE_CREATE if exclusive else FILE_OPEN_IF,
            options=(
                FILE_NON_DIRECTORY_FILE
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT
                | FILE_OPEN_NO_RECALL
                | FILE_WRITE_THROUGH
            ),
            file_attributes=attributes,
            security_descriptor=descriptor,
        )
    try:
        information = handle_information(handle)
        if (
            information.is_directory
            or information.is_reparse_point
            or information.is_cloud_hydrated
        ):
            raise WindowsNativeError("A private Windows file was unsafe.")
        validate_private_acl(handle)
        if not exclusive:
            _truncate_regular_file(handle)
    except BaseException:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise
    return handle


def create_relative_regular_file_path(
    root_handle: int,
    parts: Sequence[str],
    *,
    temporary: bool = False,
    exclusive: bool = True,
    allow_path_reopen: bool = False,
) -> int:
    components = validate_relative_parts(parts)
    parent = root_handle
    owned: list[int] = []
    result = -1
    try:
        for component in components[:-1]:
            child = open_relative_directory(parent, component, writable=True)
            try:
                validate_private_acl(child)
            except BaseException:
                with contextlib.suppress(Exception):
                    close_handle(child)
                raise
            owned.append(child)
            parent = child
        result = create_or_replace_regular_file(
            parent,
            components[-1],
            exclusive=exclusive,
            temporary=temporary,
            allow_path_reopen=allow_path_reopen,
        )
        while owned:
            close_handle(owned.pop())
        return result
    except BaseException:
        for handle in reversed(owned):
            with contextlib.suppress(Exception):
                close_handle(handle)
        if result > 0:
            with contextlib.suppress(Exception):
                close_handle(result)
        raise


def handle_to_file_descriptor(handle: int, *, flags: int) -> int:
    _require_windows()
    try:
        import msvcrt

        descriptor = msvcrt.open_osfhandle(handle, flags | getattr(os, "O_NOINHERIT", 0))
    except (ImportError, OSError, TypeError, ValueError) as exc:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise WindowsNativeError("A Windows handle could not be bound to Python safely.") from exc
    if descriptor < 0:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise WindowsNativeError("A Windows handle could not be bound to Python safely.")
    return descriptor


def final_path_from_handle(handle: int) -> str:
    """Return the normalized local DOS path owned by one held filesystem handle."""

    kernel32 = _dll("kernel32")
    function = kernel32.GetFinalPathNameByHandleW
    function.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    function.restype = wintypes.DWORD
    required = int(function(wintypes.HANDLE(handle), None, 0, 0))
    if required <= 0 or required > 32768:
        raise _last_error("A held Windows directory path could not be resolved safely.")
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = int(function(wintypes.HANDLE(handle), buffer, len(buffer), 0))
    if written <= 0 or written >= len(buffer):
        raise _last_error("A held Windows directory path could not be resolved safely.")
    result = buffer.value
    if not result.startswith("\\\\?\\") or result.casefold().startswith("\\\\?\\unc\\"):
        raise WindowsUnsupportedError("A Windows capability path was not on local storage.")
    return result


def rename_handle_relative(
    handle: int,
    root_handle: int,
    destination_parts: Sequence[str],
    *,
    replace: bool,
) -> None:
    """Rename an already-held file beneath a trusted root without reopening its source name."""

    components = validate_relative_parts(destination_parts)
    parent_handle = root_handle
    parent_owned = False
    try:
        for component in components[:-1]:
            child = open_relative_directory(parent_handle, component, writable=True)
            if parent_owned:
                close_handle(parent_handle)
            parent_handle = child
            parent_owned = True
        destination = f"{final_path_from_handle(parent_handle)}\\{components[-1]}"
        encoded = destination.encode("utf-16-le")
        filename_offset = _FILE_RENAME_INFO.FileName.offset
        allocation = ctypes.create_string_buffer(filename_offset + len(encoded) + 2)
        information = ctypes.cast(
            allocation,
            ctypes.POINTER(_FILE_RENAME_INFO),
        ).contents
        information.ReplaceIfExists = bool(replace)
        information.RootDirectory = None
        information.FileNameLength = len(encoded)
        destination_buffer = ctypes.addressof(allocation) + filename_offset
        ctypes.memmove(destination_buffer, encoded, len(encoded))

        kernel32 = _dll("kernel32")
        rename = kernel32.SetFileInformationByHandle
        rename.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        rename.restype = wintypes.BOOL
        if not rename(
            wintypes.HANDLE(handle),
            FILE_RENAME_INFO_CLASS,
            allocation,
            len(allocation),
        ):
            error_number = int(ctypes.get_last_error() or 0)
            if error_number in {80, 183}:
                raise WindowsObjectExistsError(
                    "The Windows promotion destination already existed.",
                    winerror=error_number,
                )
            raise WindowsNativeError(
                "A private Windows artifact could not be promoted safely.",
                winerror=error_number,
            )
    finally:
        if parent_owned:
            close_handle(parent_handle)
