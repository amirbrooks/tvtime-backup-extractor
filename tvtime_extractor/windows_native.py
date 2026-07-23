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


INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_TEMPORARY = 0x00000100
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
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


def require_supported_runtime() -> None:
    _require_windows()
    if ctypes.sizeof(ctypes.c_void_p) != 8 or platform.machine().casefold() not in {
        "amd64",
        "x86_64",
    }:
        raise WindowsUnsupportedError("Windows recovery requires 64-bit x64 Python.")
    version = sys.getwindowsversion()
    if version.major < 10 or version.build < 22000:
        raise WindowsUnsupportedError("Windows recovery requires Windows 11 or later.")


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


def require_recovery_capabilities(handle: int) -> None:
    """Probe the non-mutating Windows contract before any password is requested."""

    require_supported_runtime()
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
    sddl = f"O:{sid}D:P(A;;FA;;;SY)(A;;FA;;;{sid})"
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
    information = handle_information(handle)
    if not information.is_directory or information.is_reparse_point:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise WindowsNativeError("The fresh Windows destination was not a regular directory.")
    try:
        validate_private_acl(handle)
    except BaseException:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise
    return handle


def open_relative_directory(parent_handle: int, name: str, *, writable: bool) -> int:
    desired = (
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
    )
    if writable:
        desired |= FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_ATTRIBUTES | WRITE_DAC
    handle, _ = _nt_create_relative(
        parent_handle,
        name,
        desired_access=desired,
        share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
        disposition=FILE_OPEN,
        options=FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        file_attributes=FILE_ATTRIBUTE_NORMAL,
        security_descriptor=None,
    )
    information = handle_information(handle)
    if not information.is_directory or information.is_reparse_point:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise WindowsNativeError("A Windows capability path traversed an unsafe directory.")
    return handle


def open_relative_directory_for_rename(root_handle: int, parts: Sequence[str]) -> int:
    """Open one descendant directory with DELETE access while rejecting reparse traversal."""

    components = validate_relative_parts(parts)
    parent = root_handle
    parent_owned = False
    try:
        for component in components[:-1]:
            child = open_relative_directory(parent, component, writable=False)
            if parent_owned:
                close_handle(parent)
            parent = child
            parent_owned = True
        handle, _ = _nt_create_relative(
            parent,
            components[-1],
            desired_access=(
                FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | DELETE
                | SYNCHRONIZE
            ),
            share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
            disposition=FILE_OPEN,
            options=(FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT),
            file_attributes=FILE_ATTRIBUTE_NORMAL,
            security_descriptor=None,
        )
        information = handle_information(handle)
        if not information.is_directory or information.is_reparse_point:
            with contextlib.suppress(Exception):
                close_handle(handle)
            raise WindowsNativeError("A Windows promotion source was not a safe directory.")
        return handle
    finally:
        if parent_owned:
            close_handle(parent)


def ensure_relative_directory(
    parent_handle: int,
    name: str,
    *,
    require_existing_private_acl: bool = True,
) -> tuple[int, bool]:
    with private_security_descriptor() as descriptor:
        handle, result = _nt_create_relative(
            parent_handle,
            name,
            desired_access=(
                FILE_LIST_DIRECTORY
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | READ_CONTROL
                | WRITE_DAC
                | SYNCHRONIZE
            ),
            share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
            disposition=FILE_OPEN_IF,
            options=(FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT),
            file_attributes=FILE_ATTRIBUTE_NORMAL,
            security_descriptor=descriptor,
        )
    information = handle_information(handle)
    if not information.is_directory or information.is_reparse_point:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise WindowsNativeError("A private Windows directory was unsafe.")
    created = result == FILE_CREATED
    if created or require_existing_private_acl:
        try:
            validate_private_acl(handle)
        except BaseException:
            with contextlib.suppress(Exception):
                close_handle(handle)
            raise
    return handle, created


def open_relative_regular_file(parent_handle: int, name: str) -> int:
    handle, _ = _nt_create_relative(
        parent_handle,
        name,
        desired_access=GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        share_access=FILE_SHARE_READ,
        disposition=FILE_OPEN,
        options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        file_attributes=FILE_ATTRIBUTE_NORMAL,
        security_descriptor=None,
    )
    information = handle_information(handle)
    if information.is_directory or information.is_reparse_point:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise WindowsNativeError("A Windows capability file was not a regular file.")
    return handle


def create_fresh_regular_file(parent_handle: int, name: str, *, temporary: bool = False) -> int:
    attributes = FILE_ATTRIBUTE_NORMAL | (FILE_ATTRIBUTE_TEMPORARY if temporary else 0)
    with private_security_descriptor() as descriptor:
        handle, _ = _nt_create_relative(
            parent_handle,
            name,
            desired_access=(
                GENERIC_READ
                | GENERIC_WRITE
                | DELETE
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | READ_CONTROL
                | SYNCHRONIZE
            ),
            share_access=0,
            disposition=FILE_CREATE,
            options=(
                FILE_NON_DIRECTORY_FILE
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT
                | FILE_WRITE_THROUGH
            ),
            file_attributes=attributes,
            security_descriptor=descriptor,
        )
    information = handle_information(handle)
    if information.is_directory or information.is_reparse_point:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise WindowsNativeError("A fresh private Windows file was unsafe.")
    try:
        validate_private_acl(handle)
    except BaseException:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise
    return handle


def create_or_replace_regular_file(
    parent_handle: int,
    name: str,
    *,
    exclusive: bool,
    temporary: bool = False,
) -> int:
    """Create a private file, or atomically truncate the existing regular file."""

    attributes = FILE_ATTRIBUTE_NORMAL | (FILE_ATTRIBUTE_TEMPORARY if temporary else 0)
    with private_security_descriptor() as descriptor:
        handle, _ = _nt_create_relative(
            parent_handle,
            name,
            desired_access=(
                GENERIC_READ
                | GENERIC_WRITE
                | DELETE
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | READ_CONTROL
                | WRITE_DAC
                | SYNCHRONIZE
            ),
            share_access=0,
            disposition=FILE_CREATE if exclusive else FILE_OVERWRITE_IF,
            options=(
                FILE_NON_DIRECTORY_FILE
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT
                | FILE_WRITE_THROUGH
            ),
            file_attributes=attributes,
            security_descriptor=descriptor,
        )
    information = handle_information(handle)
    if information.is_directory or information.is_reparse_point:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise WindowsNativeError("A private Windows file was unsafe.")
    try:
        validate_private_acl(handle)
    except BaseException:
        with contextlib.suppress(Exception):
            close_handle(handle)
        raise
    return handle


def open_relative_path(root_handle: int, parts: Sequence[str], *, directory: bool = False) -> int:
    components = validate_relative_parts(parts)
    current = root_handle
    owned = False
    try:
        for component in components[:-1]:
            child = open_relative_directory(current, component, writable=False)
            if owned:
                close_handle(current)
            current = child
            owned = True
        result = (
            open_relative_directory(current, components[-1], writable=False)
            if directory
            else open_relative_regular_file(current, components[-1])
        )
        return result
    finally:
        if owned:
            close_handle(current)


def ensure_relative_directory_path(
    root_handle: int,
    parts: Sequence[str],
    *,
    require_existing_private_acl: bool = True,
) -> int:
    components = validate_relative_parts(parts)
    current = root_handle
    owned = False
    try:
        for component in components:
            child, _created = ensure_relative_directory(
                current,
                component,
                require_existing_private_acl=require_existing_private_acl,
            )
            if owned:
                close_handle(current)
            current = child
            owned = True
        owned = False
        return current
    finally:
        if owned:
            close_handle(current)


def create_relative_regular_file_path(
    root_handle: int,
    parts: Sequence[str],
    *,
    temporary: bool = False,
    exclusive: bool = True,
    require_existing_private_acl: bool = True,
) -> int:
    components = validate_relative_parts(parts)
    parent = root_handle
    owned = False
    try:
        if len(components) > 1:
            parent = ensure_relative_directory_path(
                root_handle,
                components[:-1],
                require_existing_private_acl=require_existing_private_acl,
            )
            owned = True
        return create_or_replace_regular_file(
            parent,
            components[-1],
            exclusive=exclusive,
            temporary=temporary,
        )
    finally:
        if owned:
            close_handle(parent)


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


def flush_handle(handle: int) -> None:
    kernel32 = _dll("kernel32")
    function = kernel32.FlushFileBuffers
    function.argtypes = [wintypes.HANDLE]
    function.restype = wintypes.BOOL
    if not function(wintypes.HANDLE(handle)):
        raise _last_error("A private Windows file could not be flushed safely.")


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
