using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TVTimeRecovery.Windows;

internal sealed class PinnedRecoveryFile : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;

    private readonly string _path;
    private readonly FileIdentity _identity;
    private readonly List<SafeFileHandle> _directoryHandles;

    private PinnedRecoveryFile(
        string path,
        SafeFileHandle handle,
        NativeFileInformation information,
        List<SafeFileHandle> directoryHandles,
        int bufferSize)
    {
        _path = path;
        _identity = FileIdentity.From(information);
        _directoryHandles = directoryHandles;
        Stream = new FileStream(handle, FileAccess.Read, bufferSize, isAsync: false);
    }

    internal FileStream Stream { get; }

    internal static PinnedRecoveryFile Open(string path, string root, int bufferSize)
    {
        var fullPath = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(fullPath) ?? throw InvalidOutput();
        var directories = PinDirectoryChain(root, parent);
        SafeFileHandle? handle = null;
        PinnedRecoveryFile? pinned = null;
        try
        {
            handle = OpenHandle(
                fullPath,
                GenericRead | FileReadAttributes,
                FileShareRead,
                FileFlagOpenReparsePoint | FileFlagSequentialScan);
            var information = RequireRegularFile(handle);
            pinned = new PinnedRecoveryFile(
                fullPath, handle, information, directories, bufferSize);
            handle = null;
            pinned.EnsureIdentity();
            return pinned;
        }
        catch
        {
            pinned?.Dispose();
            handle?.Dispose();
            DisposeDirectories(directories);
            throw;
        }
    }

    internal static SafeFileHandle OpenDirectory(string path)
    {
        var handle = OpenHandle(
            Path.GetFullPath(path),
            FileReadAttributes,
            FileShareRead | FileShareWrite,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint);
        if (!GetFileInformationByHandle(handle, out var information) ||
            (information.FileAttributes & FileAttributeDirectory) == 0 ||
            (information.FileAttributes & FileAttributeReparsePoint) != 0)
        {
            handle.Dispose();
            throw InvalidOutput();
        }
        return handle;
    }

    internal void EnsureIdentity()
    {
        var current = RequireRegularFile(Stream.SafeFileHandle);
        using var visible = OpenHandle(
            _path,
            FileReadAttributes,
            FileShareRead,
            FileFlagOpenReparsePoint);
        var visibleInformation = RequireRegularFile(visible);
        if (_identity != FileIdentity.From(current) ||
            _identity != FileIdentity.From(visibleInformation))
            throw InvalidOutput();
    }

    public void Dispose()
    {
        Stream.Dispose();
        DisposeDirectories(_directoryHandles);
    }

    private static List<SafeFileHandle> PinDirectoryChain(string root, string parent)
    {
        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var fullParent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(parent));
        if (!string.Equals(fullParent, fullRoot, StringComparison.OrdinalIgnoreCase) &&
            !fullParent.StartsWith(
                fullRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
            throw InvalidOutput();

        var handles = new List<SafeFileHandle>();
        try
        {
            var current = fullRoot;
            handles.Add(OpenDirectory(current));
            var relative = Path.GetRelativePath(fullRoot, fullParent);
            if (relative != ".")
            {
                foreach (var component in relative.Split(
                    new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                    StringSplitOptions.RemoveEmptyEntries))
                {
                    if (component is "." or "..") throw InvalidOutput();
                    current = Path.Combine(current, component);
                    handles.Add(OpenDirectory(current));
                }
            }
            return handles;
        }
        catch
        {
            DisposeDirectories(handles);
            throw;
        }
    }

    private static SafeFileHandle OpenHandle(
        string path, uint access, uint share, uint flags)
    {
        var handle = CreateFileW(
            path,
            access,
            share,
            IntPtr.Zero,
            OpenExisting,
            flags,
            IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        handle.Dispose();
        throw InvalidOutput();
    }

    private static NativeFileInformation RequireRegularFile(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information) ||
            (information.FileAttributes & FileAttributeDirectory) != 0 ||
            (information.FileAttributes & FileAttributeReparsePoint) != 0)
            throw InvalidOutput();
        return information;
    }

    private static void DisposeDirectories(List<SafeFileHandle> handles)
    {
        for (var index = handles.Count - 1; index >= 0; index--) handles[index].Dispose();
        handles.Clear();
    }

    private readonly record struct FileIdentity(
        uint VolumeSerialNumber, uint FileIndexHigh, uint FileIndexLow)
    {
        internal static FileIdentity From(NativeFileInformation information) =>
            new(
                information.VolumeSerialNumber,
                information.FileIndexHigh,
                information.FileIndexLow);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        public uint Low;
        public uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileInformation
    {
        public uint FileAttributes;
        public NativeFileTime CreationTime;
        public NativeFileTime LastAccessTime;
        public NativeFileTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string name,
        uint access,
        uint share,
        IntPtr security,
        uint creation,
        uint flags,
        IntPtr template);

    [DllImport("kernel32", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle,
        out NativeFileInformation information);

    private static RecoveryUserException InvalidOutput()
    {
        return new RecoveryUserException(
            "The recovered output could not be validated completely.",
            RecoveryDiagnostic.OutputValidationFailed);
    }
}
