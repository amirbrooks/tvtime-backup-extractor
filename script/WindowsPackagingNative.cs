using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TVTimeWindowsPackaging
{
    internal static partial class WindowsPackagingNative
    {
        internal const uint FileShareRead = 0x00000001;
        internal const uint FileShareWrite = 0x00000002;
        internal const uint FileShareDelete = 0x00000004;
        internal const uint DeleteAccess = 0x00010000;
        internal const uint GenericRead = 0x80000000;
        internal const uint Synchronize = 0x00100000;
        internal const uint FileListDirectory = 0x00000001;
        internal const uint FileAddFile = 0x00000002;
        internal const uint FileAddSubdirectory = 0x00000004;
        internal const uint FileTraverse = 0x00000020;
        internal const uint FileReadAttributes = 0x00000080;
        internal const uint FileWriteAttributes = 0x00000100;
        internal const uint FileAttributeReparsePoint = 0x00000400;
        internal const uint FileAttributeDirectory = 0x00000010;
        internal const uint FileAttributeReadOnly = 0x00000001;

        private const uint Win32OpenExisting = 3;
        private const uint NtFileOpen = 1;
        private const uint FileCreate = 2;
        private const uint FileDirectoryFile = 0x00000001;
        private const uint FileSynchronousIoNonAlert = 0x00000020;
        private const uint FileOpenReparsePoint = 0x00200000;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint ObjCaseInsensitive = 0x00000040;
        private const int FileBasicInfo = 0;
        private const int FileRenameInfo = 3;
        private const int FileDispositionInfo = 4;
        private const int FileIdInfo = 18;

        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString
        {
            internal ushort Length;
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes
        {
            internal uint Length;
            internal IntPtr RootDirectory;
            internal IntPtr ObjectName;
            internal uint Attributes;
            internal IntPtr SecurityDescriptor;
            internal IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoStatusBlock
        {
            internal IntPtr Status;
            internal UIntPtr Information;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ByHandleFileInformation
        {
            internal uint FileAttributes;
            internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            internal uint VolumeSerialNumber;
            internal uint FileSizeHigh;
            internal uint FileSizeLow;
            internal uint NumberOfLinks;
            internal uint FileIndexHigh;
            internal uint FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        private struct FileBasicInformation
        {
            internal long CreationTime;
            internal long LastAccessTime;
            internal long LastWriteTime;
            internal long ChangeTime;
            internal uint FileAttributes;
        }

        // This fixed part mirrors FILE_RENAME_INFO exactly. Its ABI-sized
        // allocation includes the WCHAR FileName[1] member and trailing
        // alignment, before the caller appends the variable name bytes.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FileRenameInformation
        {
            internal int ReplaceIfExists;
            internal IntPtr RootDirectory;
            internal uint FileNameLength;
            internal char FileName;
        }

        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateFileW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("ntdll.dll")]
        private static extern int NtCreateFile(
            out SafeFileHandle fileHandle,
            uint desiredAccess,
            ref ObjectAttributes objectAttributes,
            out IoStatusBlock ioStatusBlock,
            IntPtr allocationSize,
            uint fileAttributes,
            uint shareAccess,
            uint createDisposition,
            uint createOptions,
            IntPtr eaBuffer,
            uint eaLength);

        [DllImport("ntdll.dll")]
        private static extern uint RtlNtStatusToDosError(int status);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file,
            int informationClass,
            [Out] byte[] information,
            uint informationSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file,
            int informationClass,
            out FileBasicInformation information,
            uint informationSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle file,
            int informationClass,
            IntPtr information,
            uint informationSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle file,
            int informationClass,
            byte[] information,
            uint informationSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle file,
            int informationClass,
            ref FileBasicInformation information,
            uint informationSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReadFile(
            SafeFileHandle file,
            byte[] buffer,
            uint bytesToRead,
            out uint bytesRead,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFilePointerEx(
            SafeFileHandle file,
            long distance,
            out long newPointer,
            uint moveMethod);

        internal static SafeFileHandle OpenCreationRoot(string path)
        {
            return OpenOrdinaryDirectory(
                path,
                FileListDirectory | FileAddSubdirectory | FileReadAttributes | Synchronize,
                FileShareRead | FileShareWrite);
        }

        internal static SafeFileHandle OpenPromotionRoot(string path)
        {
            return OpenOrdinaryDirectory(
                path,
                FileAddSubdirectory | FileReadAttributes | Synchronize,
                FileShareRead | FileShareWrite);
        }

        internal static SafeFileHandle Open(string path, uint desiredAccess, uint shareMode)
        {
            SafeFileHandle handle = CreateFile(
                path,
                desiredAccess,
                shareMode,
                IntPtr.Zero,
                Win32OpenExisting,
                FileFlagOpenReparsePoint | FileFlagBackupSemantics,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error);
            }
            return handle;
        }

        internal static ByHandleFileInformation BasicInformation(SafeFileHandle handle)
        {
            RequireUsableHandle(handle);
            ByHandleFileInformation basic;
            if (!GetFileInformationByHandle(handle, out basic))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return basic;
        }

        internal static string Identity(SafeFileHandle handle)
        {
            RequireUsableHandle(handle);
            byte[] identity = new byte[24];
            if (!GetFileInformationByHandleEx(handle, FileIdInfo, identity, (uint)identity.Length))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return BitConverter.ToString(identity).Replace("-", "");
        }

        internal static void RequireOrdinaryDirectory(SafeFileHandle handle)
        {
            ByHandleFileInformation basic = BasicInformation(handle);
            if ((basic.FileAttributes & FileAttributeReparsePoint) != 0)
                throw new InvalidOperationException(
                    "A Windows packaging directory resolved to a reparse point.");
            if ((basic.FileAttributes & FileAttributeDirectory) == 0)
                throw new InvalidOperationException(
                    "A Windows packaging directory resolved to a file.");
        }

        private static SafeFileHandle OpenOrdinaryDirectory(
            string path,
            uint desiredAccess,
            uint shareMode)
        {
            SafeFileHandle root = Open(path, desiredAccess, shareMode);
            try
            {
                RequireOrdinaryDirectory(root);
                return root;
            }
            catch
            {
                root.Dispose();
                throw;
            }
        }

        private static void RequireUsableHandle(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
                throw new InvalidOperationException("A Windows packaging capability was unavailable.");
        }
    }
}
