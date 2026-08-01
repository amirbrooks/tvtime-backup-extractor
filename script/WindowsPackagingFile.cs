using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace TVTimeWindowsPackaging
{
    public sealed class PinnedFile : IDisposable
    {
        private FileStream stream;
        private readonly List<SafeFileHandle> ancestors;

        internal PinnedFile(
            FileStream stream,
            List<SafeFileHandle> ancestors,
            string identity,
            long length,
            string relativePath)
        {
            this.stream = stream;
            this.ancestors = ancestors;
            Identity = identity;
            Length = length;
            RelativePath = relativePath;
        }

        public Stream Stream
        {
            get
            {
                if (stream == null)
                    throw new ObjectDisposedException("PinnedFile");
                return stream;
            }
        }

        public string Identity { get; private set; }
        public long Length { get; private set; }
        public string RelativePath { get; private set; }

        public void Dispose()
        {
            try
            {
                if (stream != null)
                {
                    stream.Dispose();
                    stream = null;
                }
            }
            finally
            {
                for (int index = ancestors.Count - 1; index >= 0; index--)
                    ancestors[index].Dispose();
                ancestors.Clear();
            }
        }
    }

    public static class FileCapabilities
    {
        public static PinnedFile OpenIdentityPin(
            SafeFileHandle trustedRoot,
            string relativePath)
        {
            return WindowsPackagingNative.OpenPinnedFile(
                trustedRoot,
                relativePath,
                WindowsPackagingNative.FileShareRead |
                    WindowsPackagingNative.FileShareWrite,
                null);
        }

        public static PinnedFile OpenStrictReadPin(
            SafeFileHandle trustedRoot,
            string relativePath,
            string expectedIdentity)
        {
            if (String.IsNullOrEmpty(expectedIdentity))
                throw new ArgumentException(
                    "An expected Windows package identity was unavailable.",
                    "expectedIdentity");
            return WindowsPackagingNative.OpenPinnedFile(
                trustedRoot,
                relativePath,
                WindowsPackagingNative.FileShareRead,
                expectedIdentity);
        }
    }

    internal static partial class WindowsPackagingNative
    {
        private const uint FileNonDirectoryFile = 0x00000040;
        private const long MaximumPinnedPackageBytes = 4L * 1024 * 1024 * 1024;
        private const int MaximumPinnedPathComponents = 256;

        internal static PinnedFile OpenPinnedFile(
            SafeFileHandle trustedRoot,
            string relativePath,
            uint fileShareMode,
            string expectedIdentity)
        {
            RequireOrdinaryDirectory(trustedRoot);
            string[] parts = ValidateRelativePackagePath(relativePath);
            List<SafeFileHandle> ancestors = new List<SafeFileHandle>();
            SafeFileHandle file = null;
            try
            {
                SafeFileHandle parent = trustedRoot;
                for (int index = 0; index < parts.Length - 1; index++)
                {
                    SafeFileHandle directory = null;
                    try
                    {
                        directory = OpenRelativePinned(
                            parent,
                            parts[index],
                            FileListDirectory | FileTraverse | FileReadAttributes | Synchronize,
                            FileShareRead | FileShareWrite,
                            FileDirectoryFile | FileSynchronousIoNonAlert | FileOpenReparsePoint);
                        RequireOrdinaryDirectory(directory);
                        ancestors.Add(directory);
                        parent = directory;
                        directory = null;
                    }
                    finally
                    {
                        // Rejecting a junction before it becomes an owned ancestor
                        // must not retain its handle and block later cleanup.
                        if (directory != null) directory.Dispose();
                    }
                }

                file = OpenRelativePinned(
                    parent,
                    parts[parts.Length - 1],
                    GenericRead | FileReadAttributes | Synchronize,
                    fileShareMode,
                    FileNonDirectoryFile | FileSynchronousIoNonAlert | FileOpenReparsePoint);
                ByHandleFileInformation basic = BasicInformation(file);
                if ((basic.FileAttributes & FileAttributeReparsePoint) != 0 ||
                    (basic.FileAttributes & FileAttributeDirectory) != 0)
                    throw new InvalidOperationException(
                        "The private Windows package was not an ordinary file.");
                long length = ((long)basic.FileSizeHigh << 32) | basic.FileSizeLow;
                if (length <= 0 || length > MaximumPinnedPackageBytes)
                    throw new InvalidOperationException(
                        "The private Windows package exceeded its byte bound.");
                string identity = Identity(file);
                if (expectedIdentity != null &&
                    !String.Equals(identity, expectedIdentity, StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        "The private Windows package changed identity.");

                FileStream stream = new FileStream(file, FileAccess.Read, 1024 * 1024, false);
                file = null;
                PinnedFile result = new PinnedFile(
                    stream,
                    ancestors,
                    identity,
                    length,
                    String.Join("\\", parts));
                ancestors = new List<SafeFileHandle>();
                return result;
            }
            catch
            {
                if (file != null) file.Dispose();
                for (int index = ancestors.Count - 1; index >= 0; index--)
                    ancestors[index].Dispose();
                throw;
            }
        }

        private static SafeFileHandle OpenRelativePinned(
            SafeFileHandle parent,
            string name,
            uint desiredAccess,
            uint shareAccess,
            uint options)
        {
            ValidateChildName(name);
            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr nameStructure = IntPtr.Zero;
            SafeFileHandle opened = null;
            bool parentReference = false;
            try
            {
                parent.DangerousAddRef(ref parentReference);
                byte[] encoded = Encoding.Unicode.GetBytes(name);
                nameBuffer = Marshal.StringToHGlobalUni(name);
                UnicodeString nativeName = new UnicodeString();
                nativeName.Length = checked((ushort)encoded.Length);
                nativeName.MaximumLength = checked((ushort)(encoded.Length + 2));
                nativeName.Buffer = nameBuffer;
                nameStructure = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(nativeName, nameStructure, false);

                ObjectAttributes attributes = new ObjectAttributes();
                attributes.Length = checked((uint)Marshal.SizeOf(typeof(ObjectAttributes)));
                attributes.RootDirectory = parent.DangerousGetHandle();
                attributes.ObjectName = nameStructure;
                attributes.Attributes = ObjCaseInsensitive;
                IoStatusBlock statusBlock;
                int status = NtCreateFile(
                    out opened,
                    desiredAccess,
                    ref attributes,
                    out statusBlock,
                    IntPtr.Zero,
                    0,
                    shareAccess,
                    NtFileOpen,
                    options,
                    IntPtr.Zero,
                    0);
                if (status < 0)
                    throw new Win32Exception((int)RtlNtStatusToDosError(status));
                return opened;
            }
            catch
            {
                if (opened != null) opened.Dispose();
                throw;
            }
            finally
            {
                if (nameStructure != IntPtr.Zero) Marshal.FreeHGlobal(nameStructure);
                if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
                if (parentReference) parent.DangerousRelease();
            }
        }

        private static string[] ValidateRelativePackagePath(string relativePath)
        {
            if (String.IsNullOrEmpty(relativePath) || Path.IsPathRooted(relativePath) ||
                relativePath.Length > 32767)
                throw new InvalidOperationException(
                    "The private Windows package path was not relative and bounded.");
            string[] parts = relativePath.Split(
                new char[] { '\\', '/' },
                StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0 || parts.Length > MaximumPinnedPathComponents ||
                !parts[parts.Length - 1].EndsWith(
                    ".msix", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "The private Windows package path was invalid.");
            foreach (string part in parts) ValidateChildName(part);
            return parts;
        }
    }
}
