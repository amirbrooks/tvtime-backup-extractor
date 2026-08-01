using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace TVTimeWindowsPackaging
{
    internal static partial class WindowsPackagingNative
    {
        internal static OwnedDirectory CreateChild(
            SafeFileHandle trustedRoot,
            string childName)
        {
            ValidateChildName(childName);
            RequireOrdinaryDirectory(trustedRoot);
            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr nameStructure = IntPtr.Zero;
            SafeFileHandle created = null;
            bool rootReference = false;
            try
            {
                trustedRoot.DangerousAddRef(ref rootReference);
                byte[] encoded = Encoding.Unicode.GetBytes(childName);
                nameBuffer = Marshal.StringToHGlobalUni(childName);
                UnicodeString name = new UnicodeString();
                name.Length = checked((ushort)encoded.Length);
                name.MaximumLength = checked((ushort)(encoded.Length + 2));
                name.Buffer = nameBuffer;
                nameStructure = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(name, nameStructure, false);

                ObjectAttributes attributes = new ObjectAttributes();
                attributes.Length = checked((uint)Marshal.SizeOf(typeof(ObjectAttributes)));
                attributes.RootDirectory = trustedRoot.DangerousGetHandle();
                attributes.ObjectName = nameStructure;
                attributes.Attributes = ObjCaseInsensitive;
                IoStatusBlock statusBlock;
                int status = NtCreateFile(
                    out created,
                    DeleteAccess | FileListDirectory | FileAddFile | FileAddSubdirectory |
                        FileTraverse | FileReadAttributes | FileWriteAttributes | Synchronize,
                    ref attributes,
                    out statusBlock,
                    IntPtr.Zero,
                    0,
                    FileShareRead | FileShareWrite,
                    FileCreate,
                    FileDirectoryFile | FileSynchronousIoNonAlert | FileOpenReparsePoint,
                    IntPtr.Zero,
                    0);
                if (status < 0)
                    throw new Win32Exception((int)RtlNtStatusToDosError(status));
                RequireOrdinaryDirectory(created);
                string identity = Identity(created);
                return new OwnedDirectory(created, identity);
            }
            catch
            {
                if (created != null) created.Dispose();
                throw;
            }
            finally
            {
                if (nameStructure != IntPtr.Zero) Marshal.FreeHGlobal(nameStructure);
                if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
                if (rootReference) trustedRoot.DangerousRelease();
            }
        }

        internal static string ReadPathIdentity(string path)
        {
            using (SafeFileHandle handle = Open(
                path, 0, FileShareRead | FileShareWrite | FileShareDelete))
            {
                RequireOrdinaryDirectory(handle);
                return Identity(handle);
            }
        }

        internal static string RenameRetainedRoot(
            SafeFileHandle handle,
            string expectedIdentity,
            SafeFileHandle destinationRoot,
            string destinationRootPath,
            string destinationName)
        {
            if (Identity(handle) != expectedIdentity)
                throw new InvalidOperationException("A Windows packaging capability changed.");
            RequireOrdinaryDirectory(destinationRoot);
            ValidateChildName(destinationName);
            string destination = Path.GetFullPath(
                Path.Combine(destinationRootPath, destinationName));

            byte[] encoded = Encoding.Unicode.GetBytes(destinationName);
            int rootOffset = IntPtr.Size == 8 ? 8 : 4;
            int lengthOffset = rootOffset + IntPtr.Size;
            int nameOffset = lengthOffset + 4;
            // FILE_RENAME_INFO declares FileName as WCHAR[1]. Retain that
            // trailing UTF-16 slot in the buffer size even though
            // FileNameLength excludes a terminator; omitting it makes the
            // structure too short on Windows and rejects the relative rename.
            int informationSize = checked(nameOffset + encoded.Length + sizeof(char));
            IntPtr buffer = Marshal.AllocHGlobal(informationSize);
            bool rootReference = false;
            try
            {
                destinationRoot.DangerousAddRef(ref rootReference);
                for (int index = 0; index < informationSize; index++)
                    Marshal.WriteByte(buffer, index, 0);
                Marshal.WriteInt32(buffer, 0, 0);
                Marshal.WriteIntPtr(
                    buffer, rootOffset, destinationRoot.DangerousGetHandle());
                Marshal.WriteInt32(buffer, lengthOffset, encoded.Length);
                Marshal.Copy(encoded, 0, Add(buffer, nameOffset), encoded.Length);
                if (!SetFileInformationByHandle(
                    handle, FileRenameInfo, buffer, (uint)informationSize))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally
            {
                if (rootReference) destinationRoot.DangerousRelease();
                Marshal.FreeHGlobal(buffer);
            }
            return destination;
        }

        internal static void ClearReadOnly(SafeFileHandle handle)
        {
            FileBasicInformation information;
            uint size = checked((uint)Marshal.SizeOf(typeof(FileBasicInformation)));
            if (!GetFileInformationByHandleEx(handle, FileBasicInfo, out information, size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((information.FileAttributes & FileAttributeReadOnly) == 0) return;

            information.FileAttributes &= ~FileAttributeReadOnly;
            if (!SetFileInformationByHandle(handle, FileBasicInfo, ref information, size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        internal static void MarkDelete(SafeFileHandle handle)
        {
            byte[] disposition = new byte[] { 1 };
            if (!SetFileInformationByHandle(
                handle,
                FileDispositionInfo,
                disposition,
                (uint)disposition.Length))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        internal static void Rewind(SafeFileHandle handle)
        {
            long pointer;
            if (!SetFilePointerEx(handle, 0, out pointer, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        internal static uint Read(SafeFileHandle handle, byte[] buffer)
        {
            uint bytesRead;
            if (!ReadFile(handle, buffer, (uint)buffer.Length, out bytesRead, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return bytesRead;
        }

        private static void ValidateChildName(string childName)
        {
            if (String.IsNullOrEmpty(childName) || childName == "." || childName == ".." ||
                childName.Length > 255 || childName.EndsWith(" ", StringComparison.Ordinal) ||
                childName.EndsWith(".", StringComparison.Ordinal) ||
                childName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                childName.IndexOfAny(new char[] { '\\', '/', '\0' }) >= 0)
                throw new InvalidOperationException("A Windows packaging child name was invalid.");
        }

        private static IntPtr Add(IntPtr pointer, int offset)
        {
            return new IntPtr(pointer.ToInt64() + offset);
        }
    }
}
