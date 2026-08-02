using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace TVTimeWindowsPackaging
{
    internal static class WindowsPackagingTree
    {
        private const int MaximumDepth = 256;
        private const int MaximumEntries = 200000;
        private const long MaximumSnapshotFileBytes = 2L * 1024 * 1024 * 1024;
        private const long MaximumSnapshotTotalBytes = 8L * 1024 * 1024 * 1024;
        private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);

        internal static void DeleteOwned(
            string path,
            SafeFileHandle rootHandle,
            string expectedIdentity)
        {
            if (WindowsPackagingNative.Identity(rootHandle) != expectedIdentity ||
                WindowsPackagingNative.ReadPathIdentity(path) != expectedIdentity)
                throw new InvalidOperationException(
                    "An owned Windows packaging directory was replaced during cleanup.");

            int entries = 0;
            DeleteChildren(path, rootHandle, 0, ref entries);
            WindowsPackagingNative.ClearReadOnly(rootHandle);
            WindowsPackagingNative.MarkDelete(rootHandle);
        }

        internal static TreeSnapshot Lock(string path)
        {
            return Lock(path, false);
        }

        internal static TreeSnapshot LockForMove(string path)
        {
            return Lock(path, true);
        }

        private static TreeSnapshot Lock(string path, bool permitRootMove)
        {
            List<SafeFileHandle> handles = new List<SafeFileHandle>();
            List<string> manifest = new List<string>();
            int entries = 0;
            long totalBytes = 0;
            try
            {
                SafeFileHandle root = WindowsPackagingNative.Open(
                    path,
                    WindowsPackagingNative.DeleteAccess |
                        WindowsPackagingNative.FileListDirectory |
                        WindowsPackagingNative.FileReadAttributes |
                        WindowsPackagingNative.FileWriteAttributes |
                        WindowsPackagingNative.Synchronize,
                    permitRootMove
                        ? WindowsPackagingNative.FileShareRead |
                            WindowsPackagingNative.FileShareDelete
                        : WindowsPackagingNative.FileShareRead);
                WindowsPackagingNative.RequireOrdinaryDirectory(root);
                handles.Add(root);
                manifest.Add("D\t");
                LockChildren(
                    path, "", 0, ref entries, ref totalBytes, handles, manifest);
                return new TreeSnapshot(
                    handles,
                    WindowsPackagingNative.Identity(root),
                    String.Join("\n", manifest.ToArray()),
                    Path.GetFullPath(path));
            }
            catch
            {
                DisposeHandles(handles);
                throw;
            }
        }

        internal static TreeSnapshot Freeze(OwnedDirectory owned, string path)
        {
            if (owned == null) throw new ArgumentNullException("owned");
            List<SafeFileHandle> handles = new List<SafeFileHandle>();
            List<string> manifest = new List<string>();
            int entries = 0;
            long totalBytes = 0;
            string fullPath = Path.GetFullPath(path);
            SafeFileHandle root = owned.Handle;
            bool rootDetached = false;
            try
            {
                WindowsPackagingNative.RequireOrdinaryDirectory(root);
                if (WindowsPackagingNative.Identity(root) != owned.Identity ||
                    WindowsPackagingNative.ReadPathIdentity(fullPath) != owned.Identity)
                    throw new InvalidOperationException(
                        "An owned Windows packaging directory changed before it was frozen.");

                manifest.Add("D\t");
                LockChildren(
                    fullPath, "", 0, ref entries, ref totalBytes, handles, manifest);

                // Keep the original DELETE-capable, no-share-delete writer until
                // every descendant is locked. A failed scan therefore leaves the
                // OwnedDirectory byte-for-byte ownership contract intact.
                handles.Insert(0, root);
                SafeFileHandle detachedRoot = owned.DetachHandle();
                rootDetached = true;
                if (!Object.ReferenceEquals(detachedRoot, root))
                    throw new InvalidOperationException(
                        "A Windows packaging snapshot detached the wrong root capability.");
                return new TreeSnapshot(
                    handles,
                    owned.Identity,
                    String.Join("\n", manifest.ToArray()),
                    fullPath);
            }
            catch
            {
                if (rootDetached && root != null && handles.Count > 0 &&
                    Object.ReferenceEquals(handles[0], root))
                {
                    handles.RemoveAt(0);
                    owned.RestoreHandle(root);
                }
                DisposeHandles(handles);
                throw;
            }
        }

        internal static string ReadManifest(string path)
        {
            List<SafeFileHandle> handles = new List<SafeFileHandle>();
            List<string> manifest = new List<string>();
            int entries = 0;
            long totalBytes = 0;
            try
            {
                SafeFileHandle root = WindowsPackagingNative.Open(
                    path,
                    WindowsPackagingNative.GenericRead |
                        WindowsPackagingNative.FileListDirectory |
                        WindowsPackagingNative.FileReadAttributes |
                        WindowsPackagingNative.Synchronize,
                    WindowsPackagingNative.FileShareRead);
                WindowsPackagingNative.RequireOrdinaryDirectory(root);
                handles.Add(root);
                manifest.Add("D\t");
                LockChildren(
                    path, "", 0, ref entries, ref totalBytes, handles, manifest);
                return String.Join("\n", manifest.ToArray());
            }
            finally
            {
                DisposeHandles(handles);
            }
        }

        internal static void Revalidate(TreeSnapshot snapshot, string path)
        {
            if (snapshot == null) throw new ArgumentNullException("snapshot");
            string fullPath = Path.GetFullPath(path);

            // A directory handle's share mode pins the root object and name, but it
            // does not freeze membership below that directory. Revalidation is an
            // explicit second scan. The original descendant pins remain held while
            // temporary handles rebuild and compare the immutable manifest.
            if (WindowsPackagingNative.Identity(snapshot.Handle) != snapshot.Identity ||
                WindowsPackagingNative.ReadPathIdentity(fullPath) != snapshot.Identity)
                throw new InvalidOperationException(
                    "A Windows packaging snapshot changed root identity.");

            List<SafeFileHandle> temporary = new List<SafeFileHandle>();
            List<string> manifest = new List<string>();
            int entries = 0;
            long totalBytes = 0;
            try
            {
                manifest.Add("D\t");
                LockChildren(
                    fullPath,
                    "",
                    0,
                    ref entries,
                    ref totalBytes,
                    temporary,
                    manifest);
                if (!String.Equals(
                    String.Join("\n", manifest.ToArray()),
                    snapshot.Manifest,
                    StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        "A Windows packaging snapshot no longer matched its immutable manifest.");
            }
            finally
            {
                DisposeHandles(temporary);
            }
        }

        internal static void RelockAfterMove(TreeSnapshot snapshot, string path)
        {
            if (snapshot == null) throw new ArgumentNullException("snapshot");
            string fullPath = Path.GetFullPath(path);
            if (WindowsPackagingNative.Identity(snapshot.Handle) != snapshot.Identity ||
                WindowsPackagingNative.ReadPathIdentity(fullPath) != snapshot.Identity)
                throw new InvalidOperationException(
                    "A moved Windows packaging snapshot changed root identity.");

            List<SafeFileHandle> descendants = new List<SafeFileHandle>();
            List<string> manifest = new List<string>();
            int entries = 0;
            long totalBytes = 0;
            try
            {
                manifest.Add("D\t");
                LockChildren(
                    fullPath,
                    "",
                    0,
                    ref entries,
                    ref totalBytes,
                    descendants,
                    manifest);
                if (!String.Equals(
                    String.Join("\n", manifest.ToArray()),
                    snapshot.Manifest,
                    StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        "A moved Windows packaging snapshot no longer matched its " +
                        "immutable manifest.");
                snapshot.AttachDescendants(descendants);
            }
            catch
            {
                DisposeHandles(descendants);
                throw;
            }
        }

        private static void DeleteChildren(
            string path,
            SafeFileHandle directoryHandle,
            int depth,
            ref int entries)
        {
            if (depth > MaximumDepth)
                throw new InvalidOperationException("A Windows packaging cleanup tree was too deep.");

            string[] children = Directory.GetFileSystemEntries(path);
            foreach (string child in children)
            {
                entries++;
                if (entries > MaximumEntries)
                    throw new InvalidOperationException(
                        "A Windows packaging cleanup tree contained too many entries.");

                FileAttributes pathAttributes = File.GetAttributes(child);
                bool pathDirectory = (pathAttributes & FileAttributes.Directory) != 0;
                using (SafeFileHandle handle = WindowsPackagingNative.OpenRelativeForDelete(
                    directoryHandle,
                    Path.GetFileName(child),
                    pathDirectory))
                {
                    WindowsPackagingNative.ByHandleFileInformation basic =
                        WindowsPackagingNative.BasicInformation(handle);
                    bool isDirectory =
                        (basic.FileAttributes & WindowsPackagingNative.FileAttributeDirectory) != 0;
                    bool isReparse =
                        (basic.FileAttributes & WindowsPackagingNative.FileAttributeReparsePoint) != 0;
                    if (isDirectory != pathDirectory)
                        throw new InvalidOperationException(
                            "A Windows packaging cleanup entry changed type.");
                    if (isDirectory && !isReparse)
                        DeleteChildren(child, handle, depth + 1, ref entries);

                    WindowsPackagingNative.ClearReadOnly(handle);
                    WindowsPackagingNative.MarkDelete(handle);
                }
            }
        }

        private static void LockChildren(
            string path,
            string relative,
            int depth,
            ref int entries,
            ref long totalBytes,
            List<SafeFileHandle> handles,
            List<string> manifest)
        {
            if (depth > MaximumDepth)
                throw new InvalidOperationException("A Windows packaging snapshot tree was too deep.");

            string[] children = Directory.GetFileSystemEntries(path);
            Array.Sort(children, StringComparer.Ordinal);
            foreach (string child in children)
            {
                entries++;
                if (entries > MaximumEntries)
                    throw new InvalidOperationException(
                        "A Windows packaging snapshot tree contained too many entries.");

                string name = Path.GetFileName(child);
                string childRelative = String.IsNullOrEmpty(relative) ? name : relative + "/" + name;
                SafeFileHandle handle = WindowsPackagingNative.Open(
                    child,
                    WindowsPackagingNative.GenericRead |
                        WindowsPackagingNative.FileListDirectory |
                        WindowsPackagingNative.FileReadAttributes |
                        WindowsPackagingNative.Synchronize,
                    WindowsPackagingNative.FileShareRead);
                handles.Add(handle);

                WindowsPackagingNative.ByHandleFileInformation basic =
                    WindowsPackagingNative.BasicInformation(handle);
                if ((basic.FileAttributes & WindowsPackagingNative.FileAttributeReparsePoint) != 0)
                    throw new InvalidOperationException(
                        "A Windows packaging snapshot contained a reparse point.");

                string encodedName = Convert.ToBase64String(StrictUtf8.GetBytes(childRelative));
                if ((basic.FileAttributes & WindowsPackagingNative.FileAttributeDirectory) != 0)
                {
                    manifest.Add("D\t" + encodedName);
                    LockChildren(
                        child,
                        childRelative,
                        depth + 1,
                        ref entries,
                        ref totalBytes,
                        handles,
                        manifest);
                }
                else
                {
                    long size = ((long)basic.FileSizeHigh << 32) | basic.FileSizeLow;
                    if (size < 0 || size > MaximumSnapshotFileBytes ||
                        totalBytes > MaximumSnapshotTotalBytes - size)
                        throw new InvalidOperationException(
                            "A Windows packaging snapshot exceeded its byte bound.");
                    totalBytes += size;
                    manifest.Add(
                        "F\t" + encodedName + "\t" +
                        size.ToString(CultureInfo.InvariantCulture) + "\t" + Hash(handle, size));
                }
            }
        }

        private static string Hash(SafeFileHandle handle, long expectedBytes)
        {
            WindowsPackagingNative.Rewind(handle);
            byte[] buffer = new byte[1024 * 1024];
            long observed = 0;
            using (SHA256 algorithm = SHA256.Create())
            {
                while (true)
                {
                    uint read = WindowsPackagingNative.Read(handle, buffer);
                    if (read == 0) break;
                    observed += read;
                    algorithm.TransformBlock(buffer, 0, (int)read, buffer, 0);
                }
                algorithm.TransformFinalBlock(new byte[0], 0, 0);
                if (observed != expectedBytes)
                    throw new InvalidOperationException(
                        "A Windows packaging snapshot file changed while it was hashed.");
                return BitConverter.ToString(algorithm.Hash).Replace("-", "");
            }
        }

        private static void DisposeHandles(List<SafeFileHandle> handles)
        {
            for (int index = handles.Count - 1; index >= 0; index--)
                handles[index].Dispose();
            handles.Clear();
        }
    }
}
