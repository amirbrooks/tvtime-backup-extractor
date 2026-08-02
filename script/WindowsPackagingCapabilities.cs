using System;
using System.Collections.Generic;
using Microsoft.Win32.SafeHandles;

namespace TVTimeWindowsPackaging
{
    public sealed class OwnedDirectory : IDisposable
    {
        internal OwnedDirectory(
            SafeFileHandle handle,
            string identity)
        {
            Handle = handle;
            Identity = identity;
        }

        public SafeFileHandle Handle { get; private set; }
        public string Identity { get; private set; }

        internal SafeFileHandle DetachHandle()
        {
            SafeFileHandle result = Handle;
            Handle = null;
            return result;
        }

        internal void RestoreHandle(SafeFileHandle handle)
        {
            if (Handle != null)
                throw new InvalidOperationException(
                    "A Windows packaging capability still owned its native handle.");
            Handle = handle;
        }

        public void Dispose()
        {
            if (Handle != null) Handle.Dispose();
        }
    }

    public sealed class TreeSnapshot : IDisposable
    {
        private readonly List<SafeFileHandle> handles;
        private readonly string manifest;

        internal TreeSnapshot(
            List<SafeFileHandle> handles,
            string identity,
            string manifest,
            string path)
        {
            if (handles == null) throw new ArgumentNullException("handles");
            if (handles.Count == 0)
                throw new ArgumentException("A tree snapshot requires a root handle.", "handles");

            this.handles = handles;
            this.manifest = manifest;
            Identity = identity;
            Path = path;
        }

        public SafeFileHandle Handle { get { return handles[0]; } }
        public string Identity { get; private set; }
        public string Manifest { get { return manifest; } }
        public string Path { get; private set; }

        internal void ReleaseDescendants()
        {
            for (int index = handles.Count - 1; index >= 1; index--)
            {
                handles[index].Dispose();
                handles.RemoveAt(index);
            }
        }

        internal void AttachDescendants(List<SafeFileHandle> descendants)
        {
            if (descendants == null) throw new ArgumentNullException("descendants");
            if (handles.Count != 1)
                throw new InvalidOperationException(
                    "A Windows packaging snapshot still retained descendant handles.");
            handles.AddRange(descendants);
            descendants.Clear();
        }

        internal void MoveTo(string path)
        {
            if (String.IsNullOrEmpty(path))
                throw new ArgumentException("A tree snapshot path was unavailable.", "path");
            Path = path;
        }

        public void Dispose()
        {
            for (int index = handles.Count - 1; index >= 0; index--)
                handles[index].Dispose();
            handles.Clear();
        }
    }

    public static class DirectoryCapabilities
    {
        public static OwnedDirectory CreateChild(string trustedRoot, string childName)
        {
            using (SafeFileHandle root = WindowsPackagingNative.OpenCreationRoot(trustedRoot))
                return WindowsPackagingNative.CreateChild(root, childName);
        }

        public static OwnedDirectory CreateChild(
            SafeFileHandle trustedRoot,
            string childName)
        {
            return WindowsPackagingNative.CreateChild(trustedRoot, childName);
        }

        public static string ReadPathIdentity(string path)
        {
            return WindowsPackagingNative.ReadPathIdentity(path);
        }

        public static string ReadHandleIdentity(SafeFileHandle handle)
        {
            WindowsPackagingNative.RequireOrdinaryDirectory(handle);
            return WindowsPackagingNative.Identity(handle);
        }

        public static string Rename(
            OwnedDirectory owned,
            string destinationRoot,
            string destinationName)
        {
            if (owned == null) throw new ArgumentNullException("owned");
            using (SafeFileHandle root = WindowsPackagingNative.OpenPromotionRoot(destinationRoot))
            {
                return RenameOwned(owned, root, destinationRoot, destinationName);
            }
        }

        public static void Rename(
            TreeSnapshot snapshot,
            string destinationRoot,
            string destinationName)
        {
            if (snapshot == null) throw new ArgumentNullException("snapshot");
            using (SafeFileHandle root = WindowsPackagingNative.OpenPromotionRoot(destinationRoot))
            {
                RenameSnapshot(snapshot, root, destinationRoot, destinationName);
            }
        }

        public static string Rename(
            OwnedDirectory owned,
            SafeFileHandle destinationRoot,
            string destinationRootPath,
            string destinationName)
        {
            if (owned == null) throw new ArgumentNullException("owned");
            WindowsPackagingNative.RequireOrdinaryDirectory(destinationRoot);
            return RenameOwned(
                owned,
                destinationRoot,
                destinationRootPath,
                destinationName);
        }

        public static void Rename(
            TreeSnapshot snapshot,
            SafeFileHandle destinationRoot,
            string destinationRootPath,
            string destinationName)
        {
            if (snapshot == null) throw new ArgumentNullException("snapshot");
            WindowsPackagingNative.RequireOrdinaryDirectory(destinationRoot);
            RenameSnapshot(
                snapshot,
                destinationRoot,
                destinationRootPath,
                destinationName);
        }

        public static void DeleteTree(string path, OwnedDirectory owned)
        {
            if (owned == null) throw new ArgumentNullException("owned");
            WindowsPackagingTree.DeleteOwned(path, owned.Handle, owned.Identity);
        }

        public static void DeleteTree(string path, TreeSnapshot snapshot)
        {
            if (snapshot == null) throw new ArgumentNullException("snapshot");
            snapshot.ReleaseDescendants();
            WindowsPackagingTree.DeleteOwned(path, snapshot.Handle, snapshot.Identity);
        }

        public static TreeSnapshot LockTree(string path)
        {
            return WindowsPackagingTree.Lock(path);
        }

        public static TreeSnapshot LockTreeForMove(string path)
        {
            return WindowsPackagingTree.LockForMove(path);
        }

        public static TreeSnapshot FreezeTree(OwnedDirectory owned, string path)
        {
            return WindowsPackagingTree.Freeze(owned, path);
        }

        public static string ReadTreeManifest(string path)
        {
            return WindowsPackagingTree.ReadManifest(path);
        }

        public static void RevalidateTree(TreeSnapshot snapshot, string path)
        {
            if (snapshot == null) throw new ArgumentNullException("snapshot");
            WindowsPackagingTree.Revalidate(snapshot, path);
        }

        private static void RenameSnapshot(
            TreeSnapshot snapshot,
            SafeFileHandle destinationRoot,
            string destinationRootPath,
            string destinationName)
        {
            // Child handles intentionally deny delete sharing and must be released
            // before Windows can rename their ancestor. The root handle is retained:
            // its no-delete share pins the root identity, and its DELETE access makes
            // the rename handle-relative rather than path-authorized.
            WindowsPackagingTree.Revalidate(snapshot, snapshot.Path);
            snapshot.ReleaseDescendants();
            string destination = WindowsPackagingNative.RenameRetainedRoot(
                snapshot.Handle,
                snapshot.Identity,
                destinationRoot,
                destinationRootPath,
                destinationName);

            // Record the already-completed move before relocking. If the relock
            // detects a changed tree, callers still own the exact cleanup-capable
            // root at its destination path.
            snapshot.MoveTo(destination);
            WindowsPackagingTree.RelockAfterMove(snapshot, destination);
        }

        private static string RenameOwned(
            OwnedDirectory owned,
            SafeFileHandle destinationRoot,
            string destinationRootPath,
            string destinationName)
        {
            return WindowsPackagingNative.RenameRetainedRoot(
                owned.Handle,
                owned.Identity,
                destinationRoot,
                destinationRootPath,
                destinationName);
        }
    }
}
