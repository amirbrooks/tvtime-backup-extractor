# Third-party notices for the private Windows candidate

The private Windows package contains CPython, the frozen TV Time recovery helper and its pinned
Python dependencies, the Windows App SDK, WinUI, and a self-contained .NET runtime. The local build
copies the available license and notice files for CPython, Python packages, and lock-file NuGet
packages into `Notices`, verifies each locked NuGet package SHA-512 against `packages.lock.json`, and
generates `Notices/MANIFEST.json` with exact versions and SHA-256 values for those included notices.

That manifest deliberately marks itself incomplete. The SDK-resolved self-contained .NET runtime
pack is not yet exact-version/hash bound or represented by a complete runtime license inventory,
and the private scripts consume a live checkout rather than an immutable commit/tree source stage.
These are explicit blockers for any distributable Windows release, not properties proved by a
successful private install.

`Microsoft.Windows.SDK.BuildTools` is used only on the private build host and is not redistributed
inside the MSIX. Its exact version remains locked and requires acceptance of Microsoft's Windows SDK
license on that build host. Project source is licensed under the repository's MIT `LICENSE` file.

This inventory is not a public-release claim. A future distributable Windows release requires the
runtime-pack binding, immutable reviewed-source staging, and a complete binary-to-component license
audit of the final signed MSIX.
