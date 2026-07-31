# Third-party notices for the private Windows candidate

The private Windows package contains CPython, the frozen TV Time recovery helper and its pinned
Python dependencies, the Windows App SDK, WinUI, and their locked runtime dependencies. The local
build copies the license and notice files shipped by those exact components into `Notices`, verifies
each NuGet package SHA-512 against `packages.lock.json`, and generates `Notices/MANIFEST.json` with
the exact component versions and SHA-256 of every included notice.

`Microsoft.Windows.SDK.BuildTools` is used only on the private build host and is not redistributed
inside the MSIX. Its exact version remains locked and requires acceptance of Microsoft's Windows SDK
license on that build host. Project source is licensed under the repository's MIT `LICENSE` file.

This inventory is not a public-release claim. A future distributable Windows release would still
require a complete binary-to-component license audit of the final signed MSIX.
