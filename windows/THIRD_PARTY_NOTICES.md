# Third-party notices for the Windows alpha

The Windows package contains CPython, the frozen TV Time recovery helper and its pinned
Python dependencies, the Windows App SDK, WinUI, and a self-contained .NET runtime. The local build
copies the available license and notice files for CPython, Python packages, and lock-file NuGet
packages into `Notices`, verifies each locked NuGet package SHA-512 against `packages.lock.json`, and
generates `Notices/MANIFEST.json` with exact versions and SHA-256 values for those included notices.

The public alpha build starts from a verified Git archive of one reviewed commit and records that
commit and tree in `windows-release-manifest.json`. It scans the final signed MSIX and binds every
downloadable file to an exact size and SHA-256 value. The build also records the pinned .NET SDK
used to resolve the self-contained runtime and includes Microsoft's runtime license and third-party
notice files in the package.

`Microsoft.Windows.SDK.BuildTools` is used only on the build host and is not redistributed
inside the MSIX. Its exact version remains locked and requires acceptance of Microsoft's Windows SDK
license on that build host. Project source is licensed under the repository's MIT `LICENSE` file.

This package remains an experimental alpha. Its source, dependency, license, signature, install,
launch, and synthetic validator checks do not prove every physical device, backup, filesystem, or UI
path. The notice manifest does not yet claim a complete final binary-to-component inventory. Testers
should report only Safe Diagnostics codes and synthetic reproduction steps.
