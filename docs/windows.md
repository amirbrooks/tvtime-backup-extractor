# Windows guide

The `v0.3.1-alpha.1` candidate adds a downloadable x64 WinUI 3 tester app. Windows 10 version 1809
or later can test compatible local Android sources and official TV Time exports. Windows 11 x64 can
also test encrypted iPhone and iPad backup recovery. The candidate is not published yet and remains
experimental.

## Security model

The native launcher passes only explicitly allowlisted inherited handles to the frozen helper: a
framed control pipe, sequenced event pipe, separate secret pipe, held destination-directory handle,
and null diagnostic sink. A Job Object terminates the helper tree on cancellation or app exit. The
helper atomically creates the fresh owner-only output below the held parent; file promotion uses the
held file handle and does not replace an existing name.

For encrypted iOS recovery, the helper opens the selected backup root without delete sharing and
traverses each source file relative to that held Win32 handle while rejecting reparse points. A
first helper returns an in-memory receipt for the source identity and critical metadata. A separate
password-gated helper must match that receipt before it creates output.

Recovery is refused unless Windows reports active BitLocker or device-encryption protection for the
app container volume. Output stays under the packaged app's local container. Completion is accepted
only after the app reopens the marker and every bound artifact, rejects reparse traversal, and
checks exact byte sizes and SHA-256 values. The reviewed implementation contains no network or
telemetry code, and the package declares no `internetClient` capability. Because the packaged
WinUI desktop process uses `runFullTrust` to launch the frozen local helper, absence of a manifest
internet capability is not an operating-system network sandbox; the no-network contract must remain
source- and package-audited. No broad-filesystem, device, or privacy-sensitive capability is
declared.

The recovery implementation contains no AI, machine-learning, or WebView integration. The release
gate also inspects final MSIX membership and rejects payload names associated with those features;
text-only dependency notices remain included.

Every recovery lane requires a source on private local storage. Known cloud-sync and shared roots,
nonlocal volumes, symbolic links, reparse points, and Windows cloud-placeholder hydration flags are
rejected at the selected root and every traversed or consumed descendant. Unrelated Android
snapshot entries are ignored rather than opened. The source volume must be NTFS so the held-file
identity checks remain trustworthy. Directory traversal is handle-pinned and rejects reparse or cloud-hydrated
metadata before enumeration; regular-file source opens use the operating system's no-recall option.
Copy an owner-controlled source to a private local NTFS folder first; do not weaken or bypass these
checks.

After validation, the result screen can open the canonical Markdown report, open the offline HTML
report, or show the private output folder. Opening a report can add its filename to browser/viewer
history or Windows Recent Items. The app does not persist the selected source or completed-output
path for a later session, and it never silently deletes incomplete or completed recovery output.
Windows can remove packaged local data during uninstall, so copy any reports you want to keep before
running the bundled removal script. The installer refuses to replace an existing alpha package.

## Install the tester build

After `v0.3.1-alpha.1` is published:

1. Download `TV-Time-Backup-Extractor-0.3.1-alpha.1-Windows-x64.zip` and
   `SHA256SUMS-Windows` from the official GitHub release.
2. Verify the ZIP checksum, then extract the complete ZIP to a private local folder.
3. Run `Install-Windows-Alpha.ps1` with PowerShell.
4. Read the certificate notice, type `INSTALL`, and approve the Windows trust prompt.

The alpha uses a project-specific self-signed certificate. The bundle contains the exact public
certificate and no private signing key. Installation verifies every bundled file, checks that the
MSIX signature matches the certificate, and requests permission to trust that certificate in the
local machine's `TrustedPeople` store. The app is installed only for the current user.

Copy any reports you want to keep before removal. Run `Uninstall-Windows-Alpha.ps1`, type `REMOVE`,
and approve the prompt to remove the package and its exact certificate. On a shared PC, the
certificate remains while another Windows account still has the same release package installed.

## Release build evidence

The public alpha build uses a verified Git archive from one clean commit. It pins Python 3.13.12,
.NET SDK 8.0.423, .NET runtime 8.0.29, and the complete NuGet graph. The build records the source
commit, tree, and dependency-lock digests, scans the expanded MSIX, signs it with a one-build
certificate, verifies that signing changed only the signature, and binds every downloadable file to
its exact size and SHA-256 value.

The package includes bound CPython, Python dependency, NuGet, .NET runtime, and project license
records. The alpha does not yet claim a complete final binary-to-component inventory. Hosted Windows
validation installs the exact package, confirms package registration, launch-smokes the native app,
removes it, checks certificate cleanup, and reverifies the ZIP.

These checks establish a downloadable tester build. They do not prove every physical device,
backup schema, NTFS configuration, or UI path. Keep compatibility reports synthetic and share only
Safe Diagnostics codes.

## iOS source

The source chooser accepts a completed encrypted iOS backup folder on Windows 11 x64. Disconnect
the phone after Apple Devices or iTunes finishes the backup, select the individual backup folder,
confirm sensitive output, and enter the local-backup password only in the native password field.

This route remains experimental. Never use real titles, history, identifiers, paths, or recovered
output in public evidence.

## Android and official-export sources

The native app accepts:

- a compatible unencrypted legacy Android `.ab` container (including the bounded supported vendor
  text envelope);
- a preserved folder with one allowlisted `DioCache.db` and optional
  `libCachedImageData.db`; or
- an official export ZIP, `tracking-prod-records.csv`, or `tracking-prod-records-v2.csv`.

Unknown archive members, links, traversal, duplicate required databases, unsupported schemas,
oversized inputs, and unsupported Android backup encryption fail closed. Modern Android release
apps usually cannot be captured with `adb backup`; the tool does not root a phone or bypass app
policy.

Advanced owners can use `android-probe --adb <reviewed-adb.exe>` to receive only coarse capability
states, never a serial number. `android-capture` additionally requires
`--acknowledge-device-capture` and a fresh private destination outside Git and synced folders.

## Existing-extraction CLI

Python 3.10 through 3.13 can still run standalone `analyze` and `report`. Existing roots are opened
without delete sharing, reparse points are rejected, and identity is revalidated at completion.
Normal errors are sanitized; `--debug` is for a private terminal only.

Never upload a backup, export, database, output tree, report, marker, screenshot, device ID, or
debug trace. See the [privacy guide](privacy.md) and [output reference](output-reference.md).
