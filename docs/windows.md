# Windows guide

Public v0.2.0 contains no Windows app. This checkout contains an unpublished private x64 WinUI 3
candidate for Windows 10 version 1809 or later. It can recover a supported Android source or an
official TV Time export without uploading anything. On Windows 11 x64, it also contains a candidate
encrypted iOS recovery route. That route is not merge-ready until a real Windows build and
synthetic end-to-end smoke test confirm it.

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
checks exact byte sizes and SHA-256 values. There is no network capability or telemetry.
The packaged WinUI desktop process declares only the required restricted `runFullTrust` capability
so it can launch the frozen local helper; it declares no internet, broad-filesystem, device, or
privacy-sensitive capability.

After validation, the result screen can open the canonical Markdown report, open the offline HTML
report, or show the private output folder. Opening a report can add its filename to browser/viewer
history or Windows Recent Items. The app does not persist the selected source or completed-output
path for a later session, and it never silently deletes incomplete or completed recovery output.
Windows can remove packaged local data during uninstall, so review retained results before manually
removing the private app. The installer refuses to uninstall or replace an existing package.

## Build and install privately

Use a private Windows x64 machine with Python 3.13.12, a current Visual Studio installation
including MSBuild/MSIX tooling, the .NET 8 SDK, and the Windows 10/11 SDK. The direct and transitive
Windows App SDK dependencies are exact and content-hash bound in `packages.lock.json`; the build
fails if restore would change that graph. From a clean PowerShell session in this source checkout:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\script\install_windows_private.ps1
```

The scripts install only hash-locked binary Python dependencies, freeze the architecture-specific
helper, build one self-contained x64 MSIX, expand and privacy-scan it, create or reuse a per-user
self-signed code-signing certificate, trust only its public certificate in the current user's
`TrustedPeople` store, sign and verify the package, and install it for the current user. They do not
create a tag, commit, release, upload, or public package.

The build also verifies every restored NuGet package against both its downloaded SHA-512 and the
committed lock content hash, validates the exact Python distribution versions, and embeds their
available license and notice texts with a content-hashed `Notices/MANIFEST.json`. The Windows SDK
build-tools package remains build-host-only and is not copied into the MSIX.

Generated build material stays in `dist-windows-private` and `.build-tools`; neither location is an
appropriate place for recovered data. A repeated build fails closed if a previous generated helper
exists, so it cannot silently replace review evidence.

## iOS source

The source chooser accepts a completed encrypted iOS backup folder on Windows 11 x64. Disconnect
the phone after Apple Devices or iTunes finishes the backup, select the individual backup folder,
confirm sensitive output, and enter the local-backup password only in the native password field.

This route is a private candidate, not part of v0.2.0. Before merge, it requires a locked-dependency
Windows build, the real NTFS capability tests, a synthetic UI screenshot, and a synthetic
end-to-end recovery smoke test. Never use real titles, history, identifiers, paths, or recovered
output in that evidence.

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
