# Windows guide

Public v0.2.0 contains no Windows app. This checkout contains an unpublished private x64 WinUI 3
candidate for Windows 10 version 1809 or later. It can recover a supported Android source or an
official TV Time export without uploading anything. Encrypted iOS recovery remains unavailable in
this candidate because the source-root binding is not yet implemented with native Windows handles.

## Security model

The native launcher passes only explicitly allowlisted inherited handles to the frozen helper: a
framed control pipe, sequenced event pipe, separate secret pipe, held destination-directory handle,
and null diagnostic sink. A Job Object terminates the helper tree on cancellation or app exit. The
helper atomically creates the fresh owner-only output below the held parent; file promotion uses the
held file handle and does not replace an existing name.

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

Encrypted iOS recovery is intentionally absent from the Windows source chooser and fails closed if
requested through an unexpected internal call. Use the notarized macOS app or the Python CLI on
macOS or Linux. Do not enter an iOS backup password into this private Windows candidate.

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
