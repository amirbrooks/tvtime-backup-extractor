# Windows guide

The current source tree supports full command-line recovery on Windows 11 x64 with 64-bit Python
3.10 through 3.13. The published v0.2.0 packages predate this work and still support only
`analyze` and `report` on Windows; do not treat a local source checkout as a published Windows
release. iMazing is not required.

## 1. Requirements

- Windows 11 on x64 with 64-bit Python 3.10, 3.11, 3.12, or 3.13.
- A completed encrypted backup created by Apple Devices or iTunes.
- A local NTFS output volume with persistent ACL support. ReFS, FAT, exFAT, UNC/network paths,
  cloud-sync roots, WSL paths, and reparse-point destinations are rejected.
- A private destination protected by BitLocker or equivalent full-volume encryption. The tool
  cannot reliably verify BitLocker state, so the sensitive-output acknowledgement remains required.
- The immediate output parent must already exist and the selected run child must not exist.

Windows ARM64, 32-bit Python, Windows 10, containers, WSL recovery, and a native Windows GUI are not
supported by this initial backend.

## 2. Make and locate a completed encrypted backup

In Apple Devices, select a local backup, enable backup encryption, save its password, and wait for
the latest-backup time to update. Confirm the backup appears as encrypted, eject the device in Apple
software, wait for it to disappear, and disconnect it. Do not move, rename, edit, or clean the
backup while Apple software is using it.

Common backup-parent locations are:

```text
%USERPROFILE%\Apple\MobileSync\Backup
%APPDATA%\Apple Computer\MobileSync\Backup
```

Select the individual child folder that directly contains `Manifest.plist`, `Manifest.db`, and
`Status.plist`, not the parent `Backup` folder.

## 3. Why native Windows recovery is now possible

The earlier limitation correctly described `CreateDirectoryW`: it creates a directory but does not
return a handle, so opening it afterward leaves a substitution interval. The new backend does not
use that two-step sequence. It calls the documented Windows `NtCreateFile` API with `FILE_CREATE`,
`FILE_DIRECTORY_FILE`, `FILE_OPEN_REPARSE_POINT`, and the already-held parent as `RootDirectory`.
That one operation creates the fresh directory, applies a protected ACL, and returns its handle.

The backend then keeps the source root, destination parent, and output root open without delete
sharing; creates descendants relative to those handles; rejects reparse components; decrypts into
exclusive held staging descriptors; and atomically promotes completed files with
`SetFileInformationByHandle`. It validates native volume/file identities and the visible paths
before and after recovery. The protected output ACL grants full control only to the current user and
SYSTEM.

Capability checks run before password entry. Unsupported Windows versions, architectures,
filesystems, ACLs, paths, or unavailable native APIs fail before plaintext creation.

## 4. Install from this source checkout

Install an explicitly selected 64-bit Python 3.10 through 3.13 from python.org or another trusted
managed source. From the project folder in PowerShell:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: --requirement requirements.lock
.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: --requirement requirements-source-build.lock
.venv\Scripts\python.exe -m pip install --no-index --no-build-isolation --no-deps .
.venv\Scripts\python.exe -m pip check
.venv\Scripts\python.exe -m tvtime_extractor --version
```

You may substitute an explicit `py -3.10`, `-3.11`, or `-3.13`. Do not use an unqualified `py -3`
when it could select unsupported Python 3.14. Confirm the selected interpreter is 64-bit:

```powershell
.venv\Scripts\python.exe -c "import struct; print(struct.calcsize('P') * 8)"
```

The result must be `64`.

## 5. Run recovery

Create a private parent on a BitLocker-protected local NTFS volume. Choose a new child name that
does not exist, then run:

```powershell
.venv\Scripts\python.exe -m tvtime_extractor recover `
  --backup "C:\Synthetic\DEVICE_BACKUP" `
  --output "D:\Private\NEW_RUN" `
  --acknowledge-sensitive-output
```

The CLI completes preflight before prompting securely for the backup password. Keep Apple Devices
and iTunes closed and do not reconnect the phone during recovery. `extract` has the same Windows
support, including the advanced `--include-decrypted-manifest` option; retained manifests are
especially sensitive and remain opt-in.

Do not put the password in the command, an environment variable, shell history, or a support
request. An interrupted or failed run remains private and marked incomplete; retry into a different
fresh child instead of reusing it.

## 6. Analyze or rebuild reports

Successful `recover` already runs analysis and reporting. The standalone commands remain available
for a completed extraction:

```powershell
.venv\Scripts\python.exe -m tvtime_extractor analyze --extraction "D:\Private\TVTime-Extraction"
.venv\Scripts\python.exe -m tvtime_extractor report --extraction "D:\Private\TVTime-Extraction"
```

Opening private reports can add their filenames to browser or viewer history and Windows Recent
Items. Close those windows after validation and keep the output off cloud-sync and shared storage.

## 7. Private diagnostics

Normal CLI errors are deliberately sanitized. `--debug` can expose paths, dependency details,
recovered names, or password text in a chained exception. Use it only in a private local terminal
and never paste or share its traceback. Never upload a backup, extraction, report, database,
completion marker, screenshot, or recovered title list.

See the [output reference](output-reference.md), [privacy guide](privacy.md), and
[troubleshooting guide](troubleshooting.md).
