# Windows guide

Windows can create the encrypted Apple backup and can inspect an already complete private
extraction. Fresh `extract` and `recover` are deliberately unsupported in this release. iMazing is
not required.

## 1. Make a completed encrypted backup

Use Apple Devices on current Windows systems, or iTunes where Apple Devices is unavailable.
Connect the iPhone or iPad, select a local backup, enable backup encryption, choose and save a unique
password, and wait for the latest-backup time to update. Confirm the completed backup appears as
encrypted in Apple's backup-management screen.

Eject the device in Apple software, wait for it to disappear, and disconnect it. Do not move,
rename, edit, or clean the backup while Apple software is using it.

Common backup-parent locations are:

```text
%USERPROFILE%\Apple\MobileSync\Backup
%APPDATA%\Apple Computer\MobileSync\Backup
```

The individual backup is the child folder that directly contains `Manifest.plist`, `Manifest.db`,
and `Status.plist`, not the parent `Backup` folder.

## 2. Why Windows fresh recovery fails closed

Recovery must create a brand-new directory and bind that exact filesystem object before any
plaintext can be written. Python's supported Windows APIs cannot atomically create a directory and
open its protective non-delete-sharing handle. Creating by pathname and opening afterward leaves a
substitution interval, so this release refuses Windows `extract` and `recover` before creating the
run directory, loading the decryption dependency, or writing plaintext.

There is no unsafe override. A future Windows recovery path requires a reviewed native atomic design.
The package therefore does not advertise a general Windows operating-system classifier.

## 3. Safe recovery route

Copy the intact encrypted backup to private storage on macOS or Linux and run recovery there. Keep
the original encrypted backup until the result is validated. If transferring a completed extraction
back to Windows, protect it with BitLocker and treat every title and history row as private.

For any fresh run path, the encrypted immediate parent must already exist and the proposed run child
must not exist. This parent-exists/child-does-not rule applies on every platform; it does not enable
Windows fresh recovery.

## 4. Install the supported Windows review tools

Install an explicitly selected Python 3.10 through 3.13 from python.org or another trusted managed
source. The examples prefer 3.13 so `py` cannot silently select unsupported Python 3.14. From the
project folder in PowerShell:

```text
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: --requirement requirements.lock
.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: --requirement requirements-source-build.lock
.venv\Scripts\python.exe -m pip install --no-index --no-build-isolation --no-deps .
.venv\Scripts\python.exe -m pip check
.venv\Scripts\python.exe -m tvtime_extractor --version
```

You may substitute an explicit `py -3.10`, `-3.11`, or `-3.12`. Do not use an unqualified `py -3`
when it could select 3.14.

## 5. Analyze or report an existing complete extraction

Use only an extraction that already has a valid complete extraction marker:

```text
.venv\Scripts\python.exe -m tvtime_extractor analyze --extraction "D:\Private\TVTime-Extraction"
.venv\Scripts\python.exe -m tvtime_extractor report --extraction "D:\Private\TVTime-Extraction"
```

These standalone commands open the selected existing root without delete sharing, reject reparse
points, compare its volume/file identity with the visible path, keep the handle open, and validate
the identity again at completion. They never unlock an iOS backup.

Running `extract` or `recover` on Windows returns a fixed unsupported-platform error. It must not
prompt for the password or create the proposed output child.

## 6. Private diagnostics and validation

The normal CLI error is deliberately sanitized. `--debug` can expose backup paths, dependency
details, recovered names, or password text in a chained third-party exception. Use it only in a
private local terminal and never paste or share its traceback.

For an existing complete extraction, confirm both `metadata\run_state.json` and
`analysis\recovery_state.json` say `complete`. Never upload the extraction, reports, screenshots, or
debug output.

See the [output reference](output-reference.md), [privacy guide](privacy.md), and
[troubleshooting guide](troubleshooting.md).
