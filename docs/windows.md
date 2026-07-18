# Windows guide

## 1. Make an encrypted backup

Use Apple Devices on current Windows systems, or iTunes where Apple Devices is unavailable.
Connect the device, choose a local backup, enable backup encryption, set a password, and wait for the
backup to finish. The extractor supports encrypted local iOS/iPadOS backups only.

## 2. Locate the backup

Common locations are:

```text
%USERPROFILE%\Apple\MobileSync\Backup
%APPDATA%\Apple Computer\MobileSync\Backup
```

Paste each location into File Explorer's address bar. A child folder that represents a backup
contains both `Manifest.plist` and `Manifest.db`. If several exist, use the modification date and
the backup-management screen in Apple Devices or iTunes to identify the intended one. Confirm the
backup completed before disconnecting the device.

## 3. Prepare protected output

Choose a new, not-yet-created run path on a BitLocker-protected internal or external drive. Do not
use the repository, the backup folder, OneDrive, a shared folder, or an old extraction folder.

## 4. Install and run from PowerShell

Install Python 3.10 through 3.13 from python.org or another trusted managed source; Python 3.13 is
recommended for a new setup. In the repository, call the environment interpreter directly:

```text
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install --only-binary=:all: --requirement requirements.txt
.venv\Scripts\python.exe -m pip install --no-deps .
.venv\Scripts\python.exe -m tvtime_extractor --version
.venv\Scripts\python.exe -m tvtime_extractor recover --help
```

Then run one line, replacing both paths:

```text
.venv\Scripts\python.exe -m tvtime_extractor recover --backup "C:\Users\ACCOUNT\Apple\MobileSync\Backup\BACKUP_FOLDER" --output "D:\Private\TVTime\NEW_RUN" --acknowledge-sensitive-output
```

The password prompt is hidden. The default result is a readable count summary, and the complete
identifiable title list appears under
`NEW_RUN\TVTime-Extraction\analysis\TVTime-Recovered-Data.md`. Keep every output private. Use a new
run path for any retry; do not merge or overwrite results. `--json` is available only when an
explicit machine-readable local summary is needed.
