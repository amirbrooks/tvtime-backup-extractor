# macOS guide

This is the recommended path for a first private recovery run. It uses free Apple and Python tools;
iMazing is not required.

## 1. Install and verify Python

The project supports and tests Python 3.10, 3.11, 3.12, and 3.13. For a fresh Mac, install Python
3.13 using the free **macOS 64-bit universal2 installer** from
[python.org/downloads/macos](https://www.python.org/downloads/macos/). Homebrew is not required.
Close and reopen Terminal after installation, then verify what will run:

```text
python3 --version
command -v python3
```

Continue if the version is 3.10 through 3.13. If Apple's `python3` asks to install Command Line Tools
or reports an older version, use the Python.org installer and repeat the verification. The later
commands call `.venv/bin/python` directly so they cannot silently switch interpreters.

## 2. Make and verify an encrypted backup

1. Connect the iPhone or iPad to the Mac, unlock it, and approve **Trust** if asked.
2. Open Finder and select the device in the sidebar.
3. Under **General**, select **Back up all of the data on your device to this Mac**.
4. Enable **Encrypt local backup**, choose a unique password, and store it safely.
5. Select **Back Up Now**. Keep the cable connected and respond if Finder asks you to unlock the
   device. The display does not need to remain permanently on.
6. Wait until Finder no longer says **Backing up**, its progress indicator has disappeared, and the
   **Latest Backup to this Mac** date and time have updated.
7. Choose **Manage Backups**. Confirm that the newly dated backup is present and shows the encrypted
   backup lock indicator. Use **Show in Finder** to identify its folder.

Do not infer completion only from a pause in the progress animation or the backup's size. The
extractor needs the encryption password and cannot recover or reset it.

Once those checks pass, click the eject button beside the device in Finder. Wait for the device to
disappear from Finder's sidebar, then disconnect the cable. The extraction uses the Mac backup and
does not require the phone to remain attached.

## 3. Locate and verify the backup folder

Finder backups are normally stored under:

```text
$HOME/Library/Application Support/MobileSync/Backup/
```

In Finder, choose **Go → Go to Folder**, paste `~/Library/Application Support/MobileSync/Backup/`,
and open `Backup`. Each long-named child folder is a device backup. Prefer **Manage Backups → Show
in Finder** when several backups exist.

In Terminal, set `BACKUP` to that individual long-named folder. Replace `BACKUP_FOLDER_NAME`; do not
include the literal placeholder:

```text
BACKUP="$HOME/Library/Application Support/MobileSync/Backup/BACKUP_FOLDER_NAME"
test -f "$BACKUP/Manifest.plist" && test -f "$BACKUP/Manifest.db" \
  && echo "Backup folder confirmed"
```

If **Show in Finder** reveals a different location, use that actual path instead. The confirmation
must print before continuing. Do not move, rename, edit, or clean the source backup.

## 4. Choose protected output and check space

Use either a FileVault-protected Mac account or an encrypted APFS volume/disk image with a password
distinct from the iOS backup password. Avoid iCloud Drive, Dropbox, shared folders, the project, and
the source backup.

The extractor does not duplicate a 120 GB device backup. It needs working space for:

- one temporary decrypted `Manifest.db`, approximately the size of the source `Manifest.db`;
- the files in the backed-up TV Time app domain;
- normalized tables and the report; and
- another `Manifest.db` only if the advanced `--include-decrypted-manifest` option is used.

The storage amount shown for TV Time on the phone is only an estimate of the app-domain output. A
conservative starting allowance is twice the source `Manifest.db`, twice the reported TV Time data,
plus 1 GB of headroom. If either size is unknown, leave several GB free. Inspect the manifest size
and the destination's available space without changing either:

```text
ls -lh "$BACKUP/Manifest.db"
df -h "$HOME"
```

For output in a FileVault-protected home folder, create a unique run name automatically:

```text
OUTPUT="$HOME/TVTime-Private/run-$(date +%Y%m%d-%H%M%S)"
```

For an encrypted volume, replace `PRIVATE_VOLUME` with its visible volume name:

```text
OUTPUT="/Volumes/PRIVATE_VOLUME/TVTime-Private/run-$(date +%Y%m%d-%H%M%S)"
df -h "/Volumes/PRIVATE_VOLUME"
```

Do not pre-create `TVTime-Extraction`; the program creates it and refuses to overwrite one.

## 5. Download and install

Follow [Download the release package or source](../README.md#1-download-the-release-package-or-source).
The release wheel is the shortest route and needs neither Git nor Apple Command Line Tools. From the
folder containing the downloaded wheel, run:

```text
python3 -m venv .venv
./.venv/bin/python -m pip install --only-binary=:all: ./tvtime_backup_extractor-0.1.0-py3-none-any.whl
./.venv/bin/python -m tvtime_extractor --version
./.venv/bin/python -m tvtime_extractor recover --help
```

Alternatively, the source ZIP route also works without Git or Apple Command Line Tools. If using
Git, first verify `git --version`; GitHub CLI users should also verify `gh auth status`.

From the project folder, create the environment and install the pinned dependencies:

```text
test -f pyproject.toml && echo "Project folder confirmed"
python3 -m venv .venv
./.venv/bin/python -m pip install --only-binary=:all: --requirement requirements.txt
./.venv/bin/python -m pip install --no-deps .
./.venv/bin/python -m tvtime_extractor --version
./.venv/bin/python -m tvtime_extractor recover --help
```

No shell activation is required. If the project is moved to another folder or Mac, recreate
`.venv` there instead of copying it.

## 6. Understand the extraction boundary

The tool opens the backup read-only and temporarily decrypts its `Manifest.db` inside the private
output. It requires `AppDomain-com.tozelabs.tvshowtime`, discovers any other matching TV Time
domain belonging directly to the app's plugins, and copies every regular file recorded in those
domains while preserving each manifest relative path below:

```text
TVTime-Extraction/raw/APP_DOMAIN/RELATIVE_PATH
```

The source file IDs, counts, declared sizes, actual sizes, and SHA-256 hashes are recorded privately
in `metadata/inventory.csv`. The primary analysis reads the copied `Documents/DioCache.db`; the
copied image-cache database is catalogued when available. Nothing is written to the phone or source
backup, and no TV Time or Apple network service is contacted.

## 7. Run the recovery

Keep `BACKUP` and `OUTPUT` from the earlier steps, then run:

```text
./.venv/bin/python -m tvtime_extractor recover \
  --backup "$BACKUP" \
  --output "$OUTPUT" \
  --acknowledge-sensitive-output
```

Enter the backup password at the hidden prompt. Do not include it in the command, shell history, a
text file, environment variable, or bug report.

If macOS reports **Operation not permitted** while reading the backup, stop and follow
[Full Disk Access](troubleshooting.md#macos-reports-operation-not-permitted). Do not copy the backup
into the repository as a workaround.

## 8. Confirm and retain safely

A successful run exits with code 0 and prints a readable summary. **Copy failures** should be `0`,
and **Files copied** should show the same copied and expected count. A nonzero **Size warnings** count
is retained in the private metadata and followed by SQLite integrity checks; validate the report
before relying on the result. Confirm that the report exists without printing its private content:

```text
test -f "$OUTPUT/TVTime-Extraction/analysis/TVTime-Recovered-Data.md" \
  && echo "Recovery report confirmed"
open "$OUTPUT/TVTime-Extraction/analysis/TVTime-Recovered-Data.md"
```

Validate the recovered titles, favorites, and watch events. A local app cache may be incomplete, so
keep the original encrypted backup until the report and tables have been checked.

For any retry, set a new `OUTPUT` value and run the full command again:

```text
OUTPUT="$HOME/TVTime-Private/run-$(date +%Y%m%d-%H%M%S)-retry"
```

Do not delete, empty, merge, or overwrite a partial run before diagnosing it privately. See
[privacy](privacy.md) before copying or eventually deleting any output.
