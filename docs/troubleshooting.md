# Troubleshooting

## `Manifest.plist was not found`

`--backup` must point to the individual long-named backup folder, not its parent `Backup` directory.
Confirm both required files without printing private contents:

```text
test -f "$BACKUP/Manifest.plist" && test -f "$BACKUP/Manifest.db" \
  && echo "Backup folder confirmed"
```

On macOS, Finder's **Manage Backups → Show in Finder** is the safest way to identify that folder.
Do not move it into the project.

## The Finder backup may not have completed

Reconnect the device and select it in Finder. A completed run has all of these signals:

- Finder no longer says **Backing up** and no backup progress indicator remains;
- **Latest Backup to this Mac** shows the expected current date and time; and
- **Manage Backups** lists that newly dated backup with the encrypted-backup lock indicator.

Only then eject the device in Finder, wait for it to disappear from the sidebar, and disconnect it.
The phone display does not need to remain permanently on, but keep the cable connected and respond
to any unlock prompt while the backup is running.

## The backup password fails

Use the password chosen when **Encrypt local backup** was enabled. It may differ from the device
passcode, Apple Account password, Mac login, or output-volume password. The project cannot recover
it. Confirm the same password works when managing or restoring the backup with Apple software.

## TV Time app domain is missing

The extractor searches the decrypted backup index for TV Time domains and specifically requires:

```text
AppDomain-com.tozelabs.tvshowtime
```

The selected backup may predate TV Time installation, be incomplete, belong to another device, or
use an unsupported app version. Open TV Time on the device, allow its local data to settle, and make
a new completed encrypted backup. Do not edit the manifest or copy a similarly named domain by
hand.

When the domain is present, the extractor copies every regular file recorded for its matching TV
Time app domains—not the entire device backup—and preserves each domain and relative path under
`TVTime-Extraction/raw/`. Analysis then looks for the copied `Documents/DioCache.db`.

## `DioCache.db` is missing

Extraction found the app container but not the cache schema expected by version 0.1.0. Preserve the
private extraction and report only a redacted description of the error. A newer TV Time release may
have changed its storage format, or the local cache may not contain the expected database.

## macOS reports `Operation not permitted`

macOS privacy controls can prevent Terminal from reading
`$HOME/Library/Application Support/MobileSync/Backup` even when the files exist.

1. Open **System Settings → Privacy & Security → Full Disk Access**.
2. Enable the trusted terminal application that will run the command, such as Terminal or iTerm.
   If it is not listed, add that application from `/System/Applications/Utilities` or
   `/Applications`.
3. Quit that terminal application completely, reopen it, return to the project folder, and retry
   using a **new** output path.

Grant access only to the application actually hosting the shell. Do not grant it to downloaded
scripts or move the backup into a Git repository. You may disable the permission again after
recovery if you no longer need terminal access to protected files.

## The destination is refused

The tool refuses destinations that overlap the source backup, sit inside a Git repository, use a
symbolic link as the final destination, or already exist. Choose a new folder on encrypted storage.
This protection prevents accidental overwrite or publication.

Do not delete an earlier run merely to reuse its name. Create another unique run instead:

```text
OUTPUT="$HOME/TVTime-Private/run-$(date +%Y%m%d-%H%M%S)-retry"
```

On another platform, choose an equivalently new private path.

## The disk fills or there may not be enough space

The extractor does not make another full copy of the iPhone backup. Its peak destination use
includes a temporary decrypted `Manifest.db`, the TV Time app-domain files, and analysis output.
`--include-decrypted-manifest` retains one additional manifest-sized file.

On macOS, inspect rather than modify the source and destination:

```text
ls -lh "$BACKUP/Manifest.db"
df -h "$HOME"
```

For an external destination, run `df -h "/Volumes/PRIVATE_VOLUME"` after replacing the volume name.
As a conservative starting allowance, leave twice the source `Manifest.db`, twice the reported TV
Time data, plus 1 GB free; if sizes are unknown, leave several GB. After a disk-full failure, retain
the partial run privately, free space without touching the backup, set a fresh `OUTPUT`, and retry.

## Extraction finished with failures

Exit code 3 means at least one app-container file failed. Analysis does not start automatically.
Review the private `metadata/summary.json` locally. Do not attach it to an issue. Ensure the backup is
complete, readable, and unchanged, then retry the full recovery into a different destination.

Every started extraction also contains private `metadata/run_state.json`. It changes to `complete`
only after the source manifest remained stable and the extraction summary was written. A wrong
password, interruption, disk error, or changing source leaves it as `incomplete`; analysis refuses
that marked run. Preserve it for diagnosis and use a new output path for the retry.

## The readable summary reports size warnings

The decryption dependency can report an actual file length that differs from the length recorded in
the backup metadata. The extractor records every mismatch privately, suppresses dependency messages
that would reveal absolute paths, and continues only when each selected file was copied. The analyzer
then requires `DioCache.db` to pass SQLite `quick_check` before producing a normal report.

Keep the backup and output. Validate the recovered title counts and readable report, and inspect the
private `metadata/summary.json` locally if needed. Do not paste paths or discrepancy records into an
issue. A size warning is not silently discarded, but it is not automatically a failed recovery when
the recovered database passes integrity checks.

## Installation fails

Supported and tested versions are Python 3.10 through 3.13; Python 3.13 is recommended for a new
installation. On macOS, use the free official installer from
[python.org/downloads/macos](https://www.python.org/downloads/macos/)—Homebrew is not required—and
verify it:

```text
python3 --version
command -v python3
```

From the project folder, create a new environment rather than reusing or deleting one from another
path or Mac:

```text
python3 -m venv .venv-retry
./.venv-retry/bin/python -m pip install --only-binary=:all: --requirement requirements.txt
./.venv-retry/bin/python -m pip install --no-deps .
./.venv-retry/bin/python -m tvtime_extractor --version
```

Use the repository's pinned `requirements.txt`. If a binary wheel is unavailable for an unusual
Python/platform combination, use Python 3.13 rather than removing pins. Continue to call
`.venv-retry/bin/python` for that attempt; do not mix interpreters from the two environments.

## The repository will not download

For **Download ZIP**, open the public repository page and choose **Code → Download ZIP**. For GitHub
CLI, confirm both authentication and the required Git executable before cloning:

```text
gh auth status
git --version
```

Then run `gh repo clone amirbrooks/tvtime-backup-extractor`. A fresh Mac without Git can use
**Code → Download ZIP** instead; this project does not require Git at runtime. Never put a personal
access token in a clone URL or support report. Private forks additionally require the signed-in
account to have access.

## The installed command is not found

Activation is optional. Run the project environment's interpreter directly.

macOS or Linux:

```text
./.venv/bin/python -m tvtime_extractor --help
```

Windows PowerShell:

```text
.venv\Scripts\python.exe -m tvtime_extractor --help
```

## Rerunning analysis

`analyze` requires a fresh extraction without an `analysis` directory. To preserve provenance, the
tool does not merge or overwrite results. Make a new full recovery run rather than manually mixing
old and new files.

## Getting safe help

Read [SUPPORT.md](../SUPPORT.md). Share only platform, Python version, tool version, subcommand, exit
code, and a paraphrased/redacted message. Never share the backup, output, reports, databases,
cookies, passwords, IDs, hashes, private paths, or screenshots of viewing history.
