# TV Time Backup Extractor

Recover your TV Time library and watch history from an encrypted local iPhone or iPad backup.
The tool copies the TV Time app container into a private folder, builds useful CSV tables, and
creates a readable report. It does not modify the phone or source backup.

> **Alpha release:** version 0.1.0 is a preview. Use it only on a backup you own or are
> authorized to access. Keep every generated file private and retain the original backup.

This project is independent and is not affiliated with or endorsed by TV Time. TV Time and related
marks belong to their respective owners. You are responsible for complying with applicable law and
service terms.

## What you need

- An **encrypted and completed** local iOS/iPadOS backup made with Finder, Apple Devices, or iTunes
- The backup password
- Python 3.10, 3.11, 3.12, or 3.13; Python 3.13 is recommended for a new installation
- A separate, encrypted destination that is **not inside this or any Git repository**
- Free space for a temporary decrypted `Manifest.db`, the TV Time app data, and the analysis—not a
  second copy of the entire device backup

Android data, cloud-account extraction, unencrypted backups, and restoring data to TV Time are not
supported. See the platform guides for [macOS](docs/macos.md),
[Windows](docs/windows.md), and [Linux](docs/linux.md).

## Quick start

### 1. Download the release package or source

Choose one of these routes.

**Installable wheel (recommended; no Git or source checkout required):** download
`tvtime_backup_extractor-0.1.0-py3-none-any.whl` from the
[v0.1.0 release](https://github.com/amirbrooks/tvtime-backup-extractor/releases/tag/v0.1.0).
Keep it in a new local folder. The release also provides `SHA256SUMS` so the download can be checked
before installation. On macOS or Linux, run:

```text
shasum -a 256 tvtime_backup_extractor-0.1.0-py3-none-any.whl
```

On Windows PowerShell, run:

```text
Get-FileHash .\tvtime_backup_extractor-0.1.0-py3-none-any.whl -Algorithm SHA256
```

Confirm that the displayed value matches the wheel's line in `SHA256SUMS` from the release.

**Download ZIP (simplest on a fresh Mac; no Git or GitHub CLI required):** open the repository page,
then choose **Code → Download ZIP**. Extract the ZIP. In Terminal, type `cd ` (including the space),
drag the extracted project folder into the Terminal window, and press Return. Safari may have
extracted the ZIP automatically.

**Git:** use this only if `git --version` succeeds:

```text
git --version
git clone https://github.com/amirbrooks/tvtime-backup-extractor.git
cd tvtime-backup-extractor
```

If `git --version` on a fresh Mac requests Apple Command Line Tools, either install those free tools
or use the ZIP route. GitHub CLI users may equivalently run
`gh repo clone amirbrooks/tvtime-backup-extractor` after `gh auth status`; do not paste a GitHub token
into a clone URL.

For a source download, confirm that Terminal is in the project folder:

```text
test -f pyproject.toml && echo "Project folder confirmed"
```

On Windows PowerShell, use `Test-Path pyproject.toml` for the same check.

### 2. Create a private Python environment

Supported and tested Python versions are 3.10 through 3.13. Python 3.13 is the recommended fresh
installation. On macOS, Python's free official installer is available from
[python.org/downloads/macos](https://www.python.org/downloads/macos/); Homebrew is not required.
Verify the interpreter before creating the environment:

```text
python3 --version
command -v python3
```

Then install into a local virtual environment. These commands deliberately call the environment's
interpreter directly, so they do not depend on shell activation.

For the downloaded release wheel on macOS or Linux, change into the folder containing the wheel and
run:

```text
python3 -m venv .venv
./.venv/bin/python -m pip install --only-binary=:all: ./tvtime_backup_extractor-0.1.0-py3-none-any.whl
./.venv/bin/python -m tvtime_extractor --version
```

On Windows PowerShell:

```text
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install --only-binary=:all: .\tvtime_backup_extractor-0.1.0-py3-none-any.whl
.venv\Scripts\python.exe -m tvtime_extractor --version
```

For a source ZIP or Git checkout, use the following commands from the project folder.

macOS or Linux:

```text
python3 -m venv .venv
./.venv/bin/python -m pip install --only-binary=:all: --requirement requirements.txt
./.venv/bin/python -m pip install --no-deps .
./.venv/bin/python -m tvtime_extractor --version
```

Windows PowerShell:

```text
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install --only-binary=:all: --requirement requirements.txt
.venv\Scripts\python.exe -m pip install --no-deps .
.venv\Scripts\python.exe -m tvtime_extractor --version
```

The dependency versions are pinned. Do not use an unreviewed replacement requirements file. Virtual
environments are not portable between paths or computers; if the project moves, create a newly
named environment there instead of copying or repairing the old one.

### 3. Locate the backup and choose an output folder

Use the platform guide linked above. The individual backup folder contains `Manifest.plist` and
`Manifest.db`. Choose a new output folder on FileVault-, BitLocker-, LUKS-, or separately encrypted
storage. Do not choose the project folder, the source backup, a synced/shared folder, or a
destination from an earlier run.

The [macOS guide](docs/macos.md) explains how to verify that Finder has completed the backup, safely
eject the device, find the backup under `$HOME`, check free space, and grant Full Disk Access only if
macOS blocks the terminal.

### 4. Recover the data

Replace the two example paths with your own. On macOS or Linux, run:

```text
./.venv/bin/python -m tvtime_extractor recover \
  --backup "/path/to/BACKUP_FOLDER" \
  --output "/path/to/NEW_PRIVATE_OUTPUT" \
  --acknowledge-sensitive-output
```

PowerShell uses a backtick for line continuation, or you can put the command on one line:

```text
.venv\Scripts\python.exe -m tvtime_extractor recover --backup "C:\path\to\BACKUP_FOLDER" --output "D:\Private\NEW_OUTPUT" --acknowledge-sensitive-output
```

The password prompt is hidden. The program does not intentionally save the password, although
Python cannot guarantee that a string is erased from memory immediately. On success, open:

```text
NEW_PRIVATE_OUTPUT/TVTime-Extraction/analysis/TVTime-Recovered-Data.md
```

The report is readable, but it is still private viewing-history data. Do not post it to GitHub or
attach it to a support request. A retry must use another new output path; preserve the failed output
privately until the error has been understood.

The default terminal result is a short readable summary. It reports title counts and points to the
Markdown report, which lists every identifiable recovered title/name. For private local automation,
add `--json` to the subcommand to request a machine-readable summary; JSON is not the default.

## What the extractor copies

The extractor opens the completed backup read-only, temporarily decrypts its file index inside the
private output, and requires the TV Time app domain
`AppDomain-com.tozelabs.tvshowtime`. It then decrypts every regular file recorded for that primary
domain and its directly related TV Time plugin domains, preserving each domain and relative path
under `TVTime-Extraction/raw/`. It records file counts, sizes, and hashes before analyzing the copied
`Documents/DioCache.db`; an available image-cache database is catalogued as a bonus.

It does **not** copy the entire iPhone backup, contact TV Time, alter the phone, restore data to the
app, or claim to be a complete cloud-account export. Local caches can be incomplete and app formats
can change. The source backup should remain untouched until the recovered titles, favorites, and
watch events have been validated.

## Commands

- `recover`: extract, analyze, and create the report in one guided run
- `extract`: decrypt the TV Time app container only
- `analyze`: create normalized private tables from an existing extraction
- `report`: rebuild the readable report from an existing analysis

Run `./.venv/bin/python -m tvtime_extractor <command> --help` on macOS/Linux or
`.venv\Scripts\python.exe -m tvtime_extractor <command> --help` on Windows for exact options.
Advanced switches `--include-raw-cache` and `--include-decrypted-manifest` retain substantially more
account or device data and are off by default. `--json` changes only the terminal summary format.

## Read before using real data

- [Privacy and safe handling](docs/privacy.md)
- [Output reference](docs/output-reference.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Support policy](SUPPORT.md)
- [Security policy](SECURITY.md)

Automated tests use invented fixtures only. The repository must never contain real backups,
cookies, databases, device manifests, account profiles, recovered reports, stable account IDs, or
viewing histories.

## Status and license

The format used by TV Time can change, so a future app version may require parser updates. Keep the
source backup and validate results before relying on them. This software is provided without
warranty and is not a backup-restoration tool.

Licensed under the [MIT License](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CHANGELOG.md](CHANGELOG.md).
