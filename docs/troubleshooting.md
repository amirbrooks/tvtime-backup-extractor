# Troubleshooting

Keep the source backup and every recovery output private while troubleshooting. Use a fresh
destination for each retry; never delete, empty, merge, rename, or edit an earlier run merely to make
the tool accept the same path.

## There is no downloadable v0.2.0 macOS app

That is the expected repository state until release packaging is completed. The native app has been
validated as a local ad-hoc development build, but no Developer ID-signed and notarized v0.2.0 DMG
has been published.

Do not download an unsigned copy from an issue or unofficial mirror, and do not disable Gatekeeper.
Use the [Python CLI fallback](../README.md#python-cli-fallback) or follow the contributor-only local
build instructions in [CONTRIBUTING.md](../CONTRIBUTING.md).

## The published macOS app will not open

First confirm that an official release actually exists and that the downloaded DMG matches the Mac:
`Apple-Silicon-arm64` for Apple silicon or `Intel-x86_64` for Intel. Verify its SHA-256 checksum
against the release's `SHA256SUMS`, install the app in Applications, and open that installed copy.

A legitimate published package must be Developer ID signed, notarized, stapled, and accepted by
Gatekeeper. If those conditions are not met, stop. Do not use “Open Anyway” as a workaround for an
unofficial or ad-hoc build.

## The app says the backup folder is invalid

Select the individual device-backup folder, not the parent folder named `Backup`. The selected folder
must directly contain regular files named:

```text
Manifest.plist
Manifest.db
```

In Finder, use the device page's **Manage Backups → Show in Finder** action to identify the intended
backup. Do not move it into the repository or select a copied subset.

For CLI use, verify only the file presence without printing private content:

```text
test -f "$BACKUP/Manifest.plist" && test -f "$BACKUP/Manifest.db" \
  && echo "Backup folder confirmed"
```

## Inspect privacy-safe native diagnostics locally

The macOS app records only fixed operation, milestone, and allow-listed failure codes in Apple's
local unified log. It does not log paths, backup identifiers, filenames, titles, recovered counts,
passwords, or free-form error text, and it does not transmit telemetry.

For a contributor-built local app, run the repository's normal packaged build with its narrow
telemetry filter:

```text
./script/build_and_run.sh --telemetry
```

Then reproduce the user-interface action and look for category `RecoveryDiagnostics`. A normal run
has bounded events such as `picker_presented`, `preflight started`, and `validation completed`. A
failure contains an allow-listed `reason`; an unknown local error is only
`unrecognized_failure`.

Do not broaden the predicate, export a `.logarchive`, or attach terminal output to an issue. Other
system logs can contain private data. Share only the app's displayed reference code and a manually
paraphrased stage unless a maintainer provides a synthetic reproduction procedure.

## The backup is not marked finished

Reconnect the device and select it in Finder or Apple Devices. A completed run has all of these
signals:

- the application no longer says **Backing up** and no progress indicator remains;
- the latest local-backup date and time have updated; and
- backup management lists that new backup with the encrypted-backup lock indicator.

Only then eject the device, wait for it to disappear, and disconnect it. The phone display does not
need to remain permanently on, but keep the cable connected and respond to unlock prompts while the
backup is being made.

The extractor also requires `Status.plist` to report a finished snapshot. It refuses an absent,
unfinished, or changing status rather than guessing.

## The backup is not confirmed as encrypted

Create another local backup with **Encrypt local backup** enabled and store its password safely. An
unencrypted backup is not accepted. Enabling FileVault on the Mac does not change whether Finder's
device backup itself is marked encrypted.

## The backup password fails

Use the password chosen when **Encrypt local backup** was enabled. It can differ from the device
passcode, Apple Account password, and Mac login.

The extractor cannot recover or reset it. Confirm the password using trusted Apple software. Do not
paste it into a support request, command, environment variable, shell history, or screenshot.

## Private output storage is refused

The extractor refuses a destination that:

- already exists;
- overlaps the source backup;
- is inside a Git repository;
- is or traverses an unsafe symbolic link or reparse point; or
- is on a nonlocal volume, is an ubiquitous item, is under a known cloud/File Provider or shared
  root, or uses FUSE, an unknown filesystem, or an ambiguous stacked Linux mount; or
- does not have a safe existing immediate parent (required by every CLI recovery backend).

The native macOS app prepares a new owner-only child in its private local container automatically;
start over so it can recheck that location. The CLI still requires a new child path on private
encrypted storage. Do not choose a cloud-synced or shared CLI destination.

On Linux, FUSE, network, shared-folder, overlay, temporary, unknown, and ambiguous stacked mounts
are refused with no override. Use a directly mounted, locally encrypted filesystem supported by the
[Linux guide](linux.md#destination-filesystem-checks). Do not share `mountinfo` or mount-command
output; it can contain private paths.

On Windows, recovery additionally requires Windows 11 x64, 64-bit Python, local NTFS with persistent
ACLs, and a non-reparse destination outside UNC, network, cloud-sync, and WSL paths. ReFS, FAT, and
exFAT are refused. Use BitLocker or equivalent private storage; the CLI cannot certify BitLocker
state automatically. See the [Windows guide](windows.md).

## The app says there is not enough free space

The extractor does not make a second copy of the complete device backup. The initial
manifest-processing preflight checks for at least the larger of 512 MiB or twice the source
`Manifest.db` size. The app displays that initial floor and the destination's free space, but the
floor is not the complete recovery-space requirement.

After reading the encrypted manifest, recovery performs another check for:

- all selected TV Time files at their declared sizes;
- one staging snapshot as large as the largest selected encrypted source payload;
- headroom equal to the larger of 64 MiB or 10% of those selected bytes; and
- one additional manifest-sized retained file only when decrypted-manifest retention is enabled.

It checks again after optional manifest retention; that second check omits the already-retained
manifest allowance but still includes the largest staging snapshot. Filesystem allocation and a
future fresh retry can need more, so leave additional room. Free space on another volume does not
increase the Mac's app-managed recovery storage.

For CLI diagnosis on macOS or Linux, inspect rather than modify:

```text
ls -lh "$BACKUP/Manifest.db"
df -h "/path/to/private/destination-parent"
```

On Windows, use private local properties dialogs to inspect free space. Do not paste filesystem or
volume output into a support request because it can expose private paths and labels.

After a disk-full failure, preserve the partial run privately, free space without touching the
backup, and retry into a new output folder.

## The source changed during recovery

Use a completed, ejected, disconnected backup. The extractor snapshots the source manifest metadata
and selected encrypted payload metadata, then revalidates it before marking extraction complete. It
stops if a selected source file or finished status changes.

Do not run Finder backup creation, backup cleanup, migration, or synchronization against the same
backup while extracting. Preserve the incomplete output, let Apple software settle, confirm the
backup is still finished, disconnect the phone, and retry into a fresh output folder.

## Cancelling, closing, or quitting behaves unexpectedly

Cancelling preflight creates no recovery output. During active recovery, Cancel, window close, and
quit require confirmation; **Continue Recovery** is the safe default. Confirmed cancellation can take
time because the helper stops at cooperative safety checkpoints.

Incomplete output is preserved and cannot be resumed or reused. If recovery naturally completes
while a close or quit confirmation is visible, the successful result remains active; completion does
not become a cancellation.

## Extraction stopped or finished with copy failures

Analysis does not proceed when a selected file could not be copied. The private
`metadata/summary.json` records the failure inventory. Each row has a fixed content-free `category`
such as `missing_encryption_key`, `key_unwrap_failure`, `ciphertext_invalid`, or `padding_failure`.
Categories identify the processing stage without recording the underlying exception, but the rest
of each row remains private. Do not attach, quote, upload, or paste the inventory in an issue.

Every started extraction has `metadata/run_state.json`, initially marked `incomplete`. It becomes
`complete` only after source revalidation and safe extraction cleanup. A wrong password,
interruption, disk error, source change, or copy failure leaves the run incomplete.

Preserve the output for private diagnosis and retry the full recovery into a new destination. Never
edit `run_state.json` to bypass analysis validation.

## The full recovery has no complete report marker

A successful full recovery also requires
`TVTime-Extraction/analysis/recovery_state.json` with `status` set to `complete`. The report builder
stages output privately and atomically promotes the whole analysis directory only after Markdown and
HTML are complete and the PDF is either generated faithfully or explicitly omitted.

If `recovery_state.json` is missing, not complete, or an `.analysis-incomplete` or
`.report-incomplete` directory remains, treat the output as incomplete. Do not merge or repair it by
hand. Retry into a new destination.

Standalone `extract` intentionally produces only `run_state.json`; it does not constitute a full
recovery report.

## Extraction reports a declared-size warning

After valid CBC decryption and strict PKCS#7 padding validation, the recovered byte count can differ
from the size declared in backup metadata. The extractor preserves the complete recovered bytes,
records the difference privately, and reports only the warning count in terminal and public JSON
output. It does not truncate or extend the file to force a match. Dependency output that could
expose absolute paths remains suppressed.

Full recovery continues through the normal schema and SQLite integrity checks. If the required
database is not structurally usable, analysis fails and the full recovery remains incomplete. Keep
all warning details and recovered files private; the discrepancy rows contain paths and exact sizes
and must not be pasted into an issue.

## The PDF was not created

This can be the intended safe result. The extractor refuses to produce a PDF if its embedded font or
available shaping support cannot faithfully render every recovered character. It records the PDF as
omitted and keeps both of these complete:

```text
TVTime-Recovered-Data.md
TVTime-Recovered-Data.html
```

Do not convert the Markdown or HTML with an online service. If a PDF is essential, use a trusted
offline viewer's print function and manually verify every name; that derivative is outside the
extractor's fidelity guarantee.

## The visual report shows no remote images

That is intentional. The HTML is self-contained, uses no JavaScript, and blocks network requests.
It visualizes aggregate counts and recovered text but does not fetch posters, trailers, or image
cache URLs. Detailed sanitized references are available in the private CSV tables.

## A report opens but appears in history or Recent Items

Opening a report hands it to the default browser, PDF viewer, Markdown viewer, or Finder. Its private
filename may appear in that application's history, macOS Recent Items, Quick Look cache, or state
restoration.

Close the report after validation and clear local history if required. Disable browser or document
sync before opening private output. Clearing history does not delete the underlying report; see the
[privacy guide](privacy.md#reports-browsers-and-recent-items).

## The TV Time app domain is missing

The extractor requires the primary backup domain:

```text
AppDomain-com.tozelabs.tvshowtime
```

The selected backup may predate TV Time installation, belong to another device, be incomplete, or
come from an unsupported app version. Do not edit the manifest or copy a similarly named domain by
hand. If possible, open TV Time on the authorized device, let its local data settle, create another
completed encrypted backup, eject the device, and retry from that new backup.

## `DioCache.db` is missing or unsupported

The current parser expects the copied primary app-domain file `Documents/DioCache.db`. A newer TV
Time version may have changed its storage format, or the local cache may not include the database or
recognized payloads.

Preserve the private extraction. Report only the version, platform, parser status, and a synthetic or
abstract description. Do not upload the database or cache.

## macOS reports `Operation not permitted`

This section applies mainly to the Python CLI. macOS privacy controls can prevent Terminal from
reading the standard MobileSync location even when the files exist.

1. Open **System Settings → Privacy & Security → Full Disk Access**.
2. Enable only the trusted terminal application that runs the command, such as Terminal or iTerm.
3. Quit that terminal completely, reopen it, return to the project directory, and retry with a new
   output path.

Grant access only to the application hosting the trusted shell. Do not grant it to downloaded
scripts and do not move the backup into a Git repository. Disable the permission later if it is no
longer needed.

The sandboxed native app instead uses a system folder picker so the user can grant read-only access
to the selected backup. Use **Manage Backups → Show in Finder** to locate the correct child folder
before choosing it. Native output stays in the app's private local container.

## CLI installation fails

Supported Python versions are 3.10 through 3.13. Use a trusted installer and the repository's exact
`requirements.lock`; do not remove pins or hashes, and do not mix interpreters.

From the project folder on macOS or Linux:

```text
python3.13 -m venv .venv-retry
./.venv-retry/bin/python -m pip install --require-hashes --only-binary=:all: --requirement requirements.lock
./.venv-retry/bin/python -m pip install --require-hashes --only-binary=:all: --requirement requirements-source-build.lock
./.venv-retry/bin/python -m pip install --no-index --no-build-isolation --no-deps .
./.venv-retry/bin/python -m pip check
./.venv-retry/bin/python -m tvtime_extractor --version
```

On Windows PowerShell, create the environment with `py -3.13 -m venv .venv-retry`, then use
`.venv-retry\Scripts\python.exe`. You may substitute an explicit 3.10, 3.11, or 3.12; do not use an
unqualified launcher that can select Python 3.14. Virtual environments are tied to their path and
computer; create a new one rather than copying or repairing an environment from elsewhere.

## The installed CLI command is not found

Shell activation is optional. Invoke the environment's interpreter directly.

macOS or Linux:

```text
./.venv/bin/python -m tvtime_extractor --help
```

Windows PowerShell:

```text
.venv\Scripts\python.exe -m tvtime_extractor --help
```

## Rerunning analysis or reports

`analyze` requires one complete extraction and refuses an existing analysis directory. `report`
requires one complete analysis and refuses existing report artifacts. These rules preserve
provenance and prevent mixed runs.

Make a new full recovery rather than manually combining or overwriting files. Advanced developers
using the separate commands must preserve the extraction completion marker.

## Getting safe help

Read [SUPPORT.md](../SUPPORT.md). Share only the application or CLI version, platform, architecture
or Python version when relevant, workflow stage, exit code, and a paraphrased synthetic message.
Never share the backup, output, reports, databases, cookies, passwords, IDs, hashes, private paths,
counts from a real recovery, or screenshots of viewing history.
