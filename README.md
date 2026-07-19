# TV Time Backup Extractor

Recover readable TV Time titles, favorites, cached episodes, watch events, and media references
from an authorized encrypted local iPhone or iPad backup. The extractor reads the completed backup,
copies only matching TV Time app-domain files into a fresh private destination, and produces
human-readable reports plus detailed CSV tables.

The project is free and open source. iMazing is not required. It does not modify the phone or source
backup, contact TV Time, restore data to the app, or provide an official cloud-account export.

> **Release status:** the source is at the v0.2.0 development baseline. The macOS application has
> been built and validated locally with an ad-hoc signature, but there is not yet a downloadable,
> Developer ID-signed, notarized v0.2.0 public artifact. Do not redistribute the local development
> app as though it were a release. The currently published v0.1.0 prerelease is CLI-only: its
> complete Markdown catalogue contains the actual recovered series, movie, favorite, episode, and
> identifiable watch-event names rather than counts alone. The v0.2.0 source adds the shared offline
> HTML/PDF views and native macOS result experience. For safety, use v0.1.0 only with Python 3.10
> through 3.13, and do not use its fresh `extract` or `recover` commands on Windows; use Windows only
> for `analyze` or `report` on an already completed extraction.

This project is independent and is not affiliated with or endorsed by TV Time or Apple. TV Time and
related marks belong to their respective owners. Use it only with data you own or are authorized to
access, and comply with applicable law and service terms.

## Choose a route

| Route | Best for | Requirements |
| --- | --- | --- |
| Native macOS app | Most Mac users | macOS 14 or later and, once published, the DMG matching the Mac's architecture |
| Python CLI recovery | macOS, Linux, automation, and development | An explicitly selected Python 3.10 through 3.13 plus the pinned dependencies |
| Windows existing-extraction tools | Windows review of an already complete extraction | Python 3.10 through 3.13; fresh `extract` and `recover` fail closed |

When signed and notarized DMGs are published, the native app will be the normal Mac installation:

- Apple silicon Macs use the `Apple-Silicon-arm64` DMG;
- Intel Macs use the `Intel-x86_64` DMG; and
- end users need no Python, iMazing, Homebrew, Git, GitHub CLI, or Apple developer tools.

Until those artifacts exist, use the source-based CLI or build the app locally for development. See
the [macOS guide](docs/macos.md) for the distinction and the
[v0.2.0 release-preparation record](docs/release-v0.2.0.md) for the remaining distribution gates.

## What every recovery needs

- A **completed and encrypted** local iOS or iPadOS backup made with Finder, Apple Devices, or
  iTunes
- The encryption password for that backup
- The phone safely ejected and disconnected after backup completion is confirmed
- Enough free local space for manifest processing, the selected TV Time app data, and reports—not another
  copy of the whole device backup

Android data, unencrypted or unfinished backups, cloud-account extraction, and restoring recovered
data to TV Time are not supported.

## Native macOS app workflow

The app supports macOS 14 or later. Once a signed and notarized DMG is published:

1. Download the DMG for **Apple silicon** or **Intel** from the project's release page and verify
   its published checksum.
2. Open the DMG, drag **TV Time Backup Extractor** to **Applications**, eject the DMG, and open the
   app from Applications.
3. Choose the Apple backup folder. If it contains one completed backup, the app selects it
   automatically. If several backups appear, open the intended one before choosing it.
4. The app creates a fresh recovery folder in private app-managed local storage. There is no
   destination picker, mounted disk-image requirement, or hard-coded user path.
5. Review the read-only preflight: encryption state, finished snapshot state, backup date and size,
   manifest size, local free space, and minimum working space.
6. Enter the backup password in the secure field and acknowledge that recovered reports are
   readable plaintext on this Mac. FileVault remains recommended for whole-disk protection.
7. Start recovery and keep the Mac awake until the result screen appears.
8. Validate the aggregate chart and counts, then open the private visual, PDF, or Markdown report,
   or reveal the app-managed recovery folder in Finder.

Use **Show Previous Recoveries** on the first screen to find older completed or incomplete runs.
Review them before deleting anything; the app never silently removes recovery output.

The password is passed only to the bundled local helper and is not intentionally written to disk.
The app clears its field after starting, but neither Swift nor Python can guarantee immediate erasure
of every in-memory copy.

Cancelling the backup check creates no recovery output. Cancelling an active recovery, closing its
window, or quitting the app requires confirmation. A confirmed cancellation preserves incomplete
output for diagnosis; it never reuses or silently deletes that output. Every retry gets a fresh
destination.

The completed native result screen provides:

- a verified-package panel confirming selected source stability, completion-marker consistency,
  copied-file integrity, and sealed report artifacts;
- an aggregate bar chart and explicit watched/saved movie and named/unnamed event counts;
- copied-file and byte-count-difference summaries;
- aggregate image, trailer, and media-URL reference counts;
- a visual report, print-friendly PDF, and complete Markdown catalogue, with a clear explanation
  when the optional PDF is omitted; and
- guarded actions to open reports or reveal the analysis directory.

Opening a report uses the default browser or document viewer. Its private filename may then appear
in that application's history or macOS Recent Items. See [Privacy and safe handling](docs/privacy.md).

## Reports and tables

A successful full recovery creates these primary reports under
`TVTime-Extraction/analysis/`:

- `TVTime-Recovered-Data.md`: canonical readable text listing every recovered record and each available name
- `TVTime-Recovered-Data.html`: accessible, self-contained primary visual report with charts and
  semantic tables; it works offline, contains no script, and does not request remote media
- `TVTime-Recovered-Data.pdf`: optional print-friendly companion generated from the same report
  model; use the HTML report for tagged semantic structure with assistive technology

Markdown, HTML, and PDF are rendered from one shared safe display model, including identical
missing-title placeholders and a copy-size-differences section when backup metadata and copied byte
counts disagree. Detailed CSV tables remain the exact archive; the readable formats replace control
characters with spaces, trim surrounding whitespace, and collapse whitespace runs while preserving
the remaining recovered Unicode text.

The PDF is deliberately omitted when the available embedded font or shaping support cannot
faithfully render every recovered character. This is a fidelity safeguard, not a failed recovery:
the Markdown and offline HTML remain complete. Normalized CSV tables preserve the detailed private
data used by the reports, including titles, favorites, episodes, and exact watch events.

Successful full recovery has two versioned machine-readable checkpoints:

- `metadata/run_state.json` has `status` set to `complete` after selected-file extraction finishes
  and the source is revalidated; and
- `analysis/recovery_state.json` has `status` set to `complete` in the atomically promoted report
  directory and binds the exact report/table artifact set, aggregate counts, byte sizes, and SHA-256
  digests.

Do not treat an output as a completed full recovery if either expected marker is absent or not
complete. Standalone `extract` intentionally creates only the extraction marker. Never edit a marker
or merge files from separate runs. See the complete [output reference](docs/output-reference.md).

## Free-space model

The extractor does not duplicate the complete iPhone or iPad backup.

The initial manifest-processing preflight checks for at least the larger of:

- 512 MiB; or
- twice the source `Manifest.db` size.

This initial floor is enough to begin safe manifest processing; it is not the full recovery-space
requirement. After the encrypted manifest identifies the TV Time domains, recovery requires the sum
of the selected files' declared sizes, the largest selected encrypted source payload as a staging
snapshot, headroom equal to the larger of 64 MiB or 10% of selected declared bytes, and one retained
`Manifest.db` only when the advanced decrypted-manifest option is enabled. The post-retention check
omits that already-retained manifest allowance but still includes the largest staging snapshot.

The full backup size shown in preflight is useful provenance; it is not the required destination
size. Keep extra headroom for filesystem allocation and future retries, and do not unmount the
destination while recovery is active.

## Python CLI fallback

The CLI is free and supports full recovery with Python 3.10, 3.11, 3.12, or 3.13 on macOS and
Linux. Windows can install the CLI and safely run standalone `analyze` or `report` against an
already complete extraction, but this release deliberately refuses fresh `extract` and `recover`:
Python cannot atomically create and lock the new Windows plaintext root. The CLI remains the
supported macOS route while no notarized DMG is published.

### Install from a source checkout or ZIP

Download the repository as a source ZIP, or clone it if Git is already available. Git is optional.
From the project directory on macOS or Linux:

```text
python3.13 -m venv .venv
./.venv/bin/python -m pip install --require-hashes --only-binary=:all: --requirement requirements.lock
./.venv/bin/python -m pip install --require-hashes --only-binary=:all: --requirement requirements-source-build.lock
./.venv/bin/python -m pip install --no-index --no-build-isolation --no-deps .
./.venv/bin/python -m pip check
./.venv/bin/python -m tvtime_extractor --version
```

On Windows PowerShell:

```text
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: --requirement requirements.lock
.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: --requirement requirements-source-build.lock
.venv\Scripts\python.exe -m pip install --no-index --no-build-isolation --no-deps .
.venv\Scripts\python.exe -m pip check
.venv\Scripts\python.exe -m tvtime_extractor --version
```

The dependency versions and downloadable artifacts are pinned. `requirements.lock` contains hashes
for supported macOS, Windows, and Linux wheels; installation rejects an unlisted artifact and never
builds a dependency from source. The minimal source-build backend is separately hash-locked, and
the final local-project install disables build isolation and the package index so it cannot fetch an
undeclared build tool. Virtual environments are not portable between folders or computers; create a
new one if the project moves.

### Run a full recovery

Use an individual backup folder and a destination run path that does not yet exist. The immediate
encrypted output parent must already exist; the fresh run child itself must not exist. This
parent-exists/child-does-not rule also applies when selecting paths on Windows, although Windows
fresh recovery is refused in this release. On macOS or Linux:

```text
./.venv/bin/python -m tvtime_extractor recover \
  --backup "/path/to/DEVICE_BACKUP" \
  --output "/path/to/PRIVATE_NEW_RUN" \
  --acknowledge-sensitive-output
```

The CLI completes and visibly summarizes the full read-only backup/destination preflight before the
hidden password prompt appears. It consumes the same source-identity receipt after the prompt, then
holds the selected parent and fresh output-root directory identities through recovery. A replaced
backup root, changed bound critical metadata, or changed displayed source aggregate fails before
output creation; selected payload files are snapshot-verified during extraction and revalidated
before extraction completion. POSIX descendants remain relative to the descriptor-rooted working
directory. Standalone `analyze` and `report` hold and revalidate the exact existing extraction root;
on Windows they use a non-delete-sharing handle and reject reparse points. Do not place the password
in the command,
environment, shell history, or a support request. The default terminal output is a concise readable
summary; `--json` is an explicit private automation option and is not the default.

On Windows, move or copy the intact encrypted backup to a private macOS/Linux system for extraction,
or bring an already complete private extraction to Windows and use only `analyze`/`report`; see the
[Windows guide](docs/windows.md).

Linux accepts only a conservative set of ordinary local filesystem types. FUSE, network, shared,
virtual-machine shared-folder, temporary, overlay, and unknown filesystem types are refused with no
override.

The CLI commands are:

- `recover`: preflight, extract, analyze, and report in one workflow
- `extract`: copy and inventory matching TV Time app-domain files only
- `analyze`: build normalized private tables from one complete extraction
- `report`: build readable and visual reports from one complete analysis

Run `python -m tvtime_extractor <command> --help` through the virtual environment for exact options.
`--debug` deliberately retains chained third-party exceptions and can expose backup paths,
dependency details, recovered names, or password text. Use it only in a private local terminal and
never paste or share its traceback.
The advanced `extract --include-decrypted-manifest` and `analyze --include-raw-cache` switches
retain substantially more account or device data and are off by default. They are deliberately not
available on the sealed `recover` workflow: preserve those advanced outputs for private manual
analysis, and use a fresh default recovery when native completion validation is required.

## Extraction boundary and limitations

The extractor opens the completed backup read-only and temporarily decrypts its file index inside
the private output. It requires the primary TV Time domain
`AppDomain-com.tozelabs.tvshowtime` and includes directly related TV Time plugin domains. Every
selected regular file is copied below `TVTime-Extraction/raw/` with its domain and manifest-relative
path preserved. File counts, sizes, and hashes are recorded privately before analysis.

The primary parser reads the copied `Documents/DioCache.db`; an available image-cache database is
catalogued as a bonus. Local caches can be incomplete, events can survive without names, and TV Time
can change its schema. Missing data is stated rather than guessed. Retain the original encrypted
backup until titles, favorites, episodes, watch events, and completion markers have been validated.

## Read before using real data

- [macOS guide](docs/macos.md)
- [Windows guide](docs/windows.md)
- [Linux guide](docs/linux.md)
- [Privacy and safe handling](docs/privacy.md)
- [Output reference](docs/output-reference.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Support policy](SUPPORT.md)
- [Security policy](SECURITY.md)

Automated tests use invented fixtures only. The repository must never contain a real backup,
database, device manifest, recovered report, stable account or device identifier, private URL,
password, or viewing history.

## License

Licensed under the [MIT License](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CHANGELOG.md](CHANGELOG.md). The software is provided without warranty and is not a
backup-restoration tool. A packaged macOS app also carries its complete third-party texts and an
exact component/license inventory under `Contents/Resources/Licenses`.
