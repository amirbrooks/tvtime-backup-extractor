# macOS guide

The native app is the intended recovery experience for macOS 14 or later. It is free, includes its
recovery engine, and does not require iMazing, Python, Homebrew, Git, GitHub CLI, or developer tools
for end users.

> **Current distribution status:** [v0.2.0 is published](https://github.com/amirbrooks/tvtime-backup-extractor/releases/tag/v0.2.0)
> with Developer ID-signed, notarized, stapled DMGs for Apple silicon and Intel. The app bundle
> produced by `script/build_local_app.sh` remains ad-hoc signed for contributor use and is not a
> substitute for the official release.

Contributor app builds use exact CPython 3.13.12 plus a reviewed native-runtime license profile;
the broader Python 3.10-through-3.13 range applies to the CLI, not native app packaging. See
[CONTRIBUTING.md](../CONTRIBUTING.md#native-macos-development-setup).

## 1. Make a completed encrypted backup

1. Connect the iPhone or iPad, unlock it, and approve **Trust** if asked.
2. Open Finder and select the device in the sidebar.
3. Under **General**, select **Back up all of the data on your device to this Mac**.
4. Enable **Encrypt local backup**, choose a unique password, and save it in a password manager.
5. Select **Back Up Now**. Keep the cable connected and respond to any unlock prompt.
6. Wait until Finder no longer says **Backing up**, the progress indicator has disappeared, and
   **Latest Backup to this Mac** shows the expected new date and time.
7. Choose **Manage Backups**. Confirm the new backup appears with the encrypted-backup lock
   indicator. Use **Show in Finder** to identify it.

The phone screen does not need to remain permanently on, but the cable must remain connected and the
phone may need to be unlocked when Finder asks. Do not infer completion from backup size or a pause
in the animation.

Once all completion checks pass, eject the device in Finder. Wait for it to disappear from the
sidebar, then disconnect it. Recovery uses the local Mac backup; the phone should remain disconnected
so the source backup cannot be updated during extraction.

The backup password may differ from the phone passcode, Apple Account password, and Mac login. The
extractor cannot recover or reset it.

## 2. Identify the individual backup folder

Finder backups are normally under:

```text
~/Library/Application Support/MobileSync/Backup/
```

Each child of that folder represents a device backup. When the parent contains exactly one valid
completed backup, the app accepts the parent and selects that backup automatically. When several
backups exist, open the intended child before choosing it; **Manage Backups → Show in Finder** is the
safest way to identify the correct one. An individual backup contains regular `Manifest.plist` and
`Manifest.db` files, but ordinary users do not need to inspect those files manually.

Do not move, rename, edit, clean, or duplicate the backup as part of recovery. The app's system
folder picker normally opens at the standard backup location and lets macOS grant access to the
chosen folder.

## 3. App-managed private output

The native app creates every recovery in its own private local app container. The user does not
choose or mount an output volume. Each run receives a new `TVTime-Recovery-...` directory with
owner-only permissions, outside known cloud, shared, source-backup, and Git locations. The result
screen can reveal that directory in Finder.

The first screen's **Show Previous Recoveries** button reveals the private app-managed parent after
a relaunch or after starting over. Review old completed or incomplete runs there before deleting
anything; the app does not automatically delete recovery output.

Recovered reports are readable plaintext. The sandbox and owner-only permissions reduce accidental
access but do not provide whole-disk encryption, so FileVault remains recommended. Anyone who can
access the Mac account—or an administrator with sufficient privileges—may be able to read the
recovered files.

The app records the app-managed parent's filesystem device and inode before and after its local and
non-cloud checks. Preflight and recovery must use the same identity. For each helper launch, the app
verifies that no path component is a symbolic link, opens the exact parent, and passes only that
directory handle through the private local protocol. The helper verifies the handle against the
request and holds it for the complete operation. It creates and opens the fresh child relative to
that handle, changes its dedicated process into the held output-root identity, and keeps every
private descendant relative throughout extraction, analysis, and reporting. A substituted path
receives no recovered plaintext, and final success requires the original identities to remain
visible. The numeric identities are internal and are not written to a recovery report.

Preflight also produces an internal source receipt bound to the selected backup root, its critical
metadata files, and the source totals shown on the confirmation screen. The app keeps this receipt
only in memory and sends it to the recovery helper after password entry. Recovery rescans the source
and must match the receipt before the fresh output child is created. Selecting another backup,
retrying, cancelling, failing, or completing clears the retained receipt.

The app creates a fresh child such as `TVTime-Recovery-<timestamp>` beneath its private app-managed
parent. It refuses a path that already exists, overlaps the backup, is inside a Git worktree, or uses
an unsafe link. A retry always receives another fresh name.

### Space calculation

The destination does not need to hold the entire device backup. Preflight requires free space of at
least `max(512 MiB, 2 × Manifest.db size)`. It shows that minimum alongside the backup's logical size,
the manifest size, and destination free space.

After the encrypted manifest identifies the TV Time domains, recovery also requires the selected
files' declared bytes, temporary staging space equal to the largest selected encrypted payload, and
headroom of `max(64 MiB, 10% of selected bytes)`. Enabling advanced decrypted-manifest retention
adds one manifest-sized file to that check. This second check prevents a large app-domain extraction
from relying only on the initial manifest allowance.

Filesystem allocation can exceed logical sizes, so leave additional room. A failed attempt is kept
private and cannot be reused; allow room for a fresh retry until the first run is validated.

## 4. Install the published app

Use only the DMG and checksum from the
[official v0.2.0 release](https://github.com/amirbrooks/tvtime-backup-extractor/releases/tag/v0.2.0):

1. On an Apple silicon Mac, download the DMG labeled `Apple-Silicon-arm64`. On an Intel Mac,
   download `Intel-x86_64`.
2. Compare the DMG's SHA-256 value with its entry in the published `SHA256SUMS`.
3. Open the DMG, drag **TV Time Backup Extractor** to **Applications**, then eject the DMG.
4. Open the installed app from Applications.

A legitimate public package must be Developer ID signed, notarized, stapled, accepted by Gatekeeper,
and downloaded with its published checksum from the official release. Do not disable Gatekeeper or
use an app from an issue, message, local candidate, or unofficial mirror. The ad-hoc contributor
bundle does not satisfy this distribution contract, and successful local notarization alone does not
make a candidate public.

## 5. Run the guided recovery

1. Select **Choose Backup…** and choose the individual device-backup folder.
2. Wait while the app prepares private app-managed storage and scans the backup without modifying
   it.
3. Review the confirmation screen. It must show the encrypted backup as confirmed, the snapshot as
   finished, the destination as private app-managed local storage, and enough free space.
4. Acknowledge that the recovered files contain sensitive viewing history and are readable
   plaintext on this Mac.
5. Enter the encrypted-backup password in the secure field and select **Start Recovery**. The app
   rechecks local/cloud policy and directory identity immediately before it starts.

The password is sent only to the bundled local helper and is not intentionally persisted. The field
is cleared when recovery starts. The app and helper do not contact TV Time or Apple network services.

Recovery progresses through extraction, analysis, and reporting. The app copies only the primary TV
Time app domain and directly related plugin domains. It does not make another full backup copy.

## 6. Cancellation, closing, and quitting

Selecting **Cancel Check** during preflight stops the read-only scan and creates no recovery output.

Selecting **Cancel Recovery**, closing the window, or quitting while recovery is active opens a
confirmation dialog. **Continue Recovery** is the safe default. Confirmed cancellation asks the
helper to stop at a safe checkpoint and preserves any incomplete output for private diagnosis.

An incomplete run cannot be resumed, overwritten, merged, or used as a completed recovery. Keep it
private until the reason is understood, then use **Show Incomplete Recovery Folder** before starting
over if you need to inspect or remove that run. If
recovery finishes while a close or quit confirmation is visible, completion wins and the app keeps
the successful result available rather than treating it as cancelled.

## 7. Validate the result

The success screen appears only after the app reopens and validates the completed package. It shows
the selected-source, completion-marker, copied-file, and sealed-artifact checks together with an
aggregate chart, separate watched/saved movie and named/unnamed event counts, copied-file totals,
strict declared-size validation, and aggregate media-reference counts. Validate those counts before opening
private reports.

The app offers:

- **Open Visual Report** for the self-contained offline HTML catalogue;
- **Open PDF** when a faithful printable PDF could be produced;
- **Open Markdown** for the canonical complete text report; and
- **Show Recovery Folder** for the complete private package, including CSV tables and completion
  markers.

Opening a report launches the default browser or viewer. Its private filename may appear in that
application's history or macOS Recent Items. Close it after validation and clear that history if your
privacy model requires it; clearing history does not delete the report itself.

The PDF is optional. If recovered text requires character shaping or glyphs that the available
embedded font cannot preserve, the app states that the PDF was not created. The Markdown and offline
HTML reports remain the complete human-readable outputs.

For a successful full recovery, verify locally—without posting the files—that both markers say
`complete`:

```text
PRIVATE_RUN/TVTime-Extraction/metadata/run_state.json
PRIVATE_RUN/TVTime-Extraction/analysis/recovery_state.json
```

Also confirm that copied files equal selected files and that the report lists the expected titles,
favorites, episodes, and watch events. Byte-count differences remain explicit salvage notes with
declared/copied sizes and app-relative paths in the readable reports; they do not silently disappear.
Validate the recovered databases and readable content before relying on the result.

For an authorized local acceptance run, the repository validator can prove the complete root
layout, both completion contracts, artifact hashes and sizes, raw-cache-to-title/table parity,
offline HTML properties, deterministic PDF parity, and final copied-raw/sealed-artifact integrity.
It does not claim that every filesystem access/change timestamp is immutable. Pass the private path
over standard input so it does not become a process argument:

```text
printf '%s\n' "$PRIVATE_RUN" | ./.venv/bin/python -I script/validate_recovery_output.py
```

Every `GATE` line and the final `RESULT` must say `PASS`. Its aggregate `COUNT` lines remain private
and must not be pasted into issues, documentation, CI logs, or release evidence.

Keep the original encrypted backup until this review is complete. Never upload a report, table,
database, marker, screenshot of recovered content, or backup to an issue.

## CLI fallback on macOS

The free CLI supports Python 3.10 through 3.13. It remains available for automation, Linux, and
source-based workflows. Follow [Python CLI fallback](../README.md#python-cli-fallback) and use a
fresh private output path.

If Terminal reports **Operation not permitted** when reading MobileSync, follow
[macOS reports Operation not permitted](troubleshooting.md#macos-reports-operation-not-permitted).
Do not move the backup into the repository as a workaround.
