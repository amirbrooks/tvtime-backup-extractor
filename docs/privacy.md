# Privacy and safe handling

Recovery output contains personal viewing history and may contain account, device, cookie, media-URL,
and application-state data. Encryption of the source backup does **not** keep extracted files
encrypted after recovery. File permissions and the app sandbox are useful boundaries, not
substitutes for FileVault or other whole-disk encryption.

## Before recovery

- Use only a backup you own or are authorized to access.
- Wait for Finder, Apple Devices, or iTunes to finish the encrypted backup completely.
- Verify the finished backup, eject the phone, wait for it to disappear, and disconnect it.
- Keep the source backup unchanged; do not move, rename, edit, clean, or compact it.
- On macOS, let the native app create its owner-only recovery folder inside private app-managed
  local storage; do not move it into cloud sync, a shared folder, a Git repository, or the source
  backup.
- Enable FileVault when whole-disk protection is required. The native app does not claim that its
  sandbox or owner-only permissions encrypt recovered reports.
- Disable custom software that uploads the app's container or revealed recovery folder.
- Store the backup password safely and do not reuse it unnecessarily.
- Leave enough free space for selected data, temporary manifest processing, and a fresh retry.

The native macOS app creates a fresh output inside its private local app container with owner-only
permissions. It binds preflight and recovery to that directory's stable filesystem identity,
rejects symbolic-link ancestry, and gives the bundled helper an already-open parent handle. The
helper creates and opens the fresh child relative to that handle, changes its dedicated process into
the held output-root identity, and keeps every private descendant relative for the full extraction,
analysis, and report run. A substituted visible path receives no recovered plaintext and final
success requires the original identity to remain visible.
The native preflight helper also returns a strict source receipt containing only internal backup-root
identity, critical-metadata snapshots, and the displayed source aggregates. The app retains it only
in memory. The separate recovery helper must rescan and match it before creating the output child;
replacing the backup root or changing bound critical metadata or a displayed aggregate after
confirmation fails before output creation. Selected payload files are snapshot-verified during
extraction and revalidated before extraction completion. The POSIX CLI consumes the same
identity-bound receipt across its hidden password prompt and applies the same held-parent and
held-output-root model. On supported Windows 11 x64 source builds, `NtCreateFile` atomically creates
the fresh child relative to the held parent, applies a protected current-user-and-SYSTEM ACL, and
returns the handle in the same operation. Windows keeps the source, parent, and output handles open
without delete sharing, rejects reparse traversal, writes through exclusive descriptors, and
revalidates native identities and visible paths. Unsupported Windows capabilities fail before
password entry or plaintext creation. These checks do not make a mounted plaintext destination
encrypted or prove that custom sync is disabled. The full-recovery CLI cannot certify BitLocker or
every storage stack and therefore requires an explicit encrypted-destination acknowledgement.
Neither interface can certify ownership authorization, sync behavior, snapshots, or backup policy;
the user must confirm those boundaries.

Linux FUSE destinations are refused because the same mechanism can expose local, network, cloud, or
shared storage. There is no override. Linux accepts only a conservative allowlist of ordinary local
filesystem types and rejects ambiguous stacked mountpoints.

These controls assume the local operating-system account is not already compromised and no hostile
process is running as the same user during recovery. Such a process can access that user's private
files and memory and can race pathname operations. Detected source, destination, or output changes
prevent a successful completion seal, but an interrupted or tampered run can retain incomplete
private output. Close untrusted same-user software during recovery and discard any incomplete run.

## Password handling

The macOS app uses a secure field and sends the password only to its bundled local helper. The CLI
uses a hidden prompt by default. Neither path intentionally writes the password to disk, a report, or
normal progress output.

Do not put a password in a command, environment variable, shell history, text file, screenshot, or
support request. Swift and Python cannot guarantee that every in-memory copy is overwritten
immediately; close the app or terminal after validation if that matters to the local threat model.

## Data-minimizing defaults

By default:

- the full decrypted device manifest is temporary and is not retained;
- verbatim cached API responses are not exported;
- cache keys are represented by opaque hashes in the index;
- profile and settings payloads are counted but not copied to normalized tables;
- report URLs lose credentials, fragments, and nonessential query parameters;
- readable reports omit stable UUIDs and shorten recognized timestamps to calendar dates; and
- visual reports show media-reference counts without embedding or fetching remote media.

The normalized CSV files still contain private identifiers and exact timestamps where needed for a
faithful archive. The readable reports are safer to inspect, not safe to publish.

The advanced `extract --include-decrypted-manifest` and `analyze --include-raw-cache` CLI options
can expose much more device or account information. They are intentionally unavailable in the
sealed `recover` workflow and cannot produce a native-validated completion report. Do not enable
them for ordinary recovery.

## Reports, browsers, and Recent Items

The offline HTML contains no JavaScript or remote requests, but opening it still hands the local file
to the default browser. Opening the PDF or Markdown similarly hands it to another application.
Private filenames can appear in browser history, document history, macOS Recent Items, Finder
recents, Quick Look caches, crash reports, or application state restoration.

For stricter handling:

- use a dedicated local browser profile with sync disabled;
- close report tabs and document windows after validation;
- clear local history or Recent Items if appropriate;
- disable cloud sync and automatic upload in the chosen viewer; and
- keep FileVault enabled where whole-disk confidentiality is required.

Clearing history does not delete the recovery output, and deleting the visible output does not
necessarily erase caches, snapshots, or synced copies.

## Never upload these

Do not attach, commit, publish, or send any of the following, even to a private support issue:

- an iOS or iPadOS backup, `Manifest.plist`, `Status.plist`, or decrypted manifest;
- `TVTime-Extraction`, `raw`, `metadata`, `analysis`, or `cache_responses`;
- SQLite databases, property lists, cookies, profile payloads, completion markers, reports, or CSVs;
- backup passwords, device IDs, stable user IDs, hashes, private URLs, or local paths; or
- screenshots, screen recordings, PDFs, or previews containing recovered titles or history.

Repository ignore rules and release privacy scans are final defenses, not permission to put private
data in the project.

## Sharing diagnostics

The native app writes a small, local-only sequence of fixed lifecycle and failure-class events to
Apple's unified log under subsystem `com.amirbrooks.tvtime-backup-extractor` and category
`RecoveryDiagnostics`. It does not send analytics or diagnostics over the network. The event
vocabulary cannot contain a path, backup or device identifier, filename, title, recovered count,
password, free-form helper message, or report content. Unknown errors become
`unrecognized_failure` instead of being stringified. The operating system controls unified-log
retention.

For support, prefer the safe reference code displayed by the app and a manual description of the
stage. Do not export or upload a complete unified-log archive: unrelated processes can place private
data in the same archive. Contributors can filter this app's bounded events locally as described in
the troubleshooting guide.

Prefer the application or CLI version, operating system, Mac architecture when relevant, command or
workflow stage, exit code, and a manually paraphrased error. Replace usernames, paths, IDs, titles,
dates, URLs, hashes, and counts with clearly synthetic values.

Treat every CLI `--debug` traceback as sensitive. It can expose backup paths, dependency details,
recovered names, or password text retained in a chained third-party exception. Never paste or share
it. If diagnosis requires it, review it only in a private local terminal and manually paraphrase the
failure without copying traceback text or terminal scrollback. Maintainers will not ask for the
backup or generated output.

## Interrupted and cancelled runs

Preflight cancellation creates no recovery output. Once extraction begins, an interruption or
confirmed cancellation can leave an incomplete private tree. The tool preserves it to avoid hiding
partial state and refuses to resume, overwrite, or merge it.

Keep an incomplete tree private while diagnosing the abstract failure. In the native app, reveal it
before starting over if you need to inspect or remove it; a new attempt always uses a fresh output
folder. Never change a completion marker to `complete` manually.

## Cleanup and retention

Retain the original encrypted backup until both completion markers and the recovered names have been
validated. Close applications using the output before deleting or relocating it.

Emptying a recycle bin or deleting files does not reliably erase SSD blocks, snapshots, backups,
sync providers, virtual-machine images, browser caches, or Recent Items databases. Prefer destroying
the key for a dedicated encrypted volume when reliable disposal matters.
