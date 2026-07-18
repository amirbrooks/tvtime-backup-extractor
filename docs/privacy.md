# Privacy and safe handling

The output contains personal viewing history and may contain account, device, cookie, media URL, and
application-state data. Encryption of the source backup does **not** keep extracted files encrypted
while the destination is mounted. File permissions are a useful boundary, not disk encryption.

## Before extraction

- Use only a backup you own or are authorized to access.
- Confirm the destination is protected by FileVault, BitLocker, LUKS, or separate volume encryption.
- Use a destination outside every Git repository and outside the source backup.
- Avoid cloud-sync, shared, indexed team, or automatically published folders.
- Keep enough free space and keep the original backup unchanged.
- Use a password distinct from any output-volume password.

The CLI enforces a fresh output, checks for overlap and Git repositories, refuses symbolic-link
destinations, uses private POSIX permissions where available, and requires
`--acknowledge-sensitive-output`. These controls do not replace encryption or authorization.

## Data-minimizing defaults

By default:

- the full decrypted device manifest is not retained;
- verbatim cached API responses are not exported;
- cache keys are represented by opaque hashes in the index;
- profile/settings payloads are counted but not copied to normalized tables;
- report URLs lose credentials, fragments, and nonessential query parameters;
- the readable report omits stable UUIDs and shortens recognized timestamps to calendar dates.

The normalized CSV files still contain private identifiers and exact timestamps where they are
needed for a faithful personal archive. The readable report is safer to inspect, not safe to publish.

`--include-decrypted-manifest` and `--include-raw-cache` are advanced opt-ins. They can expose much
more device or account information. Do not enable them for ordinary recovery.

## Never upload these

Do not attach or commit any of the following, even to a private support issue:

- an iOS backup or `Manifest.plist`/decrypted manifest;
- `TVTime-Extraction`, `raw`, `metadata`, `analysis`, or `cache_responses`;
- SQLite databases, property lists, cookies, profile payloads, reports, or CSV exports;
- backup passwords, device IDs, stable user IDs, local paths, or screenshots containing them.

The repository ignore rules are a last defense, not permission to place private data in the project.

## Sharing diagnostics

Prefer the program version, operating system, command name, exit code, and a manually paraphrased
error. Replace usernames, paths, IDs, titles, dates, URLs, and counts with clearly synthetic values.
Do not use the `--debug` traceback in a public terminal or issue unless you have reviewed and redacted
it; debug output may include private paths.

## Cleanup

Close applications using the output before deleting it. Emptying a recycle bin or deleting a file
does not reliably erase blocks from SSDs, snapshots, backups, sync providers, or virtual-machine
images. Prefer destroying the encryption key or encrypted volume when reliable disposal matters.
Retain the source backup until recovery has been validated.
