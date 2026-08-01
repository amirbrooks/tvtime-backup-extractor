# TV Time Backup Extractor v0.3.0-alpha.1

This is an experimental GitHub prerelease for technical testers. It is not the latest stable
release; v0.2.0 remains the stable recommendation.

## Downloads

- `TV-Time-Backup-Extractor-0.3.0-alpha.1-macOS-Apple-Silicon-arm64.dmg` for Apple silicon Macs
- `TV-Time-Backup-Extractor-0.3.0-alpha.1-macOS-Intel-x86_64.dmg` for Intel Macs
- the Python wheel or source package for Python 3.10 through 3.13 on macOS or Linux, and for the
  documented existing-extraction/report routes on Windows
- `SHA256SUMS` and the release manifests for verification

The Mac DMGs are intended to be Developer ID signed, notarized, stapled, and Gatekeeper accepted.
Verify the downloaded filenames against `SHA256SUMS` before opening them.

## What is experimental

The alpha adds macOS and Python recovery from official TV Time ZIP/CSV exports, compatible legacy
Android backup containers, and preserved Android database snapshots. Android acquisition is device
and schema dependent: modern devices commonly do not expose compatible app data, and unsupported
sources fail closed.

The repository contains a promising native Windows app candidate, but this release deliberately
includes no MSIX or other Windows binary. Native Windows installation, UI behavior, real NTFS
capability behavior, and complete packaged recovery are not yet proven. Advanced Windows testers
may use the Python CLI or follow the private source-build instructions in `docs/windows.md` using
only synthetic or owner-authorized local data.

Existing encrypted-iOS recovery on macOS retains the published v0.2 workflow. Official-export
recovery has synthetic end-to-end coverage. No test result claims that every TV Time app version,
backup schema, or physical device is compatible.

## Privacy and safety

Recovery is local and offline. Never upload a backup, database, export, report, screenshot, marker,
or recovered content to an issue. Keep every source read-only and retain recovered output only in
private owner-controlled local storage. For encrypted-iOS recovery, use a completed encrypted
backup and disconnect the phone after confirming that backup has finished. Opening a report can add
its private filename to browser or viewer history and Recent Items.

If recovery stops in the macOS app, use **Copy Safe Diagnostics** and share only that bounded text
plus a manual description of the stage. Unknown failures are reported as `unrecognized_failure`.
Do not send a screenshot, complete log archive, backup, database, export, report, or recovered
output.

This project is independent and is not affiliated with or endorsed by TV Time, Apple, Google, or
Microsoft.
