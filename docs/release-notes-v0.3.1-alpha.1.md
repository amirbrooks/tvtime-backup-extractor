# TV Time Backup Extractor v0.3.1-alpha.1

This prerelease adds a downloadable Windows x64 tester app alongside updated Mac and Python builds.
It remains experimental. v0.2.0 is still the stable recommendation.

## Downloads

- `TV-Time-Backup-Extractor-0.3.1-alpha.1-macOS-Apple-Silicon-arm64.dmg` for Apple silicon Macs
- `TV-Time-Backup-Extractor-0.3.1-alpha.1-macOS-Intel-x86_64.dmg` for Intel Macs
- `TV-Time-Backup-Extractor-0.3.1-alpha.1-Windows-x64.zip` for Windows testers
- `tvtime_backup_extractor-0.3.1a1-py3-none-any.whl` and the matching source archive
- release manifests and checksums for all platforms

Verify the downloaded artifact against the published checksums before opening it.

## Windows alpha

The Windows ZIP contains the signed MSIX, its public certificate, guarded install and removal
scripts, license notices, and a source-bound release manifest. It does not contain the signing
private key. Windows asks for explicit permission to trust the project-specific alpha certificate.

Windows 10 version 1809 or later can test compatible local Android sources and official exports.
Encrypted iPhone and iPad backup recovery requires Windows 11 x64. BitLocker or Windows device
encryption must protect the app's private output volume.

The hosted release gate builds, installs, launch-smokes, removes, and reverifies the exact package.
That does not prove every physical device, backup schema, filesystem, or UI path. Please report
compatibility using synthetic steps and Safe Diagnostics codes only.

## Mac and Python

The Mac app keeps encrypted iOS recovery and adds the experimental Android and official-export
routes. The separate Apple silicon and Intel DMGs are intended to be Developer ID signed,
notarized, stapled, and accepted by Gatekeeper.

The Python packages support Python 3.10 through 3.13. Full encrypted-backup recovery remains
supported on macOS and Linux. Windows continues to support the documented existing-extraction and
report routes through Python.

## Privacy

Recovery is local and offline. The application contains no network client, telemetry, AI feature,
machine-learning feature, or WebView. Never upload a backup, export, database, report, output tree,
marker, screenshot of recovered content, or debug trace.

If the app stops, share only the fixed Safe Diagnostics codes and a synthetic description of the
stage. Those codes do not contain paths, titles, identifiers, passwords, counts, or raw errors.

This project is independent and is not affiliated with or endorsed by TV Time, Apple, Google, or
Microsoft.
