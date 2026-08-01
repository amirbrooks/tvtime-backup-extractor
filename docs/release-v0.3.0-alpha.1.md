# v0.3.0-alpha.1 release preparation record

## Current status

This prerelease was published on 2026-08-01 from tagged commit
`9b61b27e670b12bd16a072e0e8c61121dc89c13f`:

- [GitHub release](https://github.com/amirbrooks/tvtime-backup-extractor/releases/tag/v0.3.0-alpha.1)
- eight public assets: two architecture-specific Mac DMGs, two Mac manifests, Mac checksums, a
  Python wheel, a Python source archive, and a Python release manifest

- `v0.2.0` remains the latest stable release. GitHub marks `v0.3.0-alpha.1` as a prerelease, not
  latest.
- Release metadata identifies the same alpha without violating platform version formats:
  `0.3.0a1` for Python, `0.3.0` plus bundle build `1` and the explicit
  `TVTimeReleaseVersion=0.3.0-alpha.1` for macOS, and private MSIX identity `0.3.0.1` with an Alpha
  display name for Windows. Artifact filenames use `0.3.0-alpha.1`. A later stable build must use
  new filenames and increment the native build and package version numbers without changing stable
  application identifiers.

## Alpha scope

The candidate adds local recovery from supported legacy Android backups, preserved Android
database snapshots, and official TV Time exports. It also contains a private x64 Windows app
candidate for Android and export recovery on Windows 10 1809 or later, plus encrypted iOS backup
recovery on Windows 11 x64.

The public alpha artifact set is deliberately narrower: signed and notarized Apple silicon and
Intel DMGs plus verified Python wheel and source packages. It does not include an MSIX or another
public Windows binary. Advanced Windows testers may use the Python CLI or the private source-build
instructions in `docs/windows.md`.

The application code adds no network client, telemetry, WebView, or AI feature. Final Windows MSIX
membership and third-party notice verification remain required before any Windows binary can be
published.

Android recovery is experimental and limited to compatible legacy backups, already-preserved
snapshots, or official exports. Device backup policy and recovered schemas vary; modern devices
commonly fail closed. A successful synthetic fixture does not claim that a particular physical
device or current TV Time app build is recoverable.

## Final release evidence from 2026-08-01

Tagged commit `9b61b27e670b12bd16a072e0e8c61121dc89c13f` produced the published assets:

- 15 hosted CI jobs passed on macOS, Linux, and Windows for Python 3.10 through 3.13, including the
  native Windows compile and synthetic validator smoke;
- source-bound Python wheel and source distributions passed exact membership, content, metadata,
  clean-install, dependency, command-help, and privacy checks;
- the arm64 and x86_64 apps and packaged helpers passed exact architecture, sandbox entitlement,
  deep signature, native-license, synthetic protocol, privacy, notarization, stapling, and
  Gatekeeper checks;
- both DMGs passed their own Developer ID signing, notarization, stapling, Gatekeeper, mounted-image,
  link-containment, manifest, and checksum checks; and
- all eight draft assets were downloaded into a fresh directory and matched the verified originals
  byte for byte before publication. The downloaded Mac and Python artifacts then repeated their
  source, privacy, checksum, signature, ticket, Gatekeeper, manifest, and link-containment checks.

## Alpha confidence by route

- Existing macOS encrypted-iOS recovery: high. It retains the published v0.2.0 workflow and has
  expanded Swift, helper, privacy, and packaging coverage.
- macOS and Python official-export recovery: reasonable from synthetic end-to-end coverage.
- Legacy Android backup or snapshot recovery: experimental and device/schema dependent.
- Native Windows app: private and not included in this release. Compilation, validator smoke, and
  hosted Windows lanes do not prove installation, UI behavior, NTFS behavior, or complete packaged
  recovery.

## Pre-tag alpha release gates

The prerelease must not be tagged or uploaded until all of these public alpha gates are complete:

1. Freeze one clean release commit and rerun the complete Python, Swift, formatting, privacy,
   source-package, and hosted CI gates on that exact commit.
2. Build fresh arm64 and x86_64 macOS DMGs from that commit with the official universal2 Python,
   Developer ID signing, hardened runtime, production entitlements, notarization, stapling,
   Gatekeeper assessment, native-license verification, manifests, and checksums.
3. Exercise both architecture-specific packaged helpers and inspect the final DMGs. Confirm the
   existing encrypted-iOS journey remains operational and the new export route completes with only
   synthetic data. Keep any unavailable physical Intel-system validation explicit in the release
   notes rather than treating Rosetta execution as identical hardware proof.

## Deferred device validation

This alpha includes no Windows binary, so private MSIX packaging, native Windows installation, UI,
NTFS, and packaged recovery proof are not publication gates for this release. Android acquisition
also remains experimental and device-dependent. Native Windows and physical Android validation
continue in [issue #13](https://github.com/amirbrooks/tvtime-backup-extractor/issues/13) before either
capability is described as generally available.

## Draft verification gate

After the tag is pushed and the complete asset set is uploaded to a draft prerelease, re-download
every draft asset into a fresh directory and repeat checksum, signature, notarization, stapling,
Gatekeeper, architecture, version, provenance, and privacy verification. The prerelease must remain
draft until this passes.

## Privacy evidence rules

Use synthetic fixtures only for public or retained evidence. Never attach or publish a real backup,
database, export, recovered output, report, completion marker, title, identifier, private path,
screenshot of recovered content, or device/account detail.

Release credentials stay outside the repository. Use only the intended local Developer ID identity
and a named `notarytool` Keychain profile. Do not copy credentials or environment values from
another repository.

## Publication sequence

After every pre-tag gate passes:

1. Create an annotated `v0.3.0-alpha.1` tag locally from the exact reviewed commit and verify its
   peeled commit before any remote mutation.
2. Push only that tag, fetch it back, and verify the remote peeled tag still resolves to the same
   commit.
3. Create a draft GitHub prerelease with `--verify-tag`. Release tooling must not create or retarget
   the tag.
4. Upload only the complete verified artifact set and its manifests/checksums.
5. Complete the draft verification gate above.
6. Publish as a prerelease while keeping v0.2.0 as latest stable.
7. Update release-status copy only after GitHub confirms publication.
