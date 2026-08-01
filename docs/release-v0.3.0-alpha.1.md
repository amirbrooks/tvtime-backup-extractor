# v0.3.0-alpha.1 release preparation record

## Current status

This prerelease is not published. No `v0.3.0-alpha.1` tag, GitHub release, or public alpha artifact
exists yet.

- `v0.2.0` remains the current stable release.
- The intended GitHub tag is `v0.3.0-alpha.1` and must be marked as a prerelease, not latest.
- Release metadata identifies the same alpha without violating platform version formats:
  `0.3.0a1` for Python, `0.3.0` plus bundle build `1` and the explicit
  `TVTimeReleaseVersion=0.3.0-alpha.1` for macOS, and private MSIX identity `0.3.0.1` with an Alpha
  display name for Windows. Artifact filenames use `0.3.0-alpha.1`. A later stable build must use
  new filenames and increment the native build and package version numbers without changing stable
  application identifiers.
- Tagging and uploading remain blocked until every pre-tag gate in this record passes on one frozen
  source commit. Publication remains blocked until the uploaded draft assets pass revalidation.

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

## Preparation evidence from 2026-08-01

Merged commit `42f9aa5bdefe79c94e7e0913bf6ee9d96d103b5a` produced this exact-source
preparation evidence:

- 15 hosted CI jobs passed on macOS, Linux, and Windows for Python 3.10 through 3.13, including the
  native Windows compile and synthetic validator smoke;
- source-bound Python wheel and source distributions passed exact membership, content, metadata,
  clean-install, dependency, command-help, and privacy checks;
- the local arm64 app passed exact architecture, sandbox entitlement, deep signature, native
  license, packaged-helper synthetic preflight, privacy, launch, and clean-quit checks; and
- all eight public v0.2.0 assets were downloaded again and passed checksums, Developer ID signature,
  notarization ticket, Gatekeeper, architecture, version, and privacy checks.

The diagnostics and release-documentation change set then passed 465 local Python tests
with 13 expected platform-specific skips, 122 debug Swift tests, Ruff, formatting, shell syntax,
Python helper compilation, and Git diff checks. These local results do not extend the earlier
hosted or source-package evidence to the changed bytes.

This is preparation evidence only. The final tagged commit must rerun every applicable gate after
all release changes are merged.

## Alpha confidence by route

- Existing macOS encrypted-iOS recovery: high. It retains the published v0.2.0 workflow and has
  expanded Swift, helper, privacy, and packaging coverage.
- macOS and Python official-export recovery: reasonable from synthetic end-to-end coverage.
- Legacy Android backup or snapshot recovery: experimental and device/schema dependent.
- Native Windows app: private and not included in this release. Compilation, validator smoke, and
  hosted Windows lanes do not prove installation, UI behavior, NTFS behavior, or complete packaged
  recovery.

## Pre-tag alpha release gates

The prerelease must not be tagged or uploaded until all of these are complete:

1. Build the private MSIX from a source-bound immutable stage on supported native Windows 11 x64.
2. Pass the real NTFS capability suite, install/package smoke, synthetic UI journey, and synthetic
   end-to-end recovery journey on that Windows build.
3. Verify final MSIX membership, runtime-pack pins, binary-to-component notices, and the package
   no-network/no-AI contract. The verified MSIX remains private and is not a public alpha asset.
4. Validate a supported legacy Android capture where available and confirm documented fail-closed
   behavior on a modern device that does not expose compatible app data.
5. Freeze one clean release commit and rerun the complete Python, Swift, formatting, privacy,
   source-package, and hosted CI gates on that exact commit.
6. Build fresh arm64 and x86_64 macOS DMGs from that commit with the official universal2 Python,
   Developer ID signing, hardened runtime, production entitlements, notarization, stapling,
   Gatekeeper assessment, native-license verification, manifests, and checksums.
7. Exercise both architecture-specific packaged helpers and inspect the final DMGs. Confirm the
   existing encrypted-iOS journey remains operational and the new export route completes with only
   synthetic data. Keep any unavailable physical Intel-system validation explicit in the release
   notes rather than treating Rosetta execution as identical hardware proof.

## Draft verification gate

After the tag is pushed and the complete asset set is uploaded to a draft prerelease, re-download
every draft asset into a fresh directory and repeat checksum, signature, notarization, stapling,
Gatekeeper, architecture, version, provenance, and privacy verification. The prerelease must remain
draft until this passes.

Native Windows and Android proof is tracked in
[issue #13](https://github.com/amirbrooks/tvtime-backup-extractor/issues/13).

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
