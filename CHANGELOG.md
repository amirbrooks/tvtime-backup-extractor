# Changelog

All notable changes are documented here. The project follows semantic versioning.

## 0.3.0-alpha.1 - 2026-08-01

This experimental GitHub prerelease is the first alpha for the 0.3.0 cross-platform work.
Successful synthetic checks do not make every device route verified. Its public artifact set
deliberately excludes a Windows binary.

See the [v0.3.0-alpha.1 release preparation record](docs/release-v0.3.0-alpha.1.md) for completed
evidence, release gates, and remaining native proof.

- Added native source-neutral recovery for legacy Android backup containers, preserved Android
  database snapshots, and official TV Time export ZIP/CSV files. These lanes reuse the normalized
  analyzer, sealed completion contract, and synthetic-only test policy.
- Added a Windows 10 1809+ x64 WinUI 3 app with explicit inherited handles, a separate secret
  channel, Job Object cancellation, a BitLocker/device-encryption gate, app-managed output, strict
  artifact validation, and private self-signed MSIX build/install scripts.
- Added encrypted iOS backup selection to the private WinUI app on Windows 11 x64. Source traversal
  uses held relative Win32 handles, and recovery consumes a preflight receipt before the password is
  sent to a separate helper process. Release readiness still requires synthetic Windows UI and
  recovery proof.
- Bound the complete Windows App SDK dependency graph with exact NuGet ranges and content hashes,
  added a real-reference cross-host C# compile check, and added validated Markdown, offline HTML,
  and private-folder result actions without persisting source or output paths.
- Added native macOS source selection for Android and official exports while preserving the
  published v0.2.0 encrypted-iOS-backup workflow.
- Added a copyable, bounded Safe Diagnostics trail to the macOS failure screen. It reports only
  fixed operation, milestone, and failure codes and does not include raw errors or private values.
  Displayed error references use the same exact allowlist; unknown helper values fail closed as
  `unrecognized_failure`.
- Added privacy-safe Android capability probing and explicitly acknowledged legacy-device capture.
  Modern release apps, disabled backup policy, multiple devices, and unauthorized devices fail
  closed.
- Added bounded offline recovery from supported legacy `NSKeyedArchiver` URL-cache files when
  records are no longer present in `DioCache.db`.
- Added sealed owner-only TV Time Liberator ZIP exports with separate confirmed-state and explicitly
  estimated-progress variants generated offline.
- Centralized formula-leading CSV neutralization and exact report/Refract reversal, including line
  feeds and Suite TV exports; kept unsupported ZIP encryption distinct from an incorrect password;
  and made acquisition failure messages source-neutral.
- Fixed intermittent macOS helper launches for source types that do not use the secret channel.
- Separated the Windows 10 filesystem gate from the Windows 11 encrypted-iOS gate, rejected
  remote, shared, synced, reparse, and cloud-hydrated recovery or Refract sources at the root and
  every traversed or consumed descendant, required private local NTFS sources, used no-recall regular-file
  Windows opens with pinned ancestor chains, and required the frozen helper to use reviewed x64
  Python.
- Corrected the Windows NTFS regression harness and included it in the hosted Windows matrix.
- Bound private Windows packaging to retained directory and no-follow MSIX file capabilities, exact
  restored dependency membership, immutable tree manifests, and full unsigned/package block-map
  digests through installation so namespace replacement or post-scan payload changes fail closed.
  MSBuild producer-handle provenance remains an explicit Windows release-readiness gate.
- Added a source-level Windows no-network/no-AI/no-WebView contract while keeping final transitive
  MSIX membership as an explicit Windows release-readiness proof requirement.
- Added an offline, owner-only Refract series converter using recovered tables. Import acceptance
  still requires a synthetic Windows UI smoke test before it is considered release-ready.
- Preserved recovered TVDB IDs, rewatch counts, aggregate series progress, and episode-special flags
  in normalized tables.
- Published signed, notarized, stapled, and Gatekeeper-accepted Apple silicon and Intel DMGs plus
  verified Python wheel and source packages. No MSIX is included. v0.2.0 remains the latest stable
  release.

## 0.2.0 - 2026-07-20

Version 0.2.0 is published with Developer ID-signed, notarized, stapled Apple silicon and Intel
DMGs, release manifests and checksums, and verified Python wheel and source packages. The complete
release is available from the
[official v0.2.0 release](https://github.com/amirbrooks/tvtime-backup-extractor/releases/tag/v0.2.0).

### Native macOS application

- Added a native SwiftUI application for macOS 14 or later with a guided backup picker, destination
  picker, read-only preflight review, secure password entry, destination-encryption verification,
  progress, cancellation protection, and a complete result screen.
- Added fail-closed macOS destination-encryption verification at selection, preflight, and recovery
  start; the user acknowledgement now describes plaintext exposure while the verified volume is
  unlocked rather than asking the user to certify encryption.
- Added system-owned folder selection and sandbox-scoped access instead of hard-coded user paths or
  broad filesystem access.
- Added a native aggregate chart, separate watched/saved movie and named/unnamed event counts,
  copied-file and salvage-warning summaries, media-reference counts, report availability, and
  guarded report/Finder actions.
- Added confirmation for active Cancel, window close, and quit actions. Preflight cancellation
  creates no output; active cancellation preserves incomplete output and requires a fresh retry.
- Fixed the completion-versus-quit race so natural helper completion dismisses a pending interruption
  request without turning success into cancellation or authorizing a deferred quit.

### Shared recovery engine and helper

- Added a UI-neutral recovery service, typed request/result models, progress events, cooperative
  cancellation, bounded framed helper protocol, privacy-safe helper errors, and strict native summary
  decoding.
- Bound the native app and POSIX CLI to stable destination-parent and fresh output-root directory
  identities. The dedicated helper/CLI process keeps every private descendant relative to the held
  output root for extraction, analysis, and reporting; substitution receives no recovered plaintext
  and prevents final success. Windows fresh extraction/recovery now fails closed before directory
  creation because supported Python APIs cannot atomically create and lock the new plaintext root;
  standalone Windows analysis/reporting still hold a non-delete-sharing existing-root handle,
  reject reparse points, and revalidate its stable volume/file identity.
- Sanitized every third-party decryption failure exposed by normal CLI/API use and persisted copy-
  failure summaries; raw chained exception text remains available only through an explicitly private
  `--debug` traceback whose help and privacy guidance forbid sharing.
- Bound reusable preflight receipts to stable backup-root and `Manifest.plist`, `Manifest.db`, and
  `Status.plist` identities and SHA-256 values, and revalidate them before fresh output creation.
- Bounded backup plist bytes, streamed directory traversal and manifest cursor batches, and enforced
  selected-manifest row, cell, shape, type, and combined-byte ceilings.
- Required an encrypted backup whose `Status.plist` snapshot is marked finished, and added cancellable
  read-only backup traversal before accepting a run.
- Made the CLI complete and visibly summarize backup/destination preflight before reading the hidden
  password, and kept the selected parent descriptor open across preflight, password entry, and run.
- Added exact preflight free-space checks and a second selected-data check with explicit headroom.
- Revalidated source manifest metadata, finished status, and selected encrypted payload metadata
  before the extraction completion checkpoint.
- Strengthened no-follow file access, link/reparse rejection, traversal and overlap protection,
  portable-name checks, private permissions, temporary-tree handling, and stable storage-full errors.
- Added conservative Linux local-filesystem classification; FUSE, network, shared, virtual-machine,
  overlay, temporary, unknown, and ambiguous stacked mounts fail closed with no override.
- Added atomic extraction and report markers, staging directories, and final analysis promotion so
  incomplete runs cannot be mistaken for completed recovery.
- Bound `metadata/domains.txt` into the completion artifact inventory and compare the exact bounded
  serialized completion-marker bytes after writing and again immediately before promotion.
- Bound the inventory to the exact raw tree and required exact metadata/analysis directory
  membership in both Python and Swift, rejecting missing, renamed, linked, special, or unmanifested
  files before a run can be treated as sealed.
- Removed inherited Darwin ACLs before creating children or writing bytes and independently rejected
  residual ACLs in native output validation.

### Reports and recovery usability

- Kept Markdown as the canonical complete human-readable report and added a self-contained offline
  HTML catalogue with summary cards, accessible navigation, charts, and complete recovered-name
  tables. Markdown, HTML, and PDF share one normalized display model and identical missing-title
  placeholders.
- Added an optional paginated PDF generated from the same visual model, with embedded-font and text-
  shaping fidelity checks. PDF generation is omitted explicitly when it cannot preserve every
  recovered character; Markdown and HTML remain complete.
- Added normalized media-reference catalogues, aggregate image/trailer/URL summaries, and visual
  reports that never embed or request remote media.
- Added readable copy-size-difference rows with declared/copied bytes and app-relative paths.
- Preserved exact reversible CSV spreadsheet-escape provenance so potentially active cells remain
  safe in tables without corrupting the canonical readable report.
- Added clear warnings that opening private reports can add filenames to browser/viewer history and
  macOS Recent Items.
- Added a native PDFKit raster smoke gate, explicit HTML accessibility guidance, PDF language
  metadata, and invisible/format-only Unicode title handling that cannot inflate named-title counts.

### Native packaging preparation

- Added a host-architecture, sandboxed, ad-hoc local acceptance build that is explicitly not a public
  distribution artifact.
- Added a fail-closed release pipeline for separate Apple silicon and Intel DMGs, including exact-
  architecture helper/app builds, dependency locks, bundled licenses, private-artifact scanning,
  inside-out signing, hardened runtime, entitlement verification, notarization, stapling, Gatekeeper
  assessment, per-architecture manifests, checksums, locking, and atomic output promotion.
- Added a controlled native-runtime license allowlist and fail-closed inventory of every non-system
  Mach-O. Packaging now binds each path and architecture to one component, exact version, exact
  checked-in license text, and a signing-stable canonical SHA-256 before signing, after signing, and
  again from the final DMG; unmapped, extra, missing, overlapping, or mismatched entries stop the
  build.
- Bound release builds to a clean reviewed commit and a read-only, exactly revalidated `git archive`
  source stage so mutable checkout bytes cannot enter signed applications or Python distributions.
- The release pipeline performs no upload and cannot run without a real Developer ID Application
  identity, configured notarization profile, full Xcode, universal2 build Python, and dual-
  architecture execution support.
- Validated that pipeline through signing, notarization, stapling, Gatekeeper,
  architecture-specific packaged-helper smoke, mounted-DMG license verification, provenance
  manifests, checksums, privacy scans, and fresh draft-asset re-download for both Apple silicon and
  Intel packages before publishing v0.2.0.

### Tests and documentation

- Added synthetic Python coverage for service/protocol integration, cancellation boundaries, atomic
  markers, no-follow and source-change handling, CSV reversibility, section-by-section report parity,
  parsed PDF text/occurrence fidelity, optional PDF omission, and full recovery orchestration.
- Added Swift tests for protocol decoding, summary invariants, output-path validation, recovery state
  transitions, cancellation, and interruption races using fake helpers and synthetic output trees.
- Added native macOS CI for format, debug/release tests, and optimized builds alongside full
  macOS/Linux Python recovery coverage and a Windows existing-extraction/fail-closed contract job.
- Reworked user guidance around the app-first macOS experience, published distribution state, CLI
  fallback, two-stage space model, source immutability, atomic markers, report fidelity,
  Recent Items, and safe support boundaries.

## 0.1.0 - 2026-07-18

- Established the first privacy-focused source baseline and guided `recover` workflow.
- Added separate `extract`, `analyze`, and `report` commands for advanced use.
- Added encrypted-backup password prompting, explicit sensitive-output acknowledgement, and fresh
  private destinations.
- Added TV Time domain selection, app-container inventory, normalized private CSV tables, a readable
  title report, and sanitized media-reference tables.
- Added path traversal, overlap, Git destination, link, overwrite, and portable-name protections.
- Made decrypted device-manifest and verbatim raw-cache retention explicit advanced opt-ins.
- Added SQLite snapshot/integrity and schema checks, rewatch preservation, cache-page deduplication,
  spreadsheet-safe CSV writing, readable terminal summaries, exact-pinned dependencies, synthetic
  tests, and cross-platform source instructions.
