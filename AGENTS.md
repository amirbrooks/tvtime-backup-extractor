# Repository agent notes

## Privacy boundary

- Never add a real iOS backup, TV Time output, viewing history, title list, account/profile data,
  cookie, database, manifest, completion marker, stable ID, device ID, hash, private URL, screenshot,
  screen recording, PDF preview, or local path.
- Tests and documentation use obviously synthetic values only. Redacting one field does not make a
  recovered artifact safe.
- Native decrypted output belongs in the owner-only app-managed local container, outside every Git
  repository, cloud-sync root, share, and source backup. FileVault remains recommended because the
  sandbox and permissions do not encrypt recovered reports. `.gitignore` and the release scanner
  are final defenses, not storage policy.
- Preserve secure defaults: completed encrypted backup, disconnected phone, read-only source,
  owner-only app-managed local output, sensitive-output confirmation, hidden or secure password
  entry, fresh output, Git/overlap/link/traversal checks, atomic completion markers, and opt-in
  raw-cache or decrypted-manifest retention.
- Never ask a user to upload a backup, output tree, report, database, marker, or screenshot of
  recovered content. Reproduce failures with synthetic fixtures.
- Native diagnostics use only the fixed `RecoveryDiagnostics` event vocabulary. Never log paths,
  identifiers, filenames, titles, counts, passwords, free-form errors, helper stderr, or recovered
  content, and never add network telemetry. Unknown failures remain `unrecognized_failure`.

## Product contract

- macOS 14+ users receive the native SwiftUI workflow through the architecture-specific signed and
  notarized DMGs published in the official v0.2.0 release. End users must not need Python, iMazing,
  Homebrew, Git, or developer tools.
- `script/build_local_app.sh` remains an ad-hoc, local-only acceptance path. The controlled release
  pipeline produced and published Developer ID-signed, notarized, stapled v0.2.0 DMGs for both
  architectures. Do not describe later local candidates as published until their own release gates
  are completed.
- The Python CLI remains the free fallback with Python 3.10 through 3.13. Full encrypted-backup
  recovery is supported on macOS and Linux; Windows supports analysis and report rebuilding from an
  existing completed extraction only in this baseline.
- The canonical readable output is Markdown. Self-contained offline HTML is always produced by a
  successful full report. PDF is optional and must be omitted rather than lose or reshape recovered
  text incorrectly.
- Opening private reports can add filenames to browser/viewer history or Recent Items; user guidance
  must retain that warning.

## Python code map

- `tvtime_extractor/cli.py`: public commands, hidden password prompt, readable summaries, and exit
  handling.
- `tvtime_extractor/models.py`: UI-neutral requests, preflight results, progress events, results, and
  cooperative cancellation token.
- `tvtime_extractor/service.py`: shared preflight and recovery orchestration for CLI and native app.
- `tvtime_extractor/protocol.py`: bounded framed JSON request/control primitives, strict destination
  identity binding, separate secret-channel handling, and bounded sequenced JSON Lines events used
  by the native helper.
- `tvtime_extractor/helper_main.py`: bundled-helper handshake, request validation, progress, terminal
  events, cancellation, and safe public error mapping.
- `tvtime_extractor/extract.py`: encrypted-backup access, selected-domain copying, source
  revalidation, inventory, and extraction completion marker.
- `tvtime_extractor/analyze.py`: schema/integrity checks and normalized private CSV tables.
- `tvtime_extractor/report.py`: readable report, sanitized media tables, report staging, recovery
  marker, and atomic promotion.
- `tvtime_extractor/visual_report.py`: shared visual model plus offline HTML and fidelity-gated PDF.
- `tvtime_extractor/safety.py`: path, permissions, no-follow I/O, portable names, private writes, and
  completion-marker validation.
- `scripts/macos_helper_entry.py`: minimal PyInstaller entry point; package behavior remains in
  `tvtime_extractor/`.

The required primary domain is `AppDomain-com.tozelabs.tvshowtime`. The current analyzer expects
`Documents/DioCache.db`; optional image-cache reporting reads
`Library/Application Support/libCachedImageData.db`. Treat both schemas as version-sensitive.

## Native macOS code map

- `macos/Sources/TVTimeRecoveryCore/`: helper client and protocol decoding, no-link inherited
  destination-handle binding, recovery state machine, strict summary invariants, scoped-resource
  leases, and output validation.
- `macos/Sources/TVTimeRecoveryApp/`: SwiftUI step flow, secure password confirmation, system folder
  pickers, cancellation/quit guards, result chart, report actions, and window behavior.
- `macos/Tests/TVTimeRecoveryCoreTests/`: deterministic Swift tests with fake helpers and synthetic
  output trees.
- `macos/Bundle/`: app/helper plists, sandbox entitlements, and third-party notice.
- `macos/Package.swift` and `macos/Package.resolved`: macOS 14 SwiftPM product and locked test
  dependency.

The app and bundled helper are sandboxed. Backup access must continue to originate from the
user-selected system panel and a read-only scoped lease; native output stays in the app-managed
container. Do not replace those with broad filesystem entitlements or hard-coded user paths.

## Build and packaging map

- `script/build_macos_helper.sh`: frozen architecture-specific Python helper and dependency/privacy
  validation.
- `script/git_source_stage.py`: safe, read-only `git archive` source staging and exact
  commit-content verification for signed/notarized release builds.
- `script/build_local_app.sh`: host-architecture ad-hoc acceptance bundle; never a public artifact.
- `script/build_and_run.sh`: local build-and-launch convenience action.
- `script/macos_packaging_lib.sh`: path confinement, locking, architecture, signing, entitlement,
  Gatekeeper, and atomic-promotion helpers.
- `script/build_release_app.sh`: dual architecture release pipeline for separate Apple silicon and
  Intel DMGs; it requires real Developer ID and notarization credentials and performs no upload.
- `script/scan_macos_release.py`: rejects private recovery artifacts, private build paths, broken
  links, and escaping links.
- `script/collect_macos_licenses.py` and `script/generate_macos_release_manifest.py`: license bundle
  and per-architecture release provenance. The collector must fail closed unless every non-system
  Mach-O has one exact path/architecture/component/version/license/canonical-hash mapping before and
  after signing; native-license profiles are controlled exact inputs, never network-resolved during
  a build.
- `script/build_python_distributions.py`, `script/verify_python_release.py`, and
  `script/sdist_metadata.py`: clean-commit Git-archive staging, source-bound Python release
  manifests, extracted-artifact privacy verification, and deterministic source-archive metadata.
- `requirements*.txt` are reviewed dependency inputs; `requirements*.lock` are authoritative
  exact-transitive, hash-locked installation inputs for CI and packaging.

Never combine PyInstaller executables with `lipo`. Release packaging freezes and validates the Swift
app and Python helper separately for `arm64` and `x86_64`, then creates one DMG per architecture.

## Required quality gates

Use exact-pinned dependencies. Run all applicable gates before committing:

```text
python -m ruff check .
python -m ruff format --check .
PYTHONWARNINGS=error::ResourceWarning PYTHONDONTWRITEBYTECODE=1 \
  python -m unittest discover -s tests -v
python -I script/build_python_distributions.py \
  --source-commit "$(git rev-parse HEAD)" --outdir dist-check
python -I script/verify_python_release.py \
  --root dist-check \
  --source-commit "$(git rev-parse HEAD)" \
  --source-tree "$(git rev-parse 'HEAD^{tree}')"
python -I script/sdist_metadata.py --verify dist-check/*.tar.gz
xcrun swift-format lint --strict --recursive macos/Package.swift macos/Sources macos/Tests
swift test --package-path macos --disable-automatic-resolution
swift test --package-path macos --disable-automatic-resolution --configuration release
swift build --package-path macos --disable-automatic-resolution --configuration release
git diff --check
```

Also:

- in a fresh temporary environment, install `requirements.lock` with `--require-hashes` and
  `--only-binary=:all:`, install `requirements-source-build.lock` the same way, install the local
  project with `--no-index --no-build-isolation --no-deps`, run `pip check`, and exercise every
  command help screen;
- run the full Python test matrix on macOS and Linux for the supported boundary versions, plus the
  documented existing-extraction analysis/report subset on Windows;
- syntax-check shell and Python packaging helpers;
- build the local app after production changes, verify its exact host architecture, sandbox
  entitlements, deep/strict signature, private release scan, and clean quit behavior; and
- inspect the complete staged file list for private artifacts and generated output.

TypeScript and JavaScript gates are not applicable; the offline report contains no JavaScript.

## Release discipline

- Version 0.2.0 was published on 2026-07-20 from commit
  `42880c236c5051ed322e4bfb1477a44553215bb7`. Future releases must complete the full checklist; do
  not create a tag, upload assets, or claim availability based only on a successful local build or
  notarization run.
- A distributable Mac release requires full Xcode, Swift 6.2-compatible tooling, an Apple Silicon
  build Mac with Rosetta for dual-architecture execution, the official python.org CPython 3.13.12
  universal2 build Python matching the reviewed release-native profile, a Developer ID Application
  identity, and a configured `notarytool` Keychain profile.
- The standard python.org installer places the release Python at
  `/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13`. Verify the installer signature
  and published SHA-256 before installation, then prove that executable runs under both `arch
  -arm64` and `arch -x86_64`; do not substitute Homebrew Python for a distributable build.
- Configure notarization credentials outside the repository with `notarytool store-credentials` and
  pass only the resulting Keychain profile name to the release script. Never request, paste, log, or
  persist an Apple app-specific password in an agent command or environment file.
- Both DMGs must pass exact-architecture validation, inside-out signing, hardened runtime and sandbox
  entitlement checks, notarization, stapling, Gatekeeper assessment, privacy scanning, license
  collection, exact pre/post-sign native Mach-O license-manifest verification, release-manifest
  generation, and checksums before publication is considered.
- Intel macOS resolves the current 64-bit-inode `statfs` ABI through `statfs$INODE64`; the bare
  symbol has a legacy layout. Keep the local-volume probe architecture-aware and retain the signed
  packaged-helper smoke for both `arm64` and `x86_64`.
- Release packaging must name the reviewed full Git commit, start and finish with a clean worktree,
  execute only from a read-only `git archive` of that commit, disable automatic Swift resolution,
  rebuild helpers from hash-locked dependencies without trusting caches, and record the source
  commit/tree plus lock digests in both manifests.
- Public CI uses synthetic fixtures only. Real encrypted-backup validation stays outside the
  repository and must never become an issue attachment, test fixture, documentation example, build
  input, or release asset.
- Update README, platform guides, changelog, support policy, and release-preparation record whenever
  the app/CLI contract, output set, packaging state, or distribution state changes.
