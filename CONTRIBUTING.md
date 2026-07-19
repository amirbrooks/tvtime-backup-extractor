# Contributing

Contributions are welcome when they preserve the project's privacy, provenance, and fresh-output
boundaries.

## Non-negotiable data rule

Use synthetic fixtures only. Do not commit, paste, attach, quote, screenshot, or record any real
backup, recovered file, viewing title or history, timestamp, count, stable ID, hash, hostname,
username, path, profile, URL, cookie, database, manifest, completion marker, password, token, or
report. A value being redacted or from your own account does not make the surrounding artifact safe.

Never ask a reporter for private recovery output. Convert a failure into the smallest abstract
condition or add a fully invented fixture.

## Python development setup

Python 3.10 through 3.13 is supported. From the repository root:

```text
python3.13 -m venv .venv
./.venv/bin/python -m pip install --require-hashes --only-binary=:all: --requirement requirements.lock
./.venv/bin/python -m pip install --require-hashes --only-binary=:all: --requirement requirements-source-build.lock
./.venv/bin/python -m pip install --require-hashes --only-binary=:all: --requirement requirements-dev.lock
./.venv/bin/python -m pip install --no-index --no-build-isolation --no-deps .
./.venv/bin/python -m pip check
```

On Windows, use `.venv\Scripts\python.exe`. Do not add or upgrade dependencies casually. Keep exact
pins, check relevant advisories, and explain why every new dependency belongs in the trusted runtime
or build boundary.

The `requirements*.txt` files are the short review inputs; the matching `*.lock` files are the
install inputs and include every transitive dependency plus accepted wheel hashes. Regenerate locks
from the Python 3.10 support boundary, then review the complete dependency and hash diff:

```text
uv pip compile requirements.txt --python-version 3.10 --universal --only-binary=:all: --generate-hashes --no-annotate --no-header --output-file requirements.lock
uv pip compile requirements-dev.txt --python-version 3.10 --universal --only-binary=:all: --generate-hashes --no-annotate --no-header --output-file requirements-dev.lock
uv pip compile requirements.txt requirements-macos-build.txt --python-version 3.10 --universal --only-binary=:all: --generate-hashes --no-annotate --no-header --output-file requirements-macos-build.lock
uv pip compile requirements-source-build.txt --python-version 3.10 --universal --only-binary=:all: --generate-hashes --no-annotate --no-header --output-file requirements-source-build.lock
```

Re-add the explanatory header comments if the compiler replaces them. Never weaken
`--require-hashes`, add an index URL to a lock, or accept a source-built dependency in CI or helper
packaging.

## Native macOS development setup

The Swift package targets macOS 14 and uses Swift tools 6.2. Native helper packaging is narrower
than CLI support: a local app build needs same-architecture CPython 3.13.12 whose bundled
OpenSSL/mpdecimal/SQLite versions exactly match a reviewed profile in
`macos/Bundle/NativeLicenses/PROVENANCE.json`. The current Homebrew profile is local-only; release
packaging requires the official python.org CPython 3.13.12 universal2 profile.

Run the local acceptance build from the repository root:

```text
./script/build_local_app.sh
```

The output under `dist/` is host-architecture only, sandboxed, and ad-hoc signed. It is suitable for
local development and acceptance testing; it is not notarized, Gatekeeper-ready, downloadable, or a
release asset. Do not distribute it.

Because an ad-hoc signature has no Developer Team ID, this local-only profile grants the sandboxed
helper `com.apple.security.cs.disable-library-validation` so its frozen Python framework can load
while Hardened Runtime remains enabled. The production entitlement profile deliberately omits that
exception. `build_release_app.sh` verifies the stricter production profile and must never be changed
to reuse the local entitlement file. Its pre-notarization helper smoke uses a temporary Developer
ID-signed copy with an exact empty entitlement dictionary; it must never modify the release app or
grant the local library-validation exception.

`./script/build_and_run.sh` is a local convenience action. Never point development builds or tests at
a real backup inside the repository. Any authorized real-data validation must remain entirely
outside Git, issues, logs, screenshots, and build artifacts.

For an authorized local acceptance run, validate the completed private output without placing its
path in shell history or process arguments:

```text
printf '%s\n' "$PRIVATE_RUN" | ./.venv/bin/python -I script/validate_recovery_output.py
```

The validator requires the development dependencies, including `pypdf`. It reconstructs the core
title/list tables from the raw cache, rerenders the deterministic PDF and requires exact canonical
bytes before parsing it, then rechecks the sealed package. Its temporary SQLite/PDF workspace is a
private directory inside the validated encrypted output and is removed on success or failure.
Filesystem access/change times can still change during validation; do not describe every output
metadata timestamp as immutable. The validator emits only fixed gate names, aggregate counts, and a
final result. Treat even those counts as private; never copy the output into Git, CI, issues, or
release evidence.

## Required checks

Run Python lint, format, synthetic tests with strict resource warnings, and package build:

```text
./.venv/bin/python -m ruff check .
./.venv/bin/python -m ruff format --check .
PYTHONWARNINGS=error::ResourceWarning PYTHONDONTWRITEBYTECODE=1 \
  ./.venv/bin/python -m unittest discover -s tests -v
./.venv/bin/python -I script/build_python_distributions.py \
  --source-commit "$(git rev-parse HEAD)" --outdir dist-check
./.venv/bin/python -I script/verify_python_release.py \
  --root dist-check \
  --source-commit "$(git rev-parse HEAD)" \
  --source-tree "$(git rev-parse 'HEAD^{tree}')"
./.venv/bin/python -I script/sdist_metadata.py --verify dist-check/*.tar.gz
```

On macOS, run the native gates when Swift, helper, UI, packaging, or shared engine behavior changes:

```text
xcrun swift-format lint --strict --recursive macos/Package.swift macos/Sources macos/Tests
xcrun swift-format lint --strict script/validate_pdf_render.swift
swift test --package-path macos --disable-automatic-resolution
swift test --package-path macos --disable-automatic-resolution --configuration release
swift build --package-path macos --disable-automatic-resolution --configuration release
```

Also:

- in a fresh temporary environment, install `requirements.lock` with `--require-hashes` and
  `--only-binary=:all:`, install `requirements-source-build.lock` the same way, install the source
  checkout with `--no-index --no-build-isolation --no-deps`, install the built wheel with
  `--no-deps`, run `pip check`, and exercise every CLI help screen;
- exercise all CLI help screens from that installed wheel;
- run `bash -n` over shell scripts and compile-check Python packaging helpers;
- rebuild and validate the local app bundle after production changes;
- verify the bundle's `Contents/Resources/Licenses/LICENSES.json` before and after signing so every
  non-system Mach-O has one exact component/version/license mapping and stable canonical hash;
- generate the large synthetic visual-report fixture and pass its complete PDF through
  `script/validate_pdf_render.swift` on macOS;
- run `git diff --check` and inspect the full staged file list; and
- search documentation, tests, bundles, archives, and generated metadata for private paths or
  artifacts before committing.

CI runs full invented-fixture recovery on macOS and Linux for Python 3.10 through 3.13. Windows CI
checks installation plus the supported existing-extraction analysis/report and fail-closed Windows
handle contracts; it does not claim Windows fresh recovery support. Native macOS format,
debug/release test, and optimized-build jobs use exact CPython 3.13.12 and run separately. Local
gates remain required; CI is an additional check.

## Change design

- Keep the CLI and native app on the same UI-neutral recovery service rather than duplicating
  extraction logic.
- Keep helper messages bounded and privacy-safe. Do not expose dependency exceptions or absolute
  paths through the public protocol.
- Preserve source read-only access, finished-backup checks, fresh destinations, no-follow I/O,
  cancellation checkpoints, completion markers, and atomic promotion.
- Keep Markdown and offline HTML complete. Treat PDF as optional and fail closed on text fidelity.
- Preserve sandboxed user-selected folder access and strict validation of every report action.
- Update user guidance whenever command behavior, UI copy, output artifacts, space requirements, or
  release state changes.

Use focused changes and Conventional Commit prefixes such as `feat:`, `fix:`, `docs:`, `refactor:`,
and `test:`. Report security issues through [SECURITY.md](SECURITY.md), not a public pull request.

## Release changes

Read [v0.2.0 release preparation](docs/release-v0.2.0.md) before changing packaging. The release
script requires real Developer ID and notarization credentials and deliberately creates separate
Apple silicon and Intel DMGs. A successful local ad-hoc build or CI run does not authorize a tag or
asset upload.

Native-license profiles are controlled build inputs, not an automatically discovered allowlist. If
a native runtime changes, update the profile only after independently verifying the exact upstream
archive hash, release, license path, controlled extraction method, and checked-in license bytes.
Each profile also binds the exact source-controlled CPython license to the reviewed Python source
release; packaging accepts no host-provided CPython-license override. Keep that CPython record and
one exact record each for OpenSSL, mpdecimal, and SQLite, do not add unused license files, and test
both release architectures. Archive hashes document the exact reviewed upstream license-source
inputs; they do not prove binary origin. The packaged Mach-O manifest and release checksums
separately bind the built binaries.
