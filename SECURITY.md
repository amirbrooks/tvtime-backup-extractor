# Security policy

## Supported source line

The 0.2.x source line is the current development baseline. No downloadable v0.2.0 macOS artifact is
currently represented as released, signed, or notarized. Locally built ad-hoc app bundles receive
best-effort development support and must not be redistributed.

## Report a vulnerability

Use GitHub's **Security → Report a vulnerability** flow so the report remains private. Do not open a
public issue or pull request with exploit details.

Never attach a real backup, password, cookie, database, manifest, cache payload, generated table,
completion marker, report, screenshot, device or account ID, hash, private URL, or local path.
Reproduce with the repository's synthetic fixtures or describe the minimum abstract conditions. If a
safe reproduction is impossible, state that without sending the sensitive artifact.

Useful safe information includes:

- affected source version or commit;
- operating system, architecture, and Python version when relevant;
- whether the affected surface is the CLI, native app, bundled helper, report generator, or release
  tooling;
- expected security boundary and observed abstract behavior; and
- a fully synthetic proof of concept.

## Scope

Relevant issues include:

- source-backup mutation or time-of-check/time-of-use bypass;
- path traversal, link/reparse traversal, unsafe overwrite, or output escape;
- credential persistence or disclosure across the app/helper protocol;
- destination path substitution, identity mismatch, or unintended descriptor inheritance across
  the app/helper boundary;
- malformed or unbounded helper frames and cancellation/termination races;
- bypass of completion-marker, atomic-promotion, or output-validation invariants;
- unintended raw-cache, manifest, identifier, URL, or report disclosure;
- HTML injection, spreadsheet-formula activation, or PDF text-integrity failure;
- macOS sandbox, entitlement, code-signing, notarization, Gatekeeper, or architecture confusion;
- dependency, CI, build-provenance, release-manifest, checksum, or artifact-integrity compromise; and
- private data or build paths embedded in a distributed bundle.

Incomplete local caches, missing titles, changed TV Time schemas, optional PDF omission for text
fidelity, and ordinary recovery limitations are support or compatibility issues unless they cross a
security boundary.

A process already executing as the same operating-system user is outside the isolation boundary: it
can read that user's private files and process memory and can race local pathname operations. The
extractor must still fail closed instead of sealing detected tampering. Reports that this invariant
was bypassed remain in scope; reports that assume unrestricted same-user access alone do not.

## Release trust boundary

A public macOS artifact must be architecture-specific, Developer ID signed, notarized, stapled,
Gatekeeper assessed, privacy scanned, license-complete, and checksum-covered. Until the project
publishes such artifacts through its official release channel, treat every downloadable app bundle
as unofficial. Do not bypass macOS trust controls to run one.

The contributor-only ad-hoc build uses a separate helper entitlement profile with library validation
disabled because ad-hoc nested code has no shared Developer Team ID. This exception exists only in
the local acceptance profile. Developer ID release builds must retain Hardened Runtime library
validation and the exact stricter production entitlements.
