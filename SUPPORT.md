# Support

This is a community, best-effort alpha project. It is not affiliated with TV Time or Apple and does
not provide account recovery, password recovery, data restoration, or legal advice.

The current supported development baseline is source version 0.2.0. The controlled release pipeline
has validated local Developer ID-signed, notarized, stapled macOS candidates for both architectures,
but no v0.2.0 tag, public release, or downloadable DMG is currently offered. Do not request help
bypassing Gatekeeper for an unofficial or locally shared app.

Before opening an issue, read the platform guide, [privacy guide](docs/privacy.md),
[output reference](docs/output-reference.md), and [troubleshooting guide](docs/troubleshooting.md).
Search existing issues without pasting private data.

A safe support request may include:

- application or `tvtime-extractor --version` output;
- operating system and Mac architecture, or Python version for CLI use;
- the workflow stage or CLI subcommand and exit code;
- whether the expected extraction/report completion marker was absent, incomplete, or complete,
  without attaching the marker;
- a paraphrased error with all usernames, paths, IDs, titles, dates, URLs, hashes, and real counts
  replaced by clearly synthetic placeholders; and
- a reproduction built only from the repository's invented fixtures.

Never upload a backup or generated output. Maintainers will not request passwords, cookies,
manifests, databases, raw cache payloads, account profiles, reports, tables, markers, private logs, or
screenshots of viewing history.

Opening reports can add their private filenames to browser/viewer history or Recent Items. That is a
local privacy consideration, not information to include in an issue. See
[Reports, browsers, and Recent Items](docs/privacy.md#reports-browsers-and-recent-items).

Security-boundary problems belong in the private process described in
[SECURITY.md](SECURITY.md). Missing or unnamed local-cache data and PDF omission for character
fidelity are compatibility/support topics unless they expose or corrupt data outside the documented
boundary.
