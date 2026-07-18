# Changelog

All notable changes are documented here. This project follows semantic versioning.

## 0.1.0 - 2026-07-18

- Released the first public, privacy-first baseline.
- Added a tagged release with a universal installable wheel, source distribution, and checksums.
- Changed the default command output from JSON to a concise readable recovery summary; `--json`
  remains available explicitly for private local automation.
- Added privacy-safe progress stages and visible size-warning counts without printing dependency
  messages containing absolute private paths.
- Added WAL-aware private SQLite snapshots, required schema/integrity checks, and a parser
  compatibility stop before analysis output is created.
- Preserved distinct rewatches while deduplicating repeated cache pages, neutralized spreadsheet
  formulas in CSV output, tightened TV Time domain matching, and rejected nested link traversal.
- Made the readable report explicitly list every identifiable recovered title/name found locally.
- Restored a least-privilege public CI matrix for synthetic tests on macOS, Windows, and Linux plus
  local-equivalent lint, format, build, and wheel-smoke checks.
- Added a fresh-macOS onboarding path using the free Python.org installer without requiring
  Homebrew, Git, or shell activation.
- Documented source ZIP, Git, and GitHub CLI download routes, deterministic virtual-environment
  commands, Finder backup completion checks, safe device ejection, Full Disk Access recovery, and
  retry behavior.
- Clarified supported Python versions, destination-space requirements, and the exact read-only TV
  Time app-domain extraction boundary.
- Added one guided `recover` workflow plus separate `extract`, `analyze`, and `report` commands.
- Added encrypted-backup password prompting and explicit sensitive-output acknowledgement.
- Added path traversal, overlap, Git destination, symlink, overwrite, and portable-name protections.
- Made decrypted device-manifest and verbatim raw-cache retention opt-in.
- Added normalized private CSV tables and a readable report with safer URL/date/identifier handling.
- Added fully synthetic tests for extraction boundaries, privacy defaults, analysis, reporting, and
  compatibility entry points.
- Added pinned dependencies and documented local lint, test, build, and package-smoke gates.
- Replaced delivery-specific instructions with generic end-user and privacy documentation.
