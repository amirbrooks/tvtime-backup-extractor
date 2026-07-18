# Repository agent notes

## Privacy boundary

- Never add real iOS backups, TV Time output, viewing history, account/profile data, cookies,
  databases, manifests, stable IDs, device IDs, hashes, private URLs, screenshots, or local paths.
- Tests and documentation must use obviously synthetic values only. Redacting one field does not make
  a recovered artifact safe.
- Decrypted output belongs outside every Git repository on encrypted storage. `.gitignore` is a final
  guard, not a storage policy.
- Preserve secure defaults: explicit sensitive-output acknowledgement, hidden password prompt, fresh
  output, Git/overlap/symlink/traversal checks, and opt-in raw cache or decrypted manifest retention.

## Code map

- `tvtime_extractor/cli.py`: public command contract and exit handling.
- `tvtime_extractor/extract.py`: encrypted-backup access and app-container copying.
- `tvtime_extractor/analyze.py`: normalized private CSV/JSON tables.
- `tvtime_extractor/report.py`: readable report and sanitized media references.
- `tvtime_extractor/safety.py`: path, permissions, file-writing, source-ID, and URL safety primitives.
- `scripts/`: compatibility entry points; new behavior belongs in the package.
- `tests/helpers.py`: synthetic cache/database fixtures only.
- `docs/`: end-user platform, privacy, troubleshooting, and output guidance.

The expected bundle domain is `AppDomain-com.tozelabs.tvshowtime`. The current analyzer expects
`Documents/DioCache.db`; image-cache reporting optionally reads
`Library/Application Support/libCachedImageData.db`. Treat both schemas as version-sensitive.

## Quality gates

Use the pinned environment and run all applicable Python gates before committing:

```text
python -m ruff check .
python -m ruff format --check .
PYTHONWARNINGS=error::ResourceWarning PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
python -m build --no-isolation
git diff --check
```

Smoke-test the built wheel with `--no-deps` in a fresh temporary environment and verify all command
help screens. TypeScript/JavaScript gates are not applicable because this repository has no such
package.

## Release notes

- Runtime and development dependencies are exact-pinned; review advisories before changing them.
- Public CI runs the synthetic test matrix on macOS, Windows, and Linux with Python 3.10 and 3.13,
  plus lint and build checks. Run every local gate before committing; CI is an additional check.
- Version 0.1.0 is the public alpha baseline. A real encrypted-backup validation was completed
  outside the repository; its input and output must never be copied into this repository or an issue.
- Public visibility is approved only for a tree that passes the complete privacy, package, and
  release gates. Never weaken the data boundary for examples, tests, issues, or release assets.
- Release assets may contain only the clean wheel, source distribution, and their checksums; verify
  them from a fresh environment before publishing a tag.
