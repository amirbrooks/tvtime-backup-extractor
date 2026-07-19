# Output reference

A full `recover` run creates one `TVTime-Extraction` directory under a fresh private output path.
Nothing in this tree is safe to publish, even when a filename says “sanitized.”

```text
TVTime-Extraction/
├── raw/                              decrypted TV Time app-domain files
│   └── APP_DOMAIN/                   manifest-relative paths preserved per domain
├── manifest/                         empty by default
├── metadata/
│   ├── inventory.csv                 selected-file IDs, paths, sizes, and SHA-256 hashes
│   ├── summary.json                  extraction counts, warnings, and private failure details
│   ├── run_state.json                extraction checkpoint
│   └── domains.txt                   matched backup domains
└── analysis/
    ├── TVTime-Recovered-Data.md       canonical complete readable report
    ├── TVTime-Recovered-Data.html     self-contained offline visual report
    ├── TVTime-Recovered-Data.pdf      optional faithful printable report
    ├── recovery_state.json            full-recovery/report checkpoint
    ├── analysis_summary.json          parser, integrity, and table counts
    ├── cache_index.csv                 opaque cache-source index
    ├── movie_library.csv               watched and saved movies
    ├── watched_movies.csv
    ├── movie_watchlist.csv
    ├── series_library.csv
    ├── favorite_movies.csv
    ├── favorite_shows.csv
    ├── watch_events.csv                exact private event ledger
    ├── watch_events_named.csv          ledger with locally matched titles where available
    ├── episode_cache.csv
    ├── episode_cache_unique.csv
    ├── sqlite_integrity.csv
    ├── plist_key_inventory.csv
    ├── trailer_references.csv          sanitized URL references
    ├── media_url_inventory.csv         sanitized URL references
    └── image_cache_references.csv      optional image-cache catalogue
```

Exact rows depend on what remains in the local app cache. Empty tables, unnamed watch events, and
missing image references are possible. Counts are not a guarantee of account completeness because
this is local-backup recovery, not an official TV Time export.

**How to read the series count:** `Recovered series records` counts the recovered cache rows exactly;
it is not silently deduplicated by title. The readable report separately shows named versus unnamed
records and the number of distinct named series titles. Synthetic QA fixtures use arbitrary record
counts to exercise pagination and must not be compared with a real recovery.

## Human-readable reports

All three formats are generated from the same shared safe display model:

- `TVTime-Recovered-Data.md` lists every recovered series, movie, favorite, cached episode, and
  watch-event record. Each available title/name is preserved; missing names are stated rather than
  guessed.
- `TVTime-Recovered-Data.html` is the accessible primary visual report, with semantic headings,
  table captions, summary cards, charts, navigation, and readable tables. It is a
  self-contained file with a restrictive content-security policy, no JavaScript, and no remote
  media requests, so it remains useful offline.
- `TVTime-Recovered-Data.pdf` is the print-friendly companion, with a document language, charts,
  tables, an outline, and page numbering. It is not a tagged PDF; use the HTML report with
  assistive technology. The generator uses deterministic PDF metadata/content so the repository's
  acceptance validator can require exact canonical bytes and reject visual-only mutations such as
  opaque overlays before parsing the file.

The shared model gives every format the same section membership, row counts, missing-title
placeholders, watched/saved movie breakdown, named/unnamed event breakdown, and copy-size-difference
rows. For safe one-line display, control characters become spaces, surrounding whitespace is
trimmed, and whitespace runs collapse. All other recovered Unicode text is preserved. The CSV
tables remain the exact archive when display normalization matters.

The PDF is optional by design. Before writing it, the extractor checks that an embeddable font can
represent all recovered characters and that the available renderer can preserve required shaping.
If that check fails, `recovery_state.json` records the PDF as omitted and the app explains why. The
Markdown and offline HTML remain complete; no names are silently dropped to force a PDF.

The visual reports show aggregate media-reference counts but do not embed or fetch remote images or
videos. Detailed sanitized references remain in the CSV tables.

## Completion markers and atomic promotion

`metadata/run_state.json` uses the versioned v0.2 contract and begins as `incomplete`. It changes to
`complete` only after all selected
files have been processed, the extraction summary has been written, the dependency has released its
temporary decrypted material, and the finished source metadata and selected source payloads have
been revalidated.

`analysis/recovery_state.json` uses the versioned v0.2 contract. It is written with
`status: complete` in a private staging directory only
after the Markdown and HTML reports are complete and the PDF has either been generated faithfully or
explicitly omitted. It binds an exact ordered artifact set—including `metadata/domains.txt`—with
byte sizes, lowercase SHA-256 digests, aggregate extraction/analysis/report counts, and PDF presence
state. The exact bounded serialized marker bytes are read back after writing and again immediately
before the entire staged analysis directory is promoted atomically.

A successful full recovery therefore has both markers set to `complete` and has no
`.analysis-incomplete` or `.report-incomplete` staging directory. Standalone `extract` intentionally
stops after the extraction marker; it does not create a report marker.

An interruption, wrong password, source change, copy failure, disk error, or confirmed cancellation
can leave `run_state.json` marked `incomplete` or a private staging directory in place. Preserve that
output for diagnosis, do not edit its markers, and retry into a new destination. The tool refuses to
merge, resume, or overwrite runs.

## Optional high-sensitivity output

- `--include-decrypted-manifest` adds `manifest/Manifest.decrypted.db` and records its hash. The file
  exposes device-wide backup metadata and is not needed for normal TV Time recovery.
- `--include-raw-cache` adds `analysis/cache_responses/` containing verbatim JSON or binary cache
  payloads under opaque filenames. These payloads may identify an account or installation.

Both options are off by default and are intended only for private advanced analysis. They are
available on the separate `extract` and `analyze` commands, not the sealed `recover` workflow, and
an analysis containing either advanced export cannot be promoted to a native-validated report.

## CSV behavior

CSV files preserve exact private timestamps and identifiers needed for a faithful personal archive.
Cells that could be interpreted as spreadsheet formulas are prefixed safely when written. The
coordinates of those escaped cells are recorded in `analysis_summary.json`, allowing the report
builder to reverse only those exact escapes when it reconstructs readable text.

Opening a CSV in spreadsheet software can create Recent Items, autosave, cache, or sync copies.
Import it only in a private local application and never upload it to an online spreadsheet service.

## Permissions and sensitivity

On POSIX systems the extractor uses private permissions where available: directories are created for
the owner and regular output files are owner-readable and owner-writable. These permissions do not
replace FileVault, BitLocker, LUKS, or volume encryption.

Sanitized URL tables remove common credentials, fragments, and nonessential query parameters, but
titles, dates, counts, filenames, stable identifiers, relationships, and remaining hosts can still
identify a person. No output file is intended for GitHub, public issues, analytics ingestion, cloud
document conversion, or a public release asset.
