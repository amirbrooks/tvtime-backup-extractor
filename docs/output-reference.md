# Output reference

`recover` creates one `TVTime-Extraction` directory under the new output path.

```text
TVTime-Extraction/
├── raw/                         decrypted TV Time app-domain files
├── manifest/                    empty by default
├── metadata/
│   ├── inventory.csv            private file inventory and hashes
│   ├── summary.json             extraction counts and private failure details
│   ├── run_state.json           `complete` only after the extraction checkpoint
│   └── domains.txt              matched backup domains
└── analysis/
    ├── TVTime-Recovered-Data.md readable private report
    ├── analysis_summary.json    parser and integrity counts
    ├── cache_index.csv          opaque cache-source index
    ├── movie_library.csv        watched and saved movies
    ├── watched_movies.csv
    ├── movie_watchlist.csv
    ├── series_library.csv
    ├── favorite_movies.csv
    ├── favorite_shows.csv
    ├── watch_events.csv         exact private event ledger
    ├── watch_events_named.csv
    ├── episode_cache.csv
    ├── episode_cache_unique.csv
    ├── sqlite_integrity.csv
    ├── plist_key_inventory.csv
    ├── trailer_references.csv   sanitized URLs
    ├── media_url_inventory.csv  sanitized URLs
    └── image_cache_references.csv
```

Exact rows depend on what remains in the local app cache; empty tables are possible. Counts are not a
guarantee of account completeness because this is local-backup recovery, not an official account
export.

## Optional output

- `--include-decrypted-manifest` adds `manifest/Manifest.decrypted.db` and its hash. This includes
  device-wide backup metadata and is highly sensitive.
- `--include-raw-cache` adds `analysis/cache_responses/` with verbatim JSON or binary cache payloads
  under opaque filenames. These payloads may identify the account or installation.

## Sensitivity

Every directory above is private. Sanitized URL tables remove common URL secrets, but filenames,
titles, dates, counts, stable identifiers, and relationships can still identify a person. No output
file is intended for GitHub, public issues, or analytics ingestion.
