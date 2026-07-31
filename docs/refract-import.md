# Import recovered series into Refract on Windows

The repository includes an offline converter for the JSON series format produced by
[TV-Time-Out](https://github.com/jeremyndeby/TV-Time-Out). Its exporter writes followed shows as a
top-level JSON array in `tvtime-series-{date}.json`, with seasons and episodes nested below each
show. The converter reproduces that shape from this extractor's private analysis tables; it does
not contact TV Time, Refract, TVDB, or any other network service.

This is a best-effort conversion of recovered local cache data. The cache may not contain every
episode. Missing episodes, watch dates, identifiers, or rewatches are never invented.

## Private inputs

Use the `analysis` directory from one completed extraction. The converter reads:

- `series_library.csv` and `analysis_summary.json` (required);
- `episode_cache_unique.csv` (recommended, for recovered episode state); and
- `favorite_shows.csv` (optional, for favorite flags).

Do not move these files into this Git repository or send them to an online CSV converter. They can
contain private titles, identifiers, and viewing history. Keep both the extraction and converted
JSON on local BitLocker-protected or equivalent private storage outside cloud-sync folders.

## Convert with PowerShell

Run these commands from the repository root. Substitute the first path with your completed private
analysis directory. The `Refract-Imports` parent may be created in advance, but the final
`Refract-Series-NEW` directory must not exist: the converter creates it privately and refuses to
overwrite or merge output.

```powershell
New-Item -ItemType Directory -Force "C:\Private\Refract-Imports"

.venv\Scripts\python.exe script\convert_refract_series.py `
  --analysis "C:\Private\TVTime-Extraction\analysis" `
  --output "C:\Private\Refract-Imports\Refract-Series-NEW"
```

Using `C:\` is supported when the destination is a local NTFS volume and the selected path is not a
reparse point, cloud-sync location, network share, or Git repository. Choose another new child name
if a previous attempt already created `Refract-Series-NEW`.

On success, the new directory contains exactly one file named like:

```text
tvtime-series-2026-07-23.json
```

The normal terminal summary contains aggregate counts only. It does not print series titles,
identifiers, private paths, or recovered content.

## How fields are converted

Each `series_library.csv` row becomes one show:

| Extractor field | TV-Time-Out/Refract field |
| --- | --- |
| `uuid` | `uuid` |
| `series_id` | `id.tvdb` as an integer |
| unavailable | `id.imdb: null` |
| `created_at` | `created_at`, or `null` when blank |
| `name` | `title` |
| selected completion policy | `status: "up_to_date"` |
| matching `favorite_shows.id` | `is_favorite` |

`up_to_date` is the completion-like value emitted by
[TV-Time-Out's show normalization](https://github.com/jeremyndeby/TV-Time-Out/blob/main/background.js#L1057-L1086).
It does not mark nonexistent episodes as watched.

Episode rows are joined only when `episode_cache_unique.csv.show_id` exactly matches a converted
`series_id`. Seasons and episodes are sorted numerically. Season zero is marked as specials; `TBA`
placeholders are omitted. `seen`, `is_watched`, or a valid `seen_date` supplies watched evidence.
Valid dates are normalized to UTC as `YYYY-MM-DDTHH:MM:SSZ`.

The recovered cache does not provide a reliable rewatch ledger, so `rewatch_count` is zero and
`watched_count` is either zero or one. A series with no usable episode rows receives `seasons: []`
and `_noEpisodeData: true`. Its show status remains `up_to_date`, but no episode watch is fabricated.
The show-level `last_watch_date` is never assigned to an arbitrary episode.

The analyzer protects spreadsheet-sensitive text by adding a leading apostrophe in CSV. The
converter reads `analysis_summary.json` and removes that apostrophe only at the exact recorded cell
coordinates, preserving genuine leading apostrophes.

## Validate and import

Replace the date below with the generated filename date:

```powershell
.venv\Scripts\python.exe -m json.tool `
  "C:\Private\Refract-Imports\Refract-Series-NEW\tvtime-series-2026-07-23.json" `
  > $null
```

No output means Python accepted the JSON syntax. You can also confirm that the directory contains
only that one JSON file:

```powershell
Get-ChildItem -LiteralPath "C:\Private\Refract-Imports\Refract-Series-NEW" -Force
```

In Refract, choose the TV Time import and select only the generated `tvtime-series-{date}.json`.
Review Refract's completion summary before keeping the import. This action intentionally transfers
the converted private viewing data to Refract; the offline converter itself transfers nothing.

## Failure behavior

- Invalid or duplicate series IDs, malformed headers, invalid summary JSON, unsafe paths, and output
  collisions stop the conversion.
- Parsing and schema validation finish before the output directory is created.
- Unmatched episode and favorite rows are omitted and reported only as aggregate counts.
- Missing optional companion tables produce shows with empty seasons or non-favorite status.
- An incomplete staging file is never promoted as the Refract JSON.
- Movies and custom lists are outside this converter's scope.

The upstream exporter creates only the non-empty artifact types available for a run; its JSON file
selection is implemented in
[`buildFilesList`](https://github.com/jeremyndeby/TV-Time-Out/blob/main/exporter.js#L1097-L1108).
