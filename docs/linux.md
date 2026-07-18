# Linux guide

Apple does not provide Finder, Apple Devices, or iTunes backup creation for Linux. This project can
run on Linux only when you already have an authorized encrypted iOS/iPadOS backup copied from macOS
or Windows, or when you are analyzing an extraction previously produced by this tool.

## Full recovery from an existing backup

Mount encrypted storage, copy the complete backup folder without changing its contents, and verify
that both `Manifest.plist` and `Manifest.db` are in its root. Install Python 3.10 through 3.13, then
follow the root
[quick start](../README.md#quick-start):

```text
./.venv/bin/python -m tvtime_extractor recover \
  --backup "/mnt/private/<backup-folder>" \
  --output "/mnt/private/TVTime/<new-run>" \
  --acknowledge-sensitive-output
```

LUKS or equivalent full-volume encryption is recommended. The backup and output must not overlap,
and the output must not be inside a Git repository.

## Analyze an existing extraction

If extraction was completed on another computer and the private directory was transferred using
encrypted media:

```text
./.venv/bin/python -m tvtime_extractor analyze --extraction "/mnt/private/TVTime-Extraction"
./.venv/bin/python -m tvtime_extractor report --extraction "/mnt/private/TVTime-Extraction"
```

`analyze` expects no existing `analysis` directory and refuses to mix runs. Linux cannot bypass the
need for the original backup password during extraction. Commands print readable summaries by
default; add `--json` only for an explicit private machine-readable summary.
