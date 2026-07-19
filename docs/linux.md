# Linux guide

Linux uses the free Python CLI. Apple does not provide Finder, Apple Devices, or iTunes backup
creation for Linux, so start only with an authorized completed encrypted backup copied intact from
macOS or Windows, or with a private extraction previously created by this tool.

## Full recovery from an existing backup

Mount LUKS-protected or equivalent encrypted storage. Copy the complete backup folder without
changing its contents and confirm that `Manifest.plist`, `Manifest.db`, and the finished backup
status remain at its root.

Install an explicitly selected Python 3.10 through 3.13. The example prefers 3.13 so an unqualified
launcher cannot silently select unsupported Python 3.14. Download the repository as a source ZIP,
or clone it if Git is already present. From the project directory:

```text
python3.13 -m venv .venv
./.venv/bin/python -m pip install --require-hashes --only-binary=:all: --requirement requirements.lock
./.venv/bin/python -m pip install --require-hashes --only-binary=:all: --requirement requirements-source-build.lock
./.venv/bin/python -m pip install --no-index --no-build-isolation --no-deps .
./.venv/bin/python -m pip check
./.venv/bin/python -m tvtime_extractor --version
```

Choose a fresh destination outside the backup and every Git repository. Create its immediate parent
first, but do not create the new run path itself, then run:

```text
./.venv/bin/python -m tvtime_extractor recover \
  --backup "/mnt/private/DEVICE_BACKUP" \
  --output "/mnt/private/TVTime/NEW_RUN" \
  --acknowledge-sensitive-output
```

The CLI opens and holds the exact immediate parent, completes and displays the full read-only
preflight, and only then shows the hidden prompt for the original encrypted-backup password. The
fresh run stays rooted in a held directory identity through extraction, analysis, and reports. Do
not include the password in the command or a support request.

### Destination filesystem checks

Linux accepts only a conservative allowlist of ordinary local filesystems suitable for common
LUKS-backed storage. FUSE, network, cloud, shared, virtual-machine shared-folder, overlay, temporary,
and unknown filesystem types are refused with no command-line override. Ambiguous stacked mounts
at the selected mountpoint are also refused. Move the private destination to a directly mounted,
locally encrypted filesystem before retrying.

The initial manifest-processing preflight checks for the larger of 512 MiB or twice the source
`Manifest.db` size; that floor is not the full recovery requirement. After selection, required free
space is selected declared bytes plus the largest selected encrypted source payload staging snapshot,
plus the larger of 64 MiB or 10% of selected bytes, plus a retained `Manifest.db` only when the
advanced option is enabled. The post-retention check omits that already-retained manifest allowance
but still includes the largest staging snapshot. The destination does not need another full
device-backup copy.

## Analyze an existing extraction

If a complete private extraction was transferred using encrypted media, preserve its directory tree
and extraction marker. The separate advanced commands are:

```text
./.venv/bin/python -m tvtime_extractor analyze --extraction "/mnt/private/TVTime-Extraction"
./.venv/bin/python -m tvtime_extractor report --extraction "/mnt/private/TVTime-Extraction"
```

`analyze` refuses an extraction without a trustworthy complete `metadata/run_state.json` and refuses
an existing analysis directory. `report` similarly refuses mixed or overwritten report output.

A successful full recovery creates complete Markdown and offline HTML reports plus an optional PDF
when its text can be rendered faithfully. Validate both completion markers and the readable names,
then keep the source backup until satisfied. Commands print readable summaries by default; add
`--json` only for explicit private local automation.

See the [output reference](output-reference.md), [privacy guide](privacy.md), and
[troubleshooting guide](troubleshooting.md).
