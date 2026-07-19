from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path

FORBIDDEN_NAMES = {
    "DioCache.db",
    "Manifest.plist",
    "Status.plist",
    "TVTime-Recovered-Data.html",
    "TVTime-Recovered-Data.pdf",
    "Manifest.decrypted.db",
    "Manifest.db",
    "TVTime-Recovered-Data.md",
    "TVTime-Validation-Full-List.md",
    "analysis_summary.json",
    "cache_index.csv",
    "episode_cache.csv",
    "episode_cache_unique.csv",
    "favorite_movies.csv",
    "favorite_shows.csv",
    "image_cache_references.csv",
    "inventory.csv",
    "libCachedImageData.db",
    "media_url_inventory.csv",
    "movie_library.csv",
    "movie_watchlist.csv",
    "plist_key_inventory.csv",
    "profile_and_settings.json",
    "recovery_state.json",
    "run_state.json",
    "series_library.csv",
    "sqlite_integrity.csv",
    "summary.json",
    "trailer_references.csv",
    "watch_events.csv",
    "watch_events_named.csv",
    "watched_movies.csv",
}
FORBIDDEN_DIRECTORY_NAMES = {
    ".analysis-incomplete",
    ".report-incomplete",
    ".tmp",
    "TVTime-Extraction",
    "analysis",
    "cache_responses",
    "manifest",
    "metadata",
    "raw",
}
FORBIDDEN_FILE_SUFFIXES = (
    ".binarycookies",
    ".csv",
    ".db",
    ".db-journal",
    ".db-shm",
    ".db-wal",
    ".partial",
    ".sqlite",
    ".sqlite3",
)
FORBIDDEN_NAMES_CASEFOLDED = frozenset(name.casefold() for name in FORBIDDEN_NAMES)
FORBIDDEN_DIRECTORY_NAMES_CASEFOLDED = frozenset(
    name.casefold() for name in FORBIDDEN_DIRECTORY_NAMES
)


def encoded_needles(value: str) -> tuple[bytes, ...]:
    return (
        value.encode("utf-8"),
        value.encode("utf-16-le"),
        value.encode("utf-16-be"),
    )


def contains_value(path: Path, needles: tuple[bytes, ...]) -> bool:
    maximum = max((len(needle) for needle in needles), default=0)
    overlap = b""
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                block = overlap + chunk
                if any(needle in block for needle in needles):
                    return True
                overlap = block[-maximum:] if maximum else b""
    except OSError:
        raise RuntimeError("Release tree contains an unreadable regular file") from None
    return False


def validate_symlink(root: Path, path: Path) -> None:
    try:
        target = (path.parent / os.readlink(path)).resolve(strict=True)
    except (OSError, RuntimeError):
        raise RuntimeError("Release tree contains a broken or unreadable symbolic link") from None
    if root != target and root not in target.parents:
        raise RuntimeError("Release tree contains an escaping symbolic link")


def entry_mode(path: Path) -> int:
    try:
        return path.lstat().st_mode
    except OSError:
        raise RuntimeError("Release tree entry metadata could not be read") from None


def fail_walk_closed(_error: OSError) -> None:
    raise RuntimeError("Release tree could not be traversed safely") from None


def walk_release_tree(root: Path):
    yield from os.walk(root, followlinks=False, onerror=fail_walk_closed)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--forbidden-value", action="append", default=[])
    arguments = parser.parse_args()

    root = arguments.root.resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("Release scan root must be a directory")
    values = [value for value in arguments.forbidden_value if value]
    needles = tuple(needle for value in values for needle in encoded_needles(value))
    regular_file_count = 0

    for current, directory_names, file_names in walk_release_tree(root):
        current_path = Path(current)
        for directory_name in directory_names:
            directory = current_path / directory_name
            mode = entry_mode(directory)
            if stat.S_ISLNK(mode):
                validate_symlink(root, directory)
            elif not stat.S_ISDIR(mode):
                raise RuntimeError("Release tree contains an unexpected non-directory entry")
            if directory_name.casefold() in FORBIDDEN_DIRECTORY_NAMES_CASEFOLDED:
                raise RuntimeError("Release tree contains a forbidden private-output directory")
        for file_name in file_names:
            path = current_path / file_name
            lowered_name = file_name.casefold()
            if lowered_name in FORBIDDEN_NAMES_CASEFOLDED or lowered_name.endswith(
                FORBIDDEN_FILE_SUFFIXES
            ):
                raise RuntimeError("Release tree contains a forbidden private-output file")
            mode = entry_mode(path)
            if stat.S_ISLNK(mode):
                validate_symlink(root, path)
                continue
            if not stat.S_ISREG(mode):
                raise RuntimeError("Release tree contains an unexpected non-regular entry")
            regular_file_count += 1
            if contains_value(path, needles):
                raise RuntimeError("Release artifact contains a prohibited private build path")

    if regular_file_count == 0:
        raise RuntimeError("Release tree contained no regular files")
    print(f"Release privacy scan passed for {regular_file_count} regular files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
