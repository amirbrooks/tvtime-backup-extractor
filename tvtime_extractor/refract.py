from __future__ import annotations

import csv
import io
import json
import os
import secrets
import stat
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .errors import (
    OutputExistsError,
    TVTimeError,
    UserInputError,
    insufficient_space_error,
    is_insufficient_space_error,
)
from .safety import (
    anchored_bound_output_root,
    anchored_existing_extraction_root,
    create_private_file_descriptor,
    harden_private_descriptor,
    held_destination_parent,
    is_within,
    nearest_git_root,
    no_link_absolute_path,
    promote_open_file_no_replace_atomic,
    read_json_regular,
    read_regular_bytes,
    require_private_local_destination,
)

MAXIMUM_ANALYSIS_CSV_BYTES = 64 * 1024 * 1024
MAXIMUM_ANALYSIS_CSV_ROWS = 100_000
MAXIMUM_ANALYSIS_CSV_CELL_BYTES = 8 * 1024 * 1024
MAXIMUM_ANALYSIS_CSV_ROW_BYTES = 16 * 1024 * 1024
MAXIMUM_CSV_ESCAPE_ENTRIES = 100_000
MAXIMUM_ANALYSIS_SUMMARY_BYTES = 16 * 1024 * 1024

SERIES_FIELDS = (
    "uuid",
    "series_id",
    "name",
    "country",
    "is_ended",
    "followed_at",
    "last_watch_date",
    "filters",
    "created_at",
    "updated_at",
)
EPISODE_FIELDS = (
    "source_id",
    "episode_id",
    "show_id",
    "show_name",
    "season",
    "episode",
    "episode_name",
    "air_date",
    "seen",
    "seen_date",
    "is_watched",
    "runtime",
)
FAVORITE_FIELDS = (
    "uuid",
    "id",
    "name",
    "type",
    "status",
    "created_at",
    "watched_episode_count",
    "aired_episode_count",
    "is_followed",
    "is_up_to_date",
)

_SERIES_FILENAME = "series_library.csv"
_EPISODE_FILENAME = "episode_cache_unique.csv"
_FAVORITE_FILENAME = "favorite_shows.csv"
_SUMMARY_FILENAME = "analysis_summary.json"
_TRUE_VALUES = frozenset({"1", "true", "yes", "y"})


class RefractConversionError(UserInputError):
    """A content-free failure while converting private analysis tables."""


@dataclass(frozen=True)
class RefractConversionStats:
    series: int
    episodes: int
    unmatched_episode_rows: int
    ignored_episode_rows: int
    unmatched_favorite_rows: int


@dataclass(frozen=True)
class RefractConversionResult:
    output_file: Path
    stats: RefractConversionStats


def _optional_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value if value else None


def _positive_integer(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or not text.isdecimal():
        return None
    result = int(text, 10)
    return result if result > 0 else None


def _nonnegative_integer(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or not text.isdecimal():
        return None
    return int(text, 10)


def _boolean(value: object) -> bool:
    return isinstance(value, str) and value.strip().casefold() in _TRUE_VALUES


def _normalized_watch_date(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if len(text) < 19:
        return None
    candidate = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _file_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RefractConversionError(
            "A private Refract conversion input could not be inspected safely."
        ) from exc
    return True


def _validated_escape_metadata(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RefractConversionError(
            "The private analysis summary had unsupported CSV escape metadata."
        )
    entries = 0
    for filename, items in value.items():
        if (
            not isinstance(filename, str)
            or not filename
            or len(filename.encode("utf-8")) > 1_024
            or not isinstance(items, list)
        ):
            raise RefractConversionError(
                "The private analysis summary had unsupported CSV escape metadata."
            )
        entries += len(items)
        if entries > MAXIMUM_CSV_ESCAPE_ENTRIES:
            raise RefractConversionError(
                "The private analysis summary had unsupported CSV escape metadata."
            )
        for item in items:
            if not isinstance(item, dict) or set(item) != {"row", "field"}:
                raise RefractConversionError(
                    "The private analysis summary had unsupported CSV escape metadata."
                )
            row_number = item.get("row")
            field = item.get("field")
            if (
                not isinstance(row_number, int)
                or isinstance(row_number, bool)
                or row_number < 1
                or row_number > MAXIMUM_ANALYSIS_CSV_ROWS
                or not isinstance(field, str)
                or not field
                or len(field.encode("utf-8")) > 1_024
            ):
                raise RefractConversionError(
                    "The private analysis summary had unsupported CSV escape metadata."
                )
    return value


def _escape_metadata(analysis: Path) -> dict[str, object]:
    try:
        summary = read_json_regular(
            analysis / _SUMMARY_FILENAME,
            maximum_bytes=MAXIMUM_ANALYSIS_SUMMARY_BYTES,
            require_private=True,
        )
    except (TVTimeError, OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise RefractConversionError(
            "The private analysis summary was unavailable or had unsupported JSON."
        ) from exc
    if not isinstance(summary, dict):
        raise RefractConversionError("The private analysis summary had an unsupported format.")
    return _validated_escape_metadata(summary.get("csv_spreadsheet_escaped_cells"))


def _read_csv(
    path: Path,
    fields: tuple[str, ...],
    escaped_cells: object,
) -> list[dict[str, str]]:
    if not isinstance(escaped_cells, list):
        raise RefractConversionError(
            "The private analysis summary had unsupported CSV escape metadata."
        )
    try:
        payload = read_regular_bytes(
            path,
            maximum_bytes=MAXIMUM_ANALYSIS_CSV_BYTES,
            require_private=True,
        )
        text = payload.decode("utf-8")
    except (TVTimeError, OSError, UnicodeError) as exc:
        raise RefractConversionError(
            "A private Refract conversion table could not be read safely."
        ) from exc
    try:
        if any(
            len(line.encode("utf-8")) > MAXIMUM_ANALYSIS_CSV_ROW_BYTES
            for line in text.splitlines(keepends=True)
        ):
            raise RefractConversionError(
                "A private Refract conversion table exceeded its safe row limit."
            )
    except UnicodeError as exc:
        raise RefractConversionError(
            "A private Refract conversion table contained invalid Unicode text."
        ) from exc

    rows: list[dict[str, str]] = []
    previous_field_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(MAXIMUM_ANALYSIS_CSV_CELL_BYTES + 1)
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if tuple(reader.fieldnames or ()) != fields:
            raise RefractConversionError(
                "A private Refract conversion table had an unsupported header."
            )
        for row in reader:
            if len(rows) >= MAXIMUM_ANALYSIS_CSV_ROWS:
                raise RefractConversionError(
                    "A private Refract conversion table exceeded its safe row limit."
                )
            if None in row or any(value is None for value in row.values()):
                raise RefractConversionError(
                    "A private Refract conversion table had an unsupported row shape."
                )
            converted = {field: str(row[field]) for field in fields}
            cell_sizes = [len(value.encode("utf-8")) for value in converted.values()]
            if (
                any(size > MAXIMUM_ANALYSIS_CSV_CELL_BYTES + 1 for size in cell_sizes)
                or sum(cell_sizes) > MAXIMUM_ANALYSIS_CSV_ROW_BYTES
            ):
                raise RefractConversionError(
                    "A private Refract conversion table exceeded its safe cell limit."
                )
            rows.append(converted)
    except csv.Error as exc:
        raise RefractConversionError(
            "A private Refract conversion table had unsupported CSV data."
        ) from exc
    finally:
        csv.field_size_limit(previous_field_limit)

    seen: set[tuple[int, str]] = set()
    for item in escaped_cells:
        assert isinstance(item, dict)
        row_number = item["row"]
        field = item["field"]
        assert isinstance(row_number, int)
        assert isinstance(field, str)
        coordinate = (row_number, field)
        if coordinate in seen or row_number > len(rows) or field not in rows[row_number - 1]:
            raise RefractConversionError("The private CSV escape metadata did not match its table.")
        value = rows[row_number - 1][field]
        if (
            not value.startswith("'")
            or len(value) < 2
            or not value[1:].startswith(("=", "+", "-", "@", "\t", "\r"))
        ):
            raise RefractConversionError("The private CSV escape metadata did not match its table.")
        rows[row_number - 1][field] = value[1:]
        seen.add(coordinate)
    return rows


def _read_table(
    analysis: Path,
    filename: str,
    fields: tuple[str, ...],
    escape_metadata: dict[str, object],
    *,
    required: bool,
) -> list[dict[str, str]]:
    path = analysis / filename
    if not _file_exists(path):
        if required:
            raise RefractConversionError("A required private Refract conversion table was absent.")
        return []
    return _read_csv(path, fields, escape_metadata.get(filename, []))


def _episode_from_row(row: dict[str, str]) -> tuple[int, int, dict[str, Any]] | None:
    episode_id = _positive_integer(row.get("episode_id"))
    season_number = _nonnegative_integer(row.get("season"))
    episode_number = _nonnegative_integer(row.get("episode"))
    name = _optional_text(row.get("episode_name"))
    if (
        episode_id is None
        or season_number is None
        or episode_number is None
        or (name is not None and name.strip().upper() == "TBA")
    ):
        return None
    watched_at = _normalized_watch_date(row.get("seen_date"))
    watched = _boolean(row.get("seen")) or _boolean(row.get("is_watched")) or bool(watched_at)
    episode = {
        "id": {"tvdb": episode_id, "imdb": None},
        "number": episode_number,
        "name": name,
        "special": season_number == 0,
        "is_watched": watched,
        "watched_at": watched_at,
        "rewatch_count": 0,
        "watched_count": 1 if watched else 0,
    }
    return season_number, episode_number, episode


def _group_episodes(
    rows: list[dict[str, str]],
    series_ids: set[int],
) -> tuple[dict[int, list[dict[str, Any]]], int, int]:
    positioned: dict[int, dict[tuple[int, int], dict[str, Any] | None]] = defaultdict(dict)
    unmatched = 0
    ignored = 0
    for row in rows:
        show_id = _positive_integer(row.get("show_id"))
        if show_id is None or show_id not in series_ids:
            unmatched += 1
            continue
        converted = _episode_from_row(row)
        if converted is None:
            ignored += 1
            continue
        season_number, episode_number, episode = converted
        position = (season_number, episode_number)
        previous = positioned[show_id].get(position)
        if previous is None and position in positioned[show_id]:
            ignored += 1
            continue
        if previous is not None:
            previous_id = previous["id"]["tvdb"]
            current_id = episode["id"]["tvdb"]
            if previous_id != current_id:
                positioned[show_id][position] = None
                ignored += 2
                continue
            previous_rank = (bool(previous["is_watched"]), previous["watched_at"] or "")
            current_rank = (bool(episode["is_watched"]), episode["watched_at"] or "")
            if current_rank >= previous_rank:
                positioned[show_id][position] = episode
            ignored += 1
            continue
        positioned[show_id][position] = episode

    grouped: dict[int, list[dict[str, Any]]] = {}
    for show_id, by_position in positioned.items():
        seasons: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for (season_number, _episode_number), episode in sorted(by_position.items()):
            if episode is not None:
                seasons[season_number].append(episode)
        grouped[show_id] = [
            {
                "number": season_number,
                "is_specials": season_number == 0,
                "episodes": episodes,
            }
            for season_number, episodes in sorted(seasons.items())
        ]
    return grouped, unmatched, ignored


def _favorite_ids(rows: list[dict[str, str]], series_ids: set[int]) -> tuple[set[int], int]:
    matched: set[int] = set()
    unmatched = 0
    for row in rows:
        favorite_id = _positive_integer(row.get("id"))
        if favorite_id is None or favorite_id not in series_ids:
            unmatched += 1
        else:
            matched.add(favorite_id)
    return matched, unmatched


def _validate_payload(payload: object) -> None:
    if not isinstance(payload, list) or not payload:
        raise RefractConversionError("No convertible series were present in the private table.")
    for show in payload:
        if not isinstance(show, dict) or set(show) != {
            "uuid",
            "id",
            "created_at",
            "title",
            "status",
            "is_favorite",
            "_noEpisodeData",
            "seasons",
        }:
            raise RefractConversionError("The generated Refract series data was invalid.")
        identifier = show.get("id")
        if (
            not isinstance(identifier, dict)
            or set(identifier) != {"tvdb", "imdb"}
            or not isinstance(identifier.get("tvdb"), int)
            or identifier.get("imdb") is not None
            or show.get("status") != "up_to_date"
            or not isinstance(show.get("is_favorite"), bool)
            or not isinstance(show.get("_noEpisodeData"), bool)
            or not isinstance(show.get("seasons"), list)
        ):
            raise RefractConversionError("The generated Refract series data was invalid.")
        for season in show["seasons"]:
            if (
                not isinstance(season, dict)
                or set(season) != {"number", "is_specials", "episodes"}
                or not isinstance(season.get("number"), int)
                or not isinstance(season.get("is_specials"), bool)
                or not isinstance(season.get("episodes"), list)
            ):
                raise RefractConversionError("The generated Refract episode data was invalid.")
            for episode in season["episodes"]:
                if (
                    not isinstance(episode, dict)
                    or set(episode)
                    != {
                        "id",
                        "number",
                        "name",
                        "special",
                        "is_watched",
                        "watched_at",
                        "rewatch_count",
                        "watched_count",
                    }
                    or not isinstance(episode.get("number"), int)
                    or not isinstance(episode.get("special"), bool)
                    or not isinstance(episode.get("is_watched"), bool)
                    or episode.get("rewatch_count") != 0
                    or episode.get("watched_count") not in {0, 1}
                ):
                    raise RefractConversionError("The generated Refract episode data was invalid.")


def _build_payload_from_analysis(
    analysis: Path,
) -> tuple[list[dict[str, Any]], RefractConversionStats]:
    metadata = _escape_metadata(analysis)
    series_rows = _read_table(
        analysis,
        _SERIES_FILENAME,
        SERIES_FIELDS,
        metadata,
        required=True,
    )
    episode_rows = _read_table(
        analysis,
        _EPISODE_FILENAME,
        EPISODE_FIELDS,
        metadata,
        required=False,
    )
    favorite_rows = _read_table(
        analysis,
        _FAVORITE_FILENAME,
        FAVORITE_FIELDS,
        metadata,
        required=False,
    )

    by_id: dict[int, dict[str, str]] = {}
    for row in series_rows:
        series_id = _positive_integer(row.get("series_id"))
        if series_id is None or series_id in by_id:
            raise RefractConversionError(
                "The private series table contained an invalid or duplicate series ID."
            )
        by_id[series_id] = row
    if not by_id:
        raise RefractConversionError("No convertible series were present in the private table.")

    series_ids = set(by_id)
    episodes_by_show, unmatched_episodes, ignored_episodes = _group_episodes(
        episode_rows, series_ids
    )
    favorites, unmatched_favorites = _favorite_ids(favorite_rows, series_ids)

    payload: list[dict[str, Any]] = []
    episode_count = 0
    for series_id, row in by_id.items():
        seasons = episodes_by_show.get(series_id, [])
        episode_count += sum(len(season["episodes"]) for season in seasons)
        payload.append(
            {
                "uuid": _optional_text(row.get("uuid")),
                "id": {"tvdb": series_id, "imdb": None},
                "created_at": _optional_text(row.get("created_at")),
                "title": _optional_text(row.get("name")),
                "status": "up_to_date",
                "is_favorite": series_id in favorites,
                "_noEpisodeData": not seasons,
                "seasons": seasons,
            }
        )
    payload.sort(key=lambda item: ((item["title"] or "").casefold(), item["id"]["tvdb"]))
    _validate_payload(payload)
    try:
        encoded = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        if json.loads(encoded) != payload:
            raise ValueError("JSON round-trip mismatch")
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise RefractConversionError("The generated Refract JSON was invalid.") from exc
    return payload, RefractConversionStats(
        series=len(payload),
        episodes=episode_count,
        unmatched_episode_rows=unmatched_episodes,
        ignored_episode_rows=ignored_episodes,
        unmatched_favorite_rows=unmatched_favorites,
    )


def _validated_analysis_path(path: Path) -> Path:
    analysis = no_link_absolute_path(path)
    try:
        metadata = analysis.lstat()
    except OSError as exc:
        raise RefractConversionError("The private analysis directory was unavailable.") from exc
    if not stat.S_ISDIR(metadata.st_mode) or analysis.is_symlink():
        raise RefractConversionError("The private analysis directory was unsafe.")
    if nearest_git_root(analysis) is not None:
        raise RefractConversionError(
            "Refusing to read private recovered data from inside a Git repository."
        )
    return analysis


def build_refract_series_payload(
    analysis_directory: Path,
) -> tuple[list[dict[str, Any]], RefractConversionStats]:
    """Read private analysis tables and build a validated TV-Time-Out series payload."""

    analysis = _validated_analysis_path(analysis_directory)
    extraction_root = analysis.parent
    with anchored_existing_extraction_root(extraction_root) as anchored_extraction:
        anchored_analysis = anchored_extraction / analysis.name
        return _build_payload_from_analysis(anchored_analysis)


def _validated_output_path(analysis: Path, output_directory: Path) -> Path:
    output = no_link_absolute_path(output_directory)
    require_private_local_destination(output)
    if output.exists() or output.is_symlink():
        raise OutputExistsError(
            "The Refract output directory already exists. Choose a new private directory."
        )
    if is_within(output, analysis) or is_within(analysis, output):
        raise RefractConversionError("The private analysis and Refract output must not overlap.")
    if nearest_git_root(output) is not None:
        raise RefractConversionError(
            "Refusing to place private Refract import data inside a Git repository."
        )
    return output


def _write_payload(root: Path, filename: str, payload: list[dict[str, Any]]) -> None:
    final_path = root / filename
    staging_path = root / f".{filename}.{secrets.token_hex(8)}.partial"
    encoded = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    descriptor = -1
    try:
        descriptor = create_private_file_descriptor(staging_path, exclusive=True)
        opened = harden_private_descriptor(
            descriptor,
            expected_type=stat.S_IFREG,
            mode=0o600,
        )
        remaining = memoryview(encoded)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short private Refract JSON write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        identity = (int(after.st_dev), int(after.st_ino))
        if identity != (int(opened.st_dev), int(opened.st_ino)):
            raise RefractConversionError("The private Refract staging file changed unexpectedly.")
        promote_open_file_no_replace_atomic(
            descriptor,
            staging_path,
            final_path,
            expected_identity=identity,
            durable=True,
        )
    except OSError as exc:
        if is_insufficient_space_error(exc):
            raise insufficient_space_error() from exc
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def convert_refract_series(
    *,
    analysis_directory: Path,
    output_directory: Path,
    export_date: date | None = None,
) -> RefractConversionResult:
    """Convert recovered analysis tables into one fresh private Refract series artifact."""

    analysis = _validated_analysis_path(analysis_directory)
    output = _validated_output_path(analysis, output_directory)
    payload, stats = build_refract_series_payload(analysis)
    filename = f"tvtime-series-{(export_date or date.today()).isoformat()}.json"
    with (
        held_destination_parent(output) as (parent_handle, parent_identity, visible_output),
        anchored_bound_output_root(
            visible_output,
            destination_parent_descriptor=parent_handle,
            expected_parent_identity=parent_identity,
        ) as anchored_output,
    ):
        _write_payload(anchored_output, filename, payload)
    return RefractConversionResult(output_file=output / filename, stats=stats)
