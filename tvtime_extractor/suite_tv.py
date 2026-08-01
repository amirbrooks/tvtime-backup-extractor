from __future__ import annotations

import csv
import io
import json
import os
import stat
import zipfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .safety import (
    harden_private_descriptor,
    secure_file,
    windows_create_private_staging_descriptor,
)
from .spreadsheet import spreadsheet_safe_cell

LIBERATOR_FILENAMES = (
    "shows.json",
    "movies.json",
    "favorites.json",
    "lists.json",
    "activity_history.csv",
)

_ACTIVITY_HEADER = (
    "imdb_id",
    "tvdb_id",
    "type",
    "title",
    "season",
    "episode",
    "is_special",
    "is_watched",
    "watched_at",
    "status",
    "is_watchlisted",
    "rating",
)


def _text(row: Mapping[str, object], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _integer(value: object, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _boolean(value: object) -> bool:
    return str(value).strip().casefold() in {"1", "true", "yes"}


def _csv_boolean(value: bool) -> str:
    return "true" if value else "false"


def _show_status(row: Mapping[str, object]) -> str:
    recovered_statuses = [
        value.strip() for value in str(row.get("filters") or "").split("|") if value.strip()
    ]
    if recovered_statuses and recovered_statuses[-1] in {
        "stopped",
        "continuing",
        "up_to_date",
        "not_started_yet",
    }:
        return recovered_statuses[-1]
    watched = _integer(row.get("watched_episode_count"))
    aired = _integer(row.get("aired_episode_count"))
    if watched <= 0:
        return "not_started_yet"
    if aired > 0 and watched >= aired:
        return "up_to_date"
    return "continuing"


def _build_movies(rows: Iterable[Mapping[str, object]]) -> list[dict[str, Any]]:
    movies: list[dict[str, Any]] = []
    for row in rows:
        tvdb_id = _integer(row.get("tvdb_id"))
        if tvdb_id <= 0:
            continue
        movie: dict[str, Any] = {
            "id": {
                "tvdb": tvdb_id,
                "imdb": _text(row, "imdb_id") or "-1",
            },
            "uuid": _text(row, "uuid", "movie_id"),
            "title": _text(row, "name", "title"),
            "created_at": _text(
                row,
                "created_at",
                "record_created_at",
                "followed_at",
                "observed_at_utc",
            ),
            "rating": None,
            "is_watched": _boolean(row.get("is_watched")),
            "rewatch_count": _integer(row.get("rewatch_count")),
        }
        watched_at = _text(row, "watched_at")
        if watched_at and not watched_at.startswith("0001-01-01"):
            movie["watched_at"] = watched_at
        movies.append(movie)
    return movies


def _build_shows(
    series_rows: Iterable[Mapping[str, object]],
    episode_rows: Iterable[Mapping[str, object]],
    *,
    estimate_progress: bool,
) -> list[dict[str, Any]]:
    episodes_by_show: dict[int, list[Mapping[str, object]]] = {}
    for episode in episode_rows:
        show_id = _integer(episode.get("show_id"))
        episode_id = _integer(episode.get("episode_id"))
        season_number = _integer(episode.get("season"), default=-1)
        episode_number = _integer(episode.get("episode"), default=-1)
        if show_id > 0 and episode_id > 0 and season_number >= 0 and episode_number > 0:
            episodes_by_show.setdefault(show_id, []).append(episode)

    shows: list[dict[str, Any]] = []
    for row in series_rows:
        tvdb_id = _integer(row.get("series_id") or row.get("show_id"))
        if tvdb_id <= 0:
            continue
        source_episodes = episodes_by_show.get(tvdb_id, [])
        seasons: dict[int, list[dict[str, Any]]] = {}
        exact_regular_watches = 0
        for source in sorted(
            source_episodes,
            key=lambda episode: (
                _integer(episode.get("season")),
                _integer(episode.get("episode")),
                _integer(episode.get("episode_id")),
            ),
        ):
            season_number = _integer(source.get("season"))
            is_special = _boolean(source.get("is_special")) or season_number == 0
            is_watched = _boolean(source.get("is_watched")) or _boolean(source.get("seen"))
            if is_watched and not is_special:
                exact_regular_watches += 1
            episode: dict[str, Any] = {
                "number": _integer(source.get("episode")),
                "special": is_special,
                "id": {
                    "tvdb": _integer(source.get("episode_id")),
                    "imdb": "-1",
                },
                "rating": None,
                "is_watched": is_watched,
            }
            watched_at = _text(source, "watched_at", "seen_date")
            if is_watched and watched_at and not watched_at.startswith("0001-01-01"):
                episode["watched_at"] = watched_at
            seasons.setdefault(season_number, []).append(episode)

        if estimate_progress:
            remaining = max(
                0,
                _integer(row.get("watched_episode_count")) - exact_regular_watches,
            )
            for season_number in sorted(seasons):
                for episode in seasons[season_number]:
                    if remaining <= 0:
                        break
                    if episode["special"] or episode["is_watched"]:
                        continue
                    episode["is_watched"] = True
                    remaining -= 1

        title = _text(row, "name", "title")
        if not title and source_episodes:
            title = _text(source_episodes[0], "show_name")
        shows.append(
            {
                "id": {
                    "tvdb": tvdb_id,
                    "imdb": _text(row, "imdb_id") or "-1",
                },
                "uuid": _text(row, "uuid") or f"legacy-tvdb-{tvdb_id}",
                "title": title,
                "status": _show_status(row),
                "seasons": [
                    {"number": number, "episodes": seasons[number]} for number in sorted(seasons)
                ],
                "created_at": _text(
                    row,
                    "created_at",
                    "followed_at",
                    "record_created_at",
                    "observed_at_utc",
                ),
            }
        )
    return shows


def _build_favorites(
    favorite_rows: Mapping[str, Iterable[Mapping[str, object]]],
    *,
    shows: Iterable[Mapping[str, Any]],
    movies: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    movies_by_uuid = {str(movie["uuid"]): movie for movie in movies}
    shows_by_uuid = {str(show["uuid"]): show for show in shows}

    favorite_movies: list[dict[str, Any]] = []
    for favorite in favorite_rows.get("movies", ()):
        movie = movies_by_uuid.get(_text(favorite, "uuid", "movie_id"))
        if movie is None:
            continue
        favorite_movies.append(
            {
                "id": movie["id"],
                "uuid": movie["uuid"],
                "title": movie["title"],
                "created_at": movie["created_at"],
                "rating": movie["rating"],
                "added_at": _text(favorite, "added_at", "created_at") or movie["created_at"],
            }
        )

    favorite_shows: list[dict[str, Any]] = []
    for favorite in favorite_rows.get("shows", ()):
        show = shows_by_uuid.get(_text(favorite, "uuid", "series_id", "show_id"))
        if show is None:
            continue
        favorite_shows.append(
            {
                "id": show["id"],
                "uuid": show["uuid"],
                "title": show["title"],
                "seasons": show["seasons"],
                "created_at": show["created_at"],
                "added_at": _text(favorite, "added_at", "created_at") or show["created_at"],
            }
        )

    return {
        "name": "Favorites",
        "description": "Your favorite movies and shows.",
        "is_public": False,
        "movies": favorite_movies,
        "shows": favorite_shows,
    }


def _activity_csv(
    shows: Iterable[Mapping[str, Any]],
    movies: Iterable[Mapping[str, Any]],
) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")

    def write_row(values: Iterable[object]) -> None:
        writer.writerow(tuple(spreadsheet_safe_cell(value) for value in values))

    write_row(_ACTIVITY_HEADER)
    for movie in movies:
        watched_at = str(movie.get("watched_at") or "")
        imdb_id = movie["id"]["imdb"]
        write_row(
            (
                -1 if imdb_id == "-1" else imdb_id,
                movie["id"]["tvdb"],
                "movie",
                movie["title"],
                "",
                "",
                "false",
                _csv_boolean(bool(movie["is_watched"])),
                watched_at,
                "",
                _csv_boolean(not bool(watched_at)),
                "",
            )
        )
    for show in shows:
        for season in show["seasons"]:
            for episode in season["episodes"]:
                if not episode["is_watched"]:
                    continue
                watched_at = str(episode.get("watched_at") or "")
                imdb_id = episode["id"]["imdb"]
                write_row(
                    (
                        -1 if imdb_id == "-1" else imdb_id,
                        episode["id"]["tvdb"],
                        "episode",
                        show["title"],
                        season["number"],
                        episode["number"],
                        _csv_boolean(bool(episode["special"])),
                        "true",
                        watched_at,
                        show["status"],
                        _csv_boolean(not bool(watched_at)),
                        "",
                    )
                )
    for show in shows:
        has_unwatched = any(
            not episode["is_watched"]
            for season in show["seasons"]
            for episode in season["episodes"]
        )
        imdb_id = show["id"]["imdb"]
        write_row(
            (
                -1 if imdb_id == "-1" else imdb_id,
                show["id"]["tvdb"],
                "show",
                show["title"],
                "",
                "",
                "",
                "",
                "",
                show["status"],
                _csv_boolean(has_unwatched),
                "",
            )
        )
    return output.getvalue().encode("utf-8")


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")


def _exact_keys(value: Mapping[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise ValueError("Suite TV export data had an unsupported object shape")


def _positive_identifier(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError("Suite TV export data had an invalid identifier")
    return value


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Suite TV export data had an invalid text field")
    return value


def _parse_json_document(payload: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Suite TV export data contained a duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Suite TV export data was not valid JSON") from exc


def _validate_id(value: object) -> tuple[int, str]:
    if not isinstance(value, dict):
        raise ValueError("Suite TV export data had an invalid identifier object")
    _exact_keys(value, {"tvdb", "imdb"})
    return _positive_identifier(value["tvdb"]), _string(value["imdb"])


def _validate_episode(value: object) -> tuple[int, int]:
    if not isinstance(value, dict):
        raise ValueError("Suite TV export data had an invalid episode")
    required = {"number", "special", "id", "rating", "is_watched"}
    if "watched_at" in value:
        required.add("watched_at")
        _string(value["watched_at"])
    _exact_keys(value, required)
    episode_id, _imdb_id = _validate_id(value["id"])
    number = value["number"]
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        raise ValueError("Suite TV export data had an invalid episode number")
    if not isinstance(value["special"], bool) or not isinstance(value["is_watched"], bool):
        raise ValueError("Suite TV export data had an invalid episode state")
    if value["rating"] is not None:
        raise ValueError("Suite TV export data had an unsupported episode rating")
    return episode_id, number


def _validate_show(value: object) -> tuple[int, str]:
    if not isinstance(value, dict):
        raise ValueError("Suite TV export data had an invalid show")
    _exact_keys(value, {"id", "uuid", "title", "status", "seasons", "created_at"})
    show_id, _imdb_id = _validate_id(value["id"])
    uuid = _string(value["uuid"])
    _string(value["title"])
    _string(value["created_at"])
    if value["status"] not in {"stopped", "not_started_yet", "up_to_date", "continuing"}:
        raise ValueError("Suite TV export data had an invalid show status")
    if not isinstance(value["seasons"], list):
        raise ValueError("Suite TV export data had invalid show seasons")
    episode_ids: set[int] = set()
    for season in value["seasons"]:
        if not isinstance(season, dict):
            raise ValueError("Suite TV export data had an invalid season")
        _exact_keys(season, {"number", "episodes"})
        season_number = season["number"]
        if (
            not isinstance(season_number, int)
            or isinstance(season_number, bool)
            or season_number < 0
            or not isinstance(season["episodes"], list)
        ):
            raise ValueError("Suite TV export data had an invalid season")
        for episode in season["episodes"]:
            episode_id, _episode_number = _validate_episode(episode)
            if episode_id in episode_ids:
                raise ValueError("Suite TV export data had a duplicate episode identifier")
            episode_ids.add(episode_id)
    return show_id, uuid


def _validate_movie(value: object) -> tuple[int, str]:
    if not isinstance(value, dict):
        raise ValueError("Suite TV export data had an invalid movie")
    required = {"id", "uuid", "title", "created_at", "rating", "is_watched", "rewatch_count"}
    if "watched_at" in value:
        required.add("watched_at")
        _string(value["watched_at"])
    _exact_keys(value, required)
    movie_id, _imdb_id = _validate_id(value["id"])
    uuid = _string(value["uuid"])
    _string(value["title"])
    _string(value["created_at"])
    if value["rating"] is not None or not isinstance(value["is_watched"], bool):
        raise ValueError("Suite TV export data had an invalid movie state")
    rewatch_count = value["rewatch_count"]
    if not isinstance(rewatch_count, int) or isinstance(rewatch_count, bool) or rewatch_count < 0:
        raise ValueError("Suite TV export data had an invalid movie rewatch count")
    return movie_id, uuid


def validate_liberator_files(files: Mapping[str, bytes]) -> None:
    if tuple(files) != LIBERATOR_FILENAMES or any(
        not isinstance(files[name], bytes) or not files[name] for name in LIBERATOR_FILENAMES
    ):
        raise ValueError("Suite TV export files do not match the Liberator schema")

    shows = _parse_json_document(files["shows.json"])
    movies = _parse_json_document(files["movies.json"])
    favorites = _parse_json_document(files["favorites.json"])
    lists = _parse_json_document(files["lists.json"])
    if not isinstance(shows, list) or not isinstance(movies, list) or lists != []:
        raise ValueError("Suite TV export data had an unsupported root shape")

    shows_by_key: dict[tuple[int, str], Mapping[str, object]] = {}
    for show in shows:
        show_id, uuid = _validate_show(show)
        key = (show_id, uuid)
        if key in shows_by_key:
            raise ValueError("Suite TV export data had a duplicate show")
        shows_by_key[key] = show

    movies_by_key: dict[tuple[int, str], Mapping[str, object]] = {}
    for movie in movies:
        movie_id, uuid = _validate_movie(movie)
        key = (movie_id, uuid)
        if key in movies_by_key:
            raise ValueError("Suite TV export data had a duplicate movie")
        movies_by_key[key] = movie

    if not isinstance(favorites, dict):
        raise ValueError("Suite TV export data had invalid favorites")
    _exact_keys(
        favorites,
        {"name", "description", "is_public", "movies", "shows"},
    )
    if (
        favorites["name"] != "Favorites"
        or not isinstance(favorites["description"], str)
        or favorites["is_public"] is not False
        or not isinstance(favorites["movies"], list)
        or not isinstance(favorites["shows"], list)
    ):
        raise ValueError("Suite TV export data had invalid favorites")

    for favorite in favorites["movies"]:
        if not isinstance(favorite, dict):
            raise ValueError("Suite TV export data had an invalid favorite movie")
        _exact_keys(
            favorite,
            {"id", "uuid", "title", "created_at", "rating", "added_at"},
        )
        movie_id, _imdb_id = _validate_id(favorite["id"])
        uuid = _string(favorite["uuid"])
        source = movies_by_key.get((movie_id, uuid))
        if (
            source is None
            or favorite["title"] != source["title"]
            or favorite["created_at"] != source["created_at"]
            or favorite["rating"] != source["rating"]
            or not isinstance(favorite["added_at"], str)
        ):
            raise ValueError("Suite TV export data had an unbound favorite movie")

    for favorite in favorites["shows"]:
        if not isinstance(favorite, dict):
            raise ValueError("Suite TV export data had an invalid favorite show")
        _exact_keys(
            favorite,
            {"id", "uuid", "title", "seasons", "created_at", "added_at"},
        )
        show_id, _imdb_id = _validate_id(favorite["id"])
        uuid = _string(favorite["uuid"])
        source = shows_by_key.get((show_id, uuid))
        if (
            source is None
            or favorite["title"] != source["title"]
            or favorite["seasons"] != source["seasons"]
            or favorite["created_at"] != source["created_at"]
            or not isinstance(favorite["added_at"], str)
        ):
            raise ValueError("Suite TV export data had an unbound favorite show")

    if files["activity_history.csv"] != _activity_csv(shows, movies):
        raise ValueError("Suite TV export activity history did not match its JSON records")


def build_liberator_files(
    *,
    series: Iterable[Mapping[str, object]],
    movies: Iterable[Mapping[str, object]],
    favorites: Mapping[str, Iterable[Mapping[str, object]]],
    episodes: Iterable[Mapping[str, object]],
    estimate_progress: bool,
) -> dict[str, bytes]:
    movie_values = _build_movies(movies)
    show_values = _build_shows(
        series,
        episodes,
        estimate_progress=estimate_progress,
    )
    favorite_values = _build_favorites(
        favorites,
        shows=show_values,
        movies=movie_values,
    )
    files = {
        "shows.json": _json_bytes(show_values),
        "movies.json": _json_bytes(movie_values),
        "favorites.json": _json_bytes(favorite_values),
        "lists.json": _json_bytes([]),
        "activity_history.csv": _activity_csv(show_values, movie_values),
    }
    validate_liberator_files(files)
    return files


def write_suite_tv_zip(path: Path, files: Mapping[str, bytes]) -> None:
    validate_liberator_files(files)

    descriptor = (
        windows_create_private_staging_descriptor(path)
        if os.name == "nt"
        else os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    )
    try:
        harden_private_descriptor(descriptor, expected_type=stat.S_IFREG, mode=0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            with zipfile.ZipFile(
                output,
                "w",
                compression=zipfile.ZIP_STORED,
            ) as archive:
                for name in LIBERATOR_FILENAMES:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.compress_type = zipfile.ZIP_STORED
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    archive.writestr(info, files[name])
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    secure_file(path)
