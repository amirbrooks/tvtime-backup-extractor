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
        if show_id > 0 and episode_id > 0:
            episodes_by_show.setdefault(show_id, []).append(episode)

    shows: list[dict[str, Any]] = []
    for row in series_rows:
        tvdb_id = _integer(row.get("series_id") or row.get("show_id"))
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
            is_special = _boolean(source.get("is_special"))
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
            seasons.setdefault(_integer(source.get("season")), []).append(episode)

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
        "is_public": True,
        "movies": favorite_movies,
        "shows": favorite_shows,
    }


def _activity_csv(
    shows: Iterable[Mapping[str, Any]],
    movies: Iterable[Mapping[str, Any]],
) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(_ACTIVITY_HEADER)
    for movie in movies:
        watched_at = str(movie.get("watched_at") or "")
        writer.writerow(
            (
                movie["id"]["imdb"],
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
                writer.writerow(
                    (
                        episode["id"]["imdb"],
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
        writer.writerow(
            (
                show["id"]["imdb"],
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
    return {
        "shows.json": _json_bytes(show_values),
        "movies.json": _json_bytes(movie_values),
        "favorites.json": _json_bytes(favorite_values),
        "lists.json": _json_bytes([]),
        "activity_history.csv": _activity_csv(show_values, movie_values),
    }


def write_suite_tv_zip(path: Path, files: Mapping[str, bytes]) -> None:
    if tuple(files) != LIBERATOR_FILENAMES:
        raise ValueError("Suite TV export files do not match the Liberator schema")

    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            os.chmod(path, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            with zipfile.ZipFile(
                output,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                for name in LIBERATOR_FILENAMES:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    archive.writestr(info, files[name])
    finally:
        if descriptor >= 0:
            os.close(descriptor)
