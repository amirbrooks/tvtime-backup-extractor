from __future__ import annotations

import json
import plistlib
import re
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class LegacyCacheArchive:
    source_id: str
    url: str
    payload: object
    payload_bytes: bytes
    observed_mtime_ns: int


class LegacyCacheNodeLimitError(ValueError):
    pass


def _iter_nested(value: object, *, maximum_nodes: int) -> Iterator[object]:
    stack = [value]
    visited = 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited > maximum_nodes:
            raise LegacyCacheNodeLimitError
        yield current
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def decode_legacy_cache_archive(
    data: bytes,
    *,
    source_id: str,
    observed_mtime_ns: int,
    maximum_nodes: int,
) -> LegacyCacheArchive | None:
    """Decode one extensionless NSKeyedArchiver cached-response envelope."""

    try:
        archive = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError):
        return None
    if (
        not isinstance(archive, dict)
        or archive.get("$archiver") != "NSKeyedArchiver"
        or not isinstance(archive.get("$objects"), list)
        or not isinstance(archive.get("$top"), dict)
    ):
        return None
    urls: list[str] = []
    payloads: list[tuple[object, bytes]] = []
    for value in _iter_nested(archive, maximum_nodes=maximum_nodes):
        if isinstance(value, str) and value.startswith(("https://", "http://")):
            urls.append(value)
        elif isinstance(value, bytes):
            try:
                payloads.append((json.loads(value), value))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                continue
    if len(urls) != 1 or len(payloads) != 1:
        return None
    payload, payload_bytes = payloads[0]
    return LegacyCacheArchive(
        source_id=source_id,
        url=urls[0],
        payload=payload,
        payload_bytes=payload_bytes,
        observed_mtime_ns=observed_mtime_ns,
    )


def _payload_data(payload: object) -> object:
    if isinstance(payload, dict) and "data" in payload:
        return payload.get("data")
    return payload


def _integer(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _owner_user_id(archives: Sequence[LegacyCacheArchive]) -> str | None:
    candidates: Counter[str] = Counter()
    for archive in archives:
        path = urlsplit(archive.url).path
        if not any(
            marker in path
            for marker in (
                "/allfollowing",
                "/tracking/cgw/follows/user/",
                "/tracking/watches/user/",
                "/lists/cgw/user/",
            )
        ):
            continue
        match = re.search(r"/user/(\d+)", path)
        if match is not None:
            candidates[match.group(1)] += 1
    return candidates.most_common(1)[0][0] if candidates else None


def _episodes_from_show(show: dict[str, Any]) -> list[dict[str, Any]]:
    show_id = show.get("id", "")
    show_name = show.get("name", "")
    seasons = show.get("seasons")
    if not isinstance(seasons, list):
        return []
    episodes: list[dict[str, Any]] = []
    for season in seasons:
        if not isinstance(season, dict):
            continue
        season_episodes = season.get("episodes")
        if not isinstance(season_episodes, list):
            continue
        for episode in season_episodes:
            if not isinstance(episode, dict):
                continue
            episode_show = episode.get("show")
            if not isinstance(episode_show, dict):
                episode_show = {}
            episode_season = episode.get("season")
            if isinstance(episode_season, dict):
                episode_season = episode_season.get("number")
            if episode_season in (None, ""):
                episode_season = season.get("number", "")
            episodes.append(
                {
                    "id": episode.get("id", ""),
                    "air_date": episode.get("air_date", ""),
                    "show": {
                        "id": episode_show.get("id") or show_id,
                        "name": episode_show.get("name") or show_name,
                    },
                    "season_number": episode_season,
                    "number": episode.get("number", ""),
                    "name": episode.get("name", ""),
                    "seen": episode.get("seen", ""),
                    "seen_date": episode.get("seen_date", ""),
                    "is_watched": episode.get("is_watched", ""),
                    "is_special": episode.get("is_special", False),
                    "runtime": episode.get("runtime", ""),
                }
            )
    return episodes


def _merge_show_candidates(candidates: Sequence[dict[str, Any]]) -> dict[str, Any]:
    fields = (
        "id",
        "name",
        "country",
        "status",
        "created_at",
        "updated_at",
        "watched_episode_count",
        "aired_episode_count",
    )
    merged: dict[str, Any] = {field: "" for field in fields}
    for candidate in candidates:
        for field in fields:
            value = candidate.get(field)
            if value not in (None, ""):
                merged[field] = value
    return merged


def _series_object(show: dict[str, Any]) -> dict[str, Any]:
    series_id = _integer(show.get("id"))
    watched = _integer(show.get("watched_episode_count"))
    aired = _integer(show.get("aired_episode_count"))
    if watched <= 0:
        user_status = "not_started_yet"
    elif aired > 0 and watched >= aired:
        user_status = "up_to_date"
    else:
        user_status = "continuing"
    status = str(show.get("status") or "")
    return {
        "uuid": f"legacy-tvdb-{series_id}",
        "entity_type": "series",
        "created_at": show.get("created_at", ""),
        "updated_at": show.get("updated_at", ""),
        "filter": [user_status],
        "meta": {
            "id": series_id,
            "name": show.get("name", ""),
            "country": show.get("country", ""),
            "is_ended": status.casefold() in {"ended", "canceled", "cancelled"},
        },
        "watch_status": {
            "watched_episode_count": show.get("watched_episode_count", ""),
            "aired_episode_count": show.get("aired_episode_count", ""),
        },
    }


def normalize_legacy_archives(
    archives: Sequence[LegacyCacheArchive],
) -> list[tuple[str, object]]:
    """Convert supported legacy endpoint shapes to the analyzer's in-memory shapes."""

    ordered = sorted(archives, key=lambda item: (item.observed_mtime_ns, item.source_id))
    owner_id = _owner_user_id(ordered)
    normalized: list[tuple[str, object]] = []
    show_candidates: dict[int, list[dict[str, Any]]] = {}
    episodes: list[dict[str, Any]] = []
    normalized_source_id = ordered[-1].source_id if ordered else "legacy-cache"

    for archive in ordered:
        path = urlsplit(archive.url).path
        data = _payload_data(archive.payload)
        if (
            any(
                marker in path
                for marker in (
                    "/tracking/cgw/follows/user/",
                    "/tracking/watches/user/",
                )
            )
            and isinstance(data, dict)
            and isinstance(data.get("objects"), list)
        ):
            copied_data = dict(data)
            copied_data.setdefault(
                "type",
                "watch" if "/tracking/watches/user/" in path else "list",
            )
            normalized.append((archive.source_id, {"data": copied_data}))

        if "/lists/cgw/user/" in path and isinstance(data, list):
            for item in data:
                if (
                    isinstance(item, dict)
                    and item.get("id") in {"favorite-movies", "favorite-series"}
                    and isinstance(item.get("objects"), list)
                ):
                    normalized.append(
                        (
                            archive.source_id,
                            {
                                "data": {
                                    "type": "list",
                                    "id": item.get("id"),
                                    "objects": item["objects"],
                                }
                            },
                        )
                    )

        if path.endswith("/allfollowing") and isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    show_id = _integer(item.get("id"))
                    if show_id > 0:
                        show_candidates.setdefault(show_id, []).append(item)

        profile_match = re.fullmatch(r"/v2/user/(\d+)(?:/profile)?", path)
        if (
            owner_id is not None
            and profile_match is not None
            and profile_match.group(1) == owner_id
            and isinstance(data, dict)
            and isinstance(data.get("shows"), list)
        ):
            for item in data["shows"]:
                if not isinstance(item, dict):
                    continue
                show_id = _integer(item.get("id"))
                if show_id <= 0:
                    continue
                show_candidates.setdefault(show_id, []).append(item)
                episodes.extend(_episodes_from_show(item))

        if re.fullmatch(r"/v2/cacheable/show/\d+", path) and isinstance(data, dict):
            show_id = _integer(data.get("id"))
            if show_id > 0:
                show_candidates.setdefault(show_id, []).append(data)
                episodes.extend(_episodes_from_show(data))

    valid_show_ids = {
        _integer(episode.get("show", {}).get("id"))
        for episode in episodes
        if isinstance(episode.get("show"), dict)
    }
    valid_show_ids.discard(0)
    series = [
        _series_object(_merge_show_candidates(show_candidates[series_id]))
        for series_id in sorted(show_candidates)
        if series_id in valid_show_ids
    ]
    if series:
        normalized.append(
            (
                normalized_source_id,
                {"data": {"type": "list", "objects": series}},
            )
        )
    if episodes:
        normalized.append((normalized_source_id, {"data": episodes}))
    return normalized
