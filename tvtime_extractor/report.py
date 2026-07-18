from __future__ import annotations

import base64
import csv
import html
import json
import sqlite3
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from .analyze import readonly_sqlite
from .errors import TVTimeError
from .extract import PRIMARY_DOMAIN
from .safety import (
    safe_join,
    sanitize_public_url,
    validate_extraction_directory,
    write_csv_private,
    write_text_private,
)


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise TVTimeError(f"Required analysis file was not found: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def display_date(value: str) -> str:
    if not value or value.startswith("1970-01-01"):
        return "—"
    if len(value) >= 10 and value[4:5] == "-" and value[7:8] == "-":
        return value[:10]
    return value


def markdown_text(value: object) -> str:
    text = html.escape(str(value or ""), quote=False).replace("\r", " ").replace("\n", " ")
    for character in ("\\", "`", "*", "_", "[", "]", "#"):
        text = text.replace(character, f"\\{character}")
    return text


def markdown_date(value: str) -> str:
    return markdown_text(display_date(value))


def series_status(filters: str) -> str:
    labels = {
        "up_to_date": "up to date",
        "stopped": "stopped",
        "not_started_yet": "not started",
        "continuing": "continuing / episodes remaining",
    }
    for value in (part.strip() for part in filters.split("|")):
        if value in labels:
            return labels[value]
    return filters or "saved"


def collect_trailers(value: object, inherited_name: str = "") -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if isinstance(value, dict):
        own_name = str(value.get("name") or inherited_name or "")
        meta = value.get("meta")
        if isinstance(meta, dict):
            meta_name = str(meta.get("name") or own_name)
            for trailer in meta.get("trailers") or []:
                if isinstance(trailer, dict):
                    url = sanitize_public_url(str(trailer.get("url") or ""))
                    if url:
                        rows.append(
                            {
                                "title": meta_name,
                                "trailer_name": str(trailer.get("name") or ""),
                                "runtime_seconds": str(trailer.get("runtime") or ""),
                                "url": url,
                                "thumbnail_url": sanitize_public_url(
                                    str(trailer.get("thumb_url") or "")
                                ),
                            }
                        )
        for trailer in value.get("trailers") or []:
            if isinstance(trailer, dict):
                url = sanitize_public_url(str(trailer.get("url") or ""))
                if url:
                    rows.append(
                        {
                            "title": own_name,
                            "trailer_name": str(trailer.get("name") or ""),
                            "runtime_seconds": str(trailer.get("runtime") or ""),
                            "url": url,
                            "thumbnail_url": sanitize_public_url(
                                str(trailer.get("thumb_url") or "")
                            ),
                        }
                    )
        for child in value.values():
            rows.extend(collect_trailers(child, own_name))
    elif isinstance(value, list):
        for child in value:
            rows.extend(collect_trailers(child, inherited_name))
    return rows


def collect_urls(value: object, path: str = "") -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            rows.extend(collect_urls(child, child_path))
    elif isinstance(value, list):
        for child in value:
            rows.extend(collect_urls(child, f"{path}[]"))
    elif isinstance(value, str):
        url = sanitize_public_url(value)
        if url:
            rows.append((path, url))
    return rows


def decode_tvtime_image_url(url: str) -> tuple[str, str, str]:
    sanitized = sanitize_public_url(url)
    marker = "/image/raw/"
    if marker not in sanitized:
        return sanitized, "", ""
    token = sanitized.split(marker, 1)[1].split("?", 1)[0]
    try:
        token += "=" * (-len(token) % 4)
        payload = json.loads(base64.urlsafe_b64decode(token))
        source = sanitize_image_source_reference(str(payload.get("key") or "")) or sanitized
        resize = (payload.get("edits") or {}).get("resize") or {}
        return source, str(resize.get("width") or ""), str(resize.get("height") or "")
    except (ValueError, TypeError, json.JSONDecodeError):
        return sanitized, "", ""


def sanitize_image_source_reference(value: str) -> str:
    absolute_url = sanitize_public_url(value)
    if absolute_url:
        return absolute_url
    if not isinstance(value, str) or not value or "\\" in value:
        return ""
    if any(ord(character) < 32 for character in value):
        return ""
    parsed = urlsplit(value)
    path = parsed.path
    decoded_path = unquote(path)
    if (
        parsed.scheme
        or parsed.netloc
        or not path
        or path.startswith("/")
        or path[0] in "=+-@"
        or "\\" in decoded_path
        or decoded_path.startswith("/")
    ):
        return ""
    relative = PurePosixPath(path)
    decoded_relative = PurePosixPath(decoded_path)
    if (
        relative.as_posix() != path
        or any(part in {".", ".."} for part in relative.parts)
        or any(part in {".", ".."} for part in decoded_relative.parts)
    ):
        return ""
    return path


def image_category(source: str) -> str:
    lowered = source.lower()
    for category, markers in (
        ("episode screen", ("/episode/", "/screencap/")),
        ("poster", ("/posters/", "/poster/")),
        ("background / fanart", ("/backgrounds/", "/fanart/")),
        ("thumbnail", ("ytimg.com", "thumb")),
        ("logo", ("logo",)),
    ):
        if any(marker in lowered for marker in markers):
            return category
    return "other image"


def _cache_payloads(cache_db: Path) -> list[object]:
    payloads: list[object] = []
    with readonly_sqlite(cache_db) as connection:
        try:
            rows = connection.execute("SELECT content FROM cache_dio ORDER BY key, subKey")
            for (content,) in rows:
                try:
                    payloads.append(json.loads(bytes(content or b"")))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
        except sqlite3.Error as exc:
            raise TVTimeError(f"Could not read media references from DioCache.db: {exc}") from exc
    return payloads


def _image_cache_rows(image_db: Path) -> tuple[list[dict[str, Any]], str]:
    if not image_db.is_file():
        return [], "not present"
    rows: list[dict[str, Any]] = []
    try:
        with readonly_sqlite(image_db) as connection:
            records = connection.execute(
                "SELECT _id, url, key, relativePath, eTag, validTill, touched, length "
                "FROM cacheObject ORDER BY _id"
            )
            for record in records:
                cache_id, url, _key, relative_path, _etag, valid_till, touched, length = record
                source, width, height = decode_tvtime_image_url(str(url or ""))
                rows.append(
                    {
                        "cache_id": cache_id,
                        "category": image_category(source),
                        "intended_filename": str(relative_path or ""),
                        "declared_bytes": length or "",
                        "width": width,
                        "height": height,
                        "source_url": source,
                        "cached_request_url": sanitize_public_url(str(url or "")),
                        "valid_till": valid_till or "",
                        "touched": touched or "",
                    }
                )
    except (sqlite3.Error, TVTimeError) as exc:
        return [], f"unreadable: {exc}"
    return rows, "ok"


def build_report(*, extraction_directory: Path) -> dict[str, Any]:
    """Build a readable private catalogue and sanitized media-reference tables."""

    extraction = validate_extraction_directory(extraction_directory)
    analysis = safe_join(extraction, "analysis")
    if not analysis.is_dir() or analysis.is_symlink():
        raise TVTimeError(f"Analysis directory was not found: {analysis}. Run analyze first.")

    series = read_csv(analysis / "series_library.csv")
    watched_movies = read_csv(analysis / "watched_movies.csv")
    movie_watchlist = read_csv(analysis / "movie_watchlist.csv")
    favorite_shows = read_csv(analysis / "favorite_shows.csv")
    favorite_movies = read_csv(analysis / "favorite_movies.csv")
    episodes = read_csv(analysis / "episode_cache_unique.csv")
    watch_events = read_csv(analysis / "watch_events_named.csv")
    inventory_path = safe_join(extraction, "metadata", "inventory.csv")
    extracted_file_count = len(read_csv(inventory_path)) if inventory_path.is_file() else 0

    app_root = safe_join(extraction, "raw", PRIMARY_DOMAIN)
    payloads = _cache_payloads(safe_join(app_root, "Documents", "DioCache.db"))
    all_urls: dict[str, str] = {}
    trailers_by_url: dict[str, dict[str, str]] = {}
    for payload in payloads:
        for field_path, url in collect_urls(payload):
            all_urls.setdefault(url, field_path)
        for trailer in collect_trailers(payload):
            trailers_by_url.setdefault(trailer["url"], trailer)

    trailer_rows = sorted(
        trailers_by_url.values(),
        key=lambda row: (row["title"].casefold(), row["url"]),
    )
    write_csv_private(
        analysis / "trailer_references.csv",
        trailer_rows,
        ["title", "trailer_name", "runtime_seconds", "url", "thumbnail_url"],
    )

    media_url_rows: list[dict[str, str]] = []
    for url, field_path in sorted(all_urls.items()):
        host = urlsplit(url).netloc
        lowered = f"{field_path} {url}".lower()
        if "youtube.com/watch" in lowered or "youtu.be/" in lowered:
            kind = "trailer video link"
        elif any(
            marker in lowered
            for marker in ("image", "poster", "fanart", "banner", "screen", "thumb", ".jpg", ".png")
        ):
            kind = "image link"
        else:
            kind = "other link"
        media_url_rows.append({"kind": kind, "host": host, "field_path": field_path, "url": url})
    write_csv_private(
        analysis / "media_url_inventory.csv",
        media_url_rows,
        ["kind", "host", "field_path", "url"],
    )

    image_rows, image_cache_status = _image_cache_rows(
        safe_join(app_root, "Library", "Application Support", "libCachedImageData.db")
    )
    write_csv_private(
        analysis / "image_cache_references.csv",
        image_rows,
        [
            "cache_id",
            "category",
            "intended_filename",
            "declared_bytes",
            "width",
            "height",
            "source_url",
            "cached_request_url",
            "valid_till",
            "touched",
        ],
    )

    named_events = sum(bool(row["movie_name"]) for row in watch_events)
    media_counts = Counter(row["kind"] for row in media_url_rows)
    image_category_counts = Counter(str(row["category"]) for row in image_rows)
    lines: list[str] = [
        "# TV Time recovered-data report",
        "",
        (
            "> Private output: this report contains viewing history. "
            "Do not post it to GitHub or a public issue."
        ),
        "",
        (
            "Every identifiable series, movie, favorite, episode, and watch-event title found "
            "in the recovered local cache is listed below. Missing names are called out rather "
            "than guessed."
        ),
        "",
        "## Recovery summary",
        "",
        f"- TV series library: {len(series)} titles",
        f"- Movie library: {len(watched_movies) + len(movie_watchlist)} titles "
        f"({len(watched_movies)} watched; {len(movie_watchlist)} saved)",
        f"- Favorite shows: {len(favorite_shows)}",
        f"- Favorite movies: {len(favorite_movies)}",
        f"- Watch events: {len(watch_events)} ({named_events} matched to titles)",
        f"- Identifiable cached episodes: {len(episodes)}",
        f"- Extracted app-container files: {extracted_file_count}",
        "",
        "## TV series library — all identifiable titles",
        "",
    ]
    for index, row in enumerate(series, 1):
        lines.append(
            f"{index}. {markdown_text(row['name'])} — "
            f"{markdown_text(series_status(row['filters']))}; "
            f"followed {markdown_date(row['followed_at'])}; last activity "
            f"{markdown_date(row['last_watch_date'])}"
        )

    lines.extend(["", "## Watched movies — all identifiable titles", ""])
    for index, row in enumerate(watched_movies, 1):
        lines.append(
            f"{index}. {markdown_text(row['name'])} — watched {markdown_date(row['watched_at'])}; "
            f"released {markdown_date(row['first_release_date'])}; genres: "
            f"{markdown_text(row['genres'] or '—')}"
        )

    lines.extend(["", "## Saved movie watchlist — all identifiable titles", ""])
    for index, row in enumerate(movie_watchlist, 1):
        lines.append(
            f"{index}. {markdown_text(row['name'])} — saved {markdown_date(row['followed_at'])}; "
            f"released {markdown_date(row['first_release_date'])}; genres: "
            f"{markdown_text(row['genres'] or '—')}"
        )

    lines.extend(["", "## Favorite shows — all identifiable titles", ""])
    lines.extend(
        f"{index}. {markdown_text(row['name'])}" for index, row in enumerate(favorite_shows, 1)
    )
    lines.extend(["", "## Favorite movies — all identifiable titles", ""])
    lines.extend(
        f"{index}. {markdown_text(row['name'])}" for index, row in enumerate(favorite_movies, 1)
    )

    lines.extend(["", "## Cached identifiable episodes — all identifiable names", ""])
    for index, row in enumerate(episodes, 1):
        lines.append(
            f"{index}. {markdown_text(row['show_name'])} — S{markdown_text(row['season'])}"
            f"E{markdown_text(row['episode'])} — {markdown_text(row['episode_name'])} — "
            f"seen: {markdown_text(row['seen'])}; air date: {markdown_date(row['air_date'])}"
        )

    lines.extend(
        [
            "",
            "## Watch-event ledger",
            "",
            (
                "A blank title means the event survived but its title metadata "
                "was not in the local cache."
            ),
            "",
        ]
    )
    for index, row in enumerate(sorted(watch_events, key=lambda item: item["watched_at"]), 1):
        title = row["movie_name"] or "[title not present in cache]"
        lines.append(
            f"{index}. {markdown_text(title)} — {markdown_date(row['watched_at'])}; "
            f"runtime {markdown_text(row['runtime'] or '—')} seconds"
        )

    lines.extend(
        [
            "",
            "## Media-reference summary",
            "",
            f"- Image-cache status: {markdown_text(image_cache_status)}",
            f"- Image-cache catalogue rows: {len(image_rows)}",
            f"- Trailer links: {len(trailer_rows)}",
            f"- Sanitized media URLs: {len(media_url_rows)}",
            "- Media URL categories: "
            + ", ".join(f"{name}: {count}" for name, count in sorted(media_counts.items())),
            "- Image categories: "
            + ", ".join(
                f"{name}: {count}" for name, count in sorted(image_category_counts.items())
            ),
            "",
            "Full private tables remain in this analysis directory.",
        ]
    )

    report_path = analysis / "TVTime-Recovered-Data.md"
    write_text_private(report_path, "\n".join(lines) + "\n")
    return {
        "report": str(report_path),
        "series": len(series),
        "watched_movies": len(watched_movies),
        "movie_watchlist": len(movie_watchlist),
        "favorite_shows": len(favorite_shows),
        "favorite_movies": len(favorite_movies),
        "episodes": len(episodes),
        "watch_events": len(watch_events),
        "named_watch_events": named_events,
        "image_cache_references": len(image_rows),
        "trailer_references": len(trailer_rows),
        "media_urls": len(media_url_rows),
    }
