from __future__ import annotations

import html
import io
import os
import re
import sys
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from xml.sax.saxutils import escape as xml_escape

import reportlab
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.pdfdoc import PDFString
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    LongTable,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.doctemplate import LayoutError

from .display_text import has_display_text, normalize_display_text
from .errors import OutputExistsError, TVTimeError
from .safety import secure_file, write_bytes_private, write_text_private

REPORTLAB_VERSION = "5.0.0"
HTML_REPORT_FILENAME = "TVTime-Recovered-Data.html"
PDF_REPORT_FILENAME = "TVTime-Recovered-Data.pdf"
PRIVATE_NOTICE = (
    "Private recovery output: this report contains viewing history. Keep it on encrypted "
    "storage and do not post it to a public issue or repository."
)
SYNTHETIC_FIXTURE_NOTICE = "SYNTHETIC QA FIXTURE - NOT RECOVERED USER DATA"
PDF_FIDELITY_WARNING = (
    "PDF omitted because the available embedded font and shaping engine could not faithfully "
    "render every recovered character. The Markdown and offline HTML reports are complete."
)


class PDFCapabilityError(TVTimeError):
    """The optional PDF cannot preserve the canonical recovered text faithfully."""


@dataclass(frozen=True)
class ReportMetric:
    label: str
    value: int


@dataclass(frozen=True)
class ReportRow:
    name: str
    details: str


@dataclass(frozen=True)
class ReportSection:
    identifier: str
    title: str
    description: str
    rows: tuple[ReportRow, ...]


@dataclass(frozen=True)
class AggregateStatistic:
    label: str
    value: str


@dataclass(frozen=True)
class VisualReportModel:
    metrics: tuple[ReportMetric, ...]
    summary_statistics: tuple[AggregateStatistic, ...]
    sections: tuple[ReportSection, ...]
    media_statistics: tuple[AggregateStatistic, ...]
    library_chart: tuple[ReportMetric, ...]
    media_chart: tuple[ReportMetric, ...]
    synthetic_fixture: bool = False


@dataclass(frozen=True)
class _FontCandidate:
    label: str
    regular: Path
    bold: Path
    italic: Path
    bold_italic: Path


@dataclass(frozen=True)
class _FontFamily:
    regular: str
    bold: str
    italic: str
    bold_italic: str


def _plain(value: object, *, fallback: str = "") -> str:
    return normalize_display_text(value, fallback=fallback)


def _display_date(value: object) -> str:
    text = _plain(value)
    if not text or text.startswith("1970-01-01"):
        return "-"
    if len(text) >= 10 and text[4:5] == "-" and text[7:8] == "-":
        return text[:10]
    return text


def _series_status(value: object) -> str:
    labels = {
        "up_to_date": "up to date",
        "stopped": "stopped",
        "not_started_yet": "not started",
        "continuing": "continuing / episodes remaining",
    }
    filters = _plain(value)
    for item in (part.strip() for part in filters.split("|")):
        if item in labels:
            return labels[item]
    return filters or "saved"


def _field(row: Mapping[str, object], name: str, *, fallback: str = "-") -> str:
    return _plain(row.get(name), fallback=fallback)


def _details(*parts: tuple[str, str]) -> str:
    return " | ".join(f"{label}: {value}" for label, value in parts)


def _series_rows(rows: Sequence[Mapping[str, object]]) -> tuple[ReportRow, ...]:
    return tuple(
        ReportRow(
            name=_field(row, "name", fallback="[series title not present in cache]"),
            details=_details(
                ("Status", _series_status(row.get("filters"))),
                ("Followed", _display_date(row.get("followed_at"))),
                ("Last activity", _display_date(row.get("last_watch_date"))),
            ),
        )
        for row in rows
    )


def _movie_rows(
    rows: Sequence[Mapping[str, object]],
    *,
    activity_label: str,
    activity_field: str,
) -> tuple[ReportRow, ...]:
    return tuple(
        ReportRow(
            name=_field(row, "name", fallback="[movie title not present in cache]"),
            details=_details(
                (activity_label, _display_date(row.get(activity_field))),
                ("Released", _display_date(row.get("first_release_date"))),
                ("Genres", _field(row, "genres")),
            ),
        )
        for row in rows
    )


def _favorite_rows(rows: Sequence[Mapping[str, object]]) -> tuple[ReportRow, ...]:
    result: list[ReportRow] = []
    for row in rows:
        details = [
            ("Type", _field(row, "type")),
            ("Status", _field(row, "status")),
            ("Saved", _display_date(row.get("created_at"))),
        ]
        watched = _plain(row.get("watched_episode_count"))
        aired = _plain(row.get("aired_episode_count"))
        if watched or aired:
            details.append(("Episodes watched / aired", f"{watched or '-'} / {aired or '-'}"))
        result.append(
            ReportRow(
                name=_field(row, "name", fallback="[favorite title not present in cache]"),
                details=_details(*details),
            )
        )
    return tuple(result)


def _episode_rows(rows: Sequence[Mapping[str, object]]) -> tuple[ReportRow, ...]:
    result: list[ReportRow] = []
    for row in rows:
        show_name = _field(row, "show_name", fallback="[series title not present in cache]")
        season = _field(row, "season", fallback="?")
        episode = _field(row, "episode", fallback="?")
        episode_name = _field(
            row,
            "episode_name",
            fallback="[episode title not present in cache]",
        )
        result.append(
            ReportRow(
                name=f"{show_name} - S{season}E{episode} - {episode_name}",
                details=_details(
                    ("Seen", _field(row, "seen")),
                    ("Air date", _display_date(row.get("air_date"))),
                ),
            )
        )
    return tuple(result)


def _watch_event_rows(rows: Sequence[Mapping[str, object]]) -> tuple[ReportRow, ...]:
    return tuple(
        ReportRow(
            name=_field(row, "movie_name", fallback="[title not present in cache]"),
            details=_details(
                ("Watched", _display_date(row.get("watched_at"))),
                ("Runtime seconds", _field(row, "runtime")),
            ),
        )
        for row in sorted(rows, key=lambda item: _plain(item.get("watched_at")))
    )


def _size_discrepancy_rows(
    rows: Sequence[Mapping[str, object]],
) -> tuple[ReportRow, ...]:
    return tuple(
        ReportRow(
            name=(
                f"{_field(row, 'domain', fallback='[domain not present]')}/"
                f"{_field(row, 'relative_path', fallback='[path not present]')}"
            ),
            details=_details(
                ("Declared bytes", _field(row, "declared_size")),
                ("Copied bytes", _field(row, "actual_size")),
            ),
        )
        for row in rows
    )


def build_visual_report_model(
    *,
    series: Sequence[Mapping[str, object]],
    watched_movies: Sequence[Mapping[str, object]],
    movie_watchlist: Sequence[Mapping[str, object]],
    favorite_shows: Sequence[Mapping[str, object]],
    favorite_movies: Sequence[Mapping[str, object]],
    episodes: Sequence[Mapping[str, object]],
    watch_events: Sequence[Mapping[str, object]],
    extracted_file_count: int,
    image_cache_status: str,
    trailer_count: int,
    media_url_counts: Mapping[str, int],
    image_category_counts: Mapping[str, int],
    size_discrepancies: Sequence[Mapping[str, object]] = (),
    synthetic_fixture: bool = False,
) -> VisualReportModel:
    """Normalize every human-readable report row into one immutable data source."""

    series_section_title = (
        "Synthetic series fixture records" if synthetic_fixture else "Recovered TV series records"
    )
    series_metric_label = (
        "Synthetic series records" if synthetic_fixture else "Recovered series records"
    )
    sections = (
        ReportSection(
            identifier="series-library",
            title=series_section_title,
            description=(
                (
                    "Every synthetic series fixture record. "
                    if synthetic_fixture
                    else "Every recovered series cache record. "
                )
                + "Missing titles are stated explicitly rather than guessed."
            ),
            rows=_series_rows(series),
        ),
        ReportSection(
            identifier="watched-movies",
            title="Watched movies",
            description=(
                (
                    "Every synthetic watched-movie fixture record. "
                    if synthetic_fixture
                    else "Every recovered movie record marked as watched. "
                )
                + "Missing titles are stated explicitly rather than guessed."
            ),
            rows=_movie_rows(
                watched_movies,
                activity_label="Watched",
                activity_field="watched_at",
            ),
        ),
        ReportSection(
            identifier="saved-movies",
            title="Saved movie watchlist",
            description=(
                (
                    "Every synthetic saved-movie fixture record. "
                    if synthetic_fixture
                    else "Every recovered movie record saved for later. "
                )
                + "Missing titles are stated explicitly rather than guessed."
            ),
            rows=_movie_rows(
                movie_watchlist,
                activity_label="Saved",
                activity_field="followed_at",
            ),
        ),
        ReportSection(
            identifier="favorite-shows",
            title="Favorite shows",
            description=(
                (
                    "Every synthetic favorite-show fixture record. "
                    if synthetic_fixture
                    else "Every recovered favorite-show record. "
                )
                + "Missing titles are stated explicitly."
            ),
            rows=_favorite_rows(favorite_shows),
        ),
        ReportSection(
            identifier="favorite-movies",
            title="Favorite movies",
            description=(
                (
                    "Every synthetic favorite-movie fixture record. "
                    if synthetic_fixture
                    else "Every recovered favorite-movie record. "
                )
                + "Missing titles are stated explicitly."
            ),
            rows=_favorite_rows(favorite_movies),
        ),
        ReportSection(
            identifier="cached-episodes",
            title="Cached episodes",
            description=(
                (
                    "Every distinct synthetic cached-episode fixture record. "
                    if synthetic_fixture
                    else "Every distinct recovered cached-episode record and its available state. "
                )
                + "Missing names are stated explicitly."
            ),
            rows=_episode_rows(episodes),
        ),
        ReportSection(
            identifier="watch-events",
            title="Watch-event ledger",
            description=(
                (
                    "Every synthetic watch-event fixture record. "
                    if synthetic_fixture
                    else "Every recovered watch event. "
                )
                + "Missing names are stated explicitly rather than guessed."
            ),
            rows=_watch_event_rows(watch_events),
        ),
        ReportSection(
            identifier="copy-size-differences",
            title="Copy-size differences",
            description=(
                (
                    "Synthetic file fixtures with simulated byte-count differences. "
                    if synthetic_fixture
                    else "Selected files whose copied byte count differed from backup metadata. "
                )
                + (
                    "These are layout-test values, not recovered files."
                    if synthetic_fixture
                    else "The files were retained as explicit salvage results rather than hidden."
                )
            ),
            rows=_size_discrepancy_rows(size_discrepancies),
        ),
    )
    library_chart = (
        ReportMetric(series_metric_label, len(series)),
        ReportMetric("Watched movies", len(watched_movies)),
        ReportMetric("Saved movies", len(movie_watchlist)),
        ReportMetric("Favorite shows", len(favorite_shows)),
        ReportMetric("Favorite movies", len(favorite_movies)),
        ReportMetric("Cached episodes", len(episodes)),
        ReportMetric("Watch events", len(watch_events)),
    )
    metrics = (
        *library_chart,
        ReportMetric(
            "Synthetic file fixtures" if synthetic_fixture else "Extracted files",
            extracted_file_count,
        ),
        ReportMetric(
            (
                "Synthetic byte-difference fixtures"
                if synthetic_fixture
                else "Byte-count differences"
            ),
            len(size_discrepancies),
        ),
    )
    movie_total = len(watched_movies) + len(movie_watchlist)
    named_series_titles = [_plain(row.get("name")) for row in series]
    named_series_titles = [title for title in named_series_titles if has_display_text(title)]
    distinct_series_titles = len({title.casefold() for title in named_series_titles})
    named_watch_events = sum(has_display_text(row.get("movie_name")) for row in watch_events)
    unnamed_watch_events = len(watch_events) - named_watch_events
    summary_statistics = (
        AggregateStatistic(
            "Series record title coverage",
            (
                f"{len(named_series_titles)} named; "
                f"{len(series) - len(named_series_titles)} unnamed; {len(series)} total records"
            ),
        ),
        AggregateStatistic(
            "Distinct named series titles",
            str(distinct_series_titles),
        ),
        AggregateStatistic(
            "Movie library",
            (f"{movie_total} total ({len(watched_movies)} watched; {len(movie_watchlist)} saved)"),
        ),
        AggregateStatistic(
            "Watch-event title matches",
            (
                f"{named_watch_events} named; {unnamed_watch_events} unnamed; "
                f"{len(watch_events)} total"
            ),
        ),
    )
    media_url_total = sum(int(value) for value in media_url_counts.values())
    image_total = sum(int(value) for value in image_category_counts.values())
    media_statistics: list[AggregateStatistic] = [
        AggregateStatistic("Image-cache status", _plain(image_cache_status, fallback="-")),
        AggregateStatistic("Image-cache catalogue rows", str(image_total)),
        AggregateStatistic("Trailer links", str(trailer_count)),
        AggregateStatistic("Sanitized media URLs", str(media_url_total)),
    ]
    media_statistics.extend(
        AggregateStatistic(f"Media URL category - {_plain(name)}", str(int(count)))
        for name, count in sorted(media_url_counts.items())
    )
    media_statistics.extend(
        AggregateStatistic(f"Image category - {_plain(name)}", str(int(count)))
        for name, count in sorted(image_category_counts.items())
    )
    media_chart = (
        ReportMetric("Trailer links", trailer_count),
        ReportMetric("Media URLs", media_url_total),
        ReportMetric("Image references", image_total),
        *(
            ReportMetric(f"URL: {_plain(name)}", int(count))
            for name, count in sorted(media_url_counts.items())
        ),
        *(
            ReportMetric(f"Image: {_plain(name)}", int(count))
            for name, count in sorted(image_category_counts.items())
        ),
    )
    return VisualReportModel(
        metrics=metrics,
        summary_statistics=summary_statistics,
        sections=sections,
        media_statistics=tuple(media_statistics),
        library_chart=library_chart,
        media_chart=media_chart,
        synthetic_fixture=synthetic_fixture,
    )


def _markdown_text(value: object) -> str:
    text = html.escape(str(value or ""), quote=False).replace("\r", " ").replace("\n", " ")
    for character in ("\\", "`", "*", "_", "[", "]", "#"):
        text = text.replace(character, f"\\{character}")
    return text


def render_markdown_report(
    model: VisualReportModel,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> str:
    """Render the canonical report from the same normalized rows as HTML and PDF."""

    if cancellation_check is not None:
        cancellation_check()
    document_title = (
        SYNTHETIC_FIXTURE_NOTICE if model.synthetic_fixture else "TV Time recovered-data report"
    )
    notice = (
        "> This report was generated entirely from synthetic QA records. "
        "It is not a recovery result."
        if model.synthetic_fixture
        else (
            "> Private output: this report contains viewing history. "
            "Do not post it to GitHub or a public issue."
        )
    )
    lines = [
        f"# {document_title}",
        "",
        notice,
        "",
        (
            "Every synthetic series, movie, favorite, episode, and watch-event fixture record "
            "is listed below. No count or name in this report came from a user backup."
            if model.synthetic_fixture
            else (
                "Every recovered series, movie, favorite, episode, and watch-event record is "
                "listed below. Each available title/name is preserved; missing names are called "
                "out rather than guessed."
            )
        ),
        "",
        "## Synthetic fixture summary" if model.synthetic_fixture else "## Recovery summary",
        "",
    ]
    lines.extend(f"- {_markdown_text(metric.label)}: {metric.value}" for metric in model.metrics)
    lines.extend(["", "## Recovery breakdowns", ""])
    lines.extend(
        f"- {_markdown_text(statistic.label)}: {_markdown_text(statistic.value)}"
        for statistic in model.summary_statistics
    )
    for section in model.sections:
        if cancellation_check is not None:
            cancellation_check()
        lines.extend(
            [
                "",
                f"## {_markdown_text(section.title)}",
                "",
                _markdown_text(section.description),
                "",
            ]
        )
        if not section.rows:
            lines.append("_No rows were recorded for this section._")
            continue
        for index, row in enumerate(section.rows, 1):
            if cancellation_check is not None:
                cancellation_check()
            lines.append(f"{index}. {_markdown_text(row.name)} — {_markdown_text(row.details)}")
    lines.extend(["", "## Aggregate media statistics", ""])
    lines.extend(
        f"- {_markdown_text(statistic.label)}: {_markdown_text(statistic.value)}"
        for statistic in model.media_statistics
    )
    lines.extend(["", "Full private tables remain in this analysis directory.", ""])
    return "\n".join(lines)


def _svg_chart(metrics: Sequence[ReportMetric], *, title: str) -> str:
    items = tuple(metrics) or (ReportMetric("No recovered rows", 0),)
    maximum = max((metric.value for metric in items), default=0) or 1
    width = 760
    label_width = 205
    chart_width = 455
    row_height = 35
    height = 48 + len(items) * row_height
    output = [
        (
            f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" '
            f'aria-label="{html.escape(title, quote=True)}">'
        ),
        f"<title>{html.escape(title)}</title>",
    ]
    for index, metric in enumerate(items):
        y = 35 + index * row_height
        bar_width = max(2, round(chart_width * metric.value / maximum)) if metric.value else 0
        output.extend(
            [
                (
                    f'<text class="chart-label" x="0" y="{y + 16}">'
                    f"{html.escape(metric.label)}</text>"
                ),
                (
                    f'<rect class="chart-track" x="{label_width}" y="{y}" '
                    f'width="{chart_width}" height="22" rx="6" />'
                ),
                (
                    f'<rect class="chart-bar" x="{label_width}" y="{y}" '
                    f'width="{bar_width}" height="22" rx="6" />'
                ),
                (
                    f'<text class="chart-value" x="{label_width + chart_width + 12}" '
                    f'y="{y + 16}">{metric.value}</text>'
                ),
            ]
        )
    output.append("</svg>")
    return "".join(output)


def render_html_report(
    model: VisualReportModel,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> str:
    """Render a self-contained report that cannot execute code or fetch remote resources."""

    if cancellation_check is not None:
        cancellation_check()
    if model.synthetic_fixture:
        document_title = SYNTHETIC_FIXTURE_NOTICE
        eyebrow = "Synthetic visual test catalogue"
        lede = (
            "Generated entirely from synthetic QA records to exercise report layout. "
            "These counts and names are not recovered user data."
        )
        notice = SYNTHETIC_FIXTURE_NOTICE
        footer_notice = "Synthetic layout fixture. No recovered user data is present."
    else:
        document_title = "TV Time recovered-data report"
        eyebrow = "Private offline recovery catalogue"
        lede = (
            "Every recovered series, movie, favorite, episode, and watch-event record is listed "
            "below. Each available title/name is preserved; missing names are called out rather "
            "than guessed."
        )
        notice = PRIVATE_NOTICE
        footer_notice = f"{PRIVATE_NOTICE} This file is self-contained and works offline."
    summary_title = "Synthetic fixture summary" if model.synthetic_fixture else "Recovery summary"
    library_chart_title = (
        "Synthetic fixture library counts"
        if model.synthetic_fixture
        else "Recovered library record counts"
    )
    table_row_origin = "synthetic fixture" if model.synthetic_fixture else "recovered"
    metric_cards = "".join(
        (
            '<div class="metric"><strong>'
            f"{metric.value}</strong><span>{html.escape(metric.label)}</span></div>"
        )
        for metric in model.metrics
    )
    summary_statistics = "".join(
        (
            f"<div><dt>{html.escape(statistic.label)}</dt>"
            f"<dd>{html.escape(statistic.value)}</dd></div>"
        )
        for statistic in model.summary_statistics
    )
    contents = "".join(
        f'<li><a href="#{section.identifier}">{html.escape(section.title)}</a></li>'
        for section in model.sections
    )
    section_fragments: list[str] = []
    for section in model.sections:
        if cancellation_check is not None:
            cancellation_check()
        rows: list[str] = []
        for index, row in enumerate(section.rows, 1):
            if cancellation_check is not None:
                cancellation_check()
            rows.append(
                "<tr>"
                f'<td class="number">{index}</td>'
                f'<td class="name" dir="auto">{html.escape(row.name)}</td>'
                f'<td class="details" dir="auto">{html.escape(row.details)}</td>'
                "</tr>"
            )
        table_body = "".join(rows) or (
            '<tr><td colspan="3" class="empty">No rows were recorded for this section.</td></tr>'
        )
        heading_id = f"{section.identifier}-heading"
        description_id = f"{section.identifier}-description"
        section_fragments.append(
            f'<section id="{section.identifier}" aria-labelledby="{heading_id}">'
            f'<h2 id="{heading_id}">{html.escape(section.title)}</h2>'
            f'<p class="section-note" id="{description_id}">'
            f"{html.escape(section.description)}</p>"
            '<div class="table-wrap"><table '
            f'aria-describedby="{description_id}"><caption class="sr-only">'
            f"All {table_row_origin} rows for {html.escape(section.title)}</caption>"
            '<thead><tr><th scope="col">#</th><th scope="col">Recovered name</th>'
            '<th scope="col">Recovered details</th></tr></thead>'
            f"<tbody>{table_body}</tbody></table></div>"
            '<a class="back-to-contents" href="#report-contents">Back to contents</a>'
            "</section>"
        )
    media_statistics = "".join(
        (
            f"<div><dt>{html.escape(statistic.label)}</dt>"
            f"<dd>{html.escape(statistic.value)}</dd></div>"
        )
        for statistic in model.media_statistics
    )
    csp = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
        "script-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src 'none'; "
        "connect-src 'none'; media-src 'none'; object-src 'none'; child-src 'none'; "
        "manifest-src 'none'; worker-src 'none'"
    )
    css = """
:root {
  color-scheme: light;
  --ink: #172033;
  --muted: #5d6678;
  --navy: #182a4d;
  --blue: #2864c7;
  --paper: #fff;
  --wash: #f3f6fb;
  --line: #dce3ef;
  --private: #8f2130;
}
* { box-sizing: border-box; }
html { background: #e9eef6; }
body {
  margin: 0;
  color: var(--ink);
  background: var(--paper);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  font-size: 15px;
  line-height: 1.55;
}
main { max-width: 1080px; margin: 0 auto; padding: 54px 64px 70px; }
.eyebrow {
  margin: 0 0 8px;
  color: var(--blue);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: .12em;
  text-transform: uppercase;
}
h1 { margin: 0; color: var(--navy); font-size: 42px; line-height: 1.08; }
h2 { margin: 42px 0 8px; color: var(--navy); font-size: 25px; line-height: 1.2; }
.lede { max-width: 760px; margin: 17px 0 26px; color: var(--muted); font-size: 17px; }
.privacy {
  margin: 24px 0 30px;
  padding: 16px 18px;
  border-left: 5px solid var(--private);
  border-radius: 8px;
  background: #fff1f3;
  color: #681824;
  font-weight: 650;
}
.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin: 18px 0 28px;
}
.metric {
  min-height: 105px;
  padding: 18px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--wash);
}
.metric strong { display: block; color: var(--navy); font-size: 30px; line-height: 1; }
.metric span {
  display: block;
  margin-top: 11px;
  color: var(--muted);
  font-size: 13px;
  font-weight: 700;
}
.panel {
  margin: 18px 0 30px;
  padding: 20px;
  border: 1px solid var(--line);
  border-radius: 14px;
  background: #fbfcff;
}
.chart-panel { overflow-x: auto; }
.chart { display: block; width: 100%; height: auto; }
.chart-label { fill: var(--ink); font-size: 13px; }
.chart-track { fill: #e5ebf4; }
.chart-bar { fill: var(--blue); }
.chart-value { fill: var(--navy); font-size: 13px; font-weight: 800; }
.contents {
  columns: 2;
  gap: 28px;
  margin: 10px 0 30px;
  padding: 20px 24px 20px 44px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--wash);
}
.contents li { break-inside: avoid; margin: 5px 0; }
.contents a { color: var(--navy); text-decoration: none; font-weight: 650; }
.contents a:hover, .back-to-contents:hover { text-decoration: underline; }
.contents a:focus-visible, .back-to-contents:focus-visible, .chart-panel:focus-visible {
  outline: 3px solid var(--blue);
  outline-offset: 3px;
}
.section-note { margin: 0 0 14px; color: var(--muted); }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 10px; }
table { width: 100%; border-collapse: collapse; }
caption.sr-only, .sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
thead { background: var(--navy); color: #fff; }
th, td {
  padding: 11px 12px;
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid var(--line);
}
th { font-size: 12px; letter-spacing: .035em; text-transform: uppercase; }
tbody tr:nth-child(even) { background: #f8faff; }
tbody tr:last-child td { border-bottom: 0; }
.number { width: 52px; color: var(--muted); font-variant-numeric: tabular-nums; }
.name { width: 38%; font-weight: 750; }
.details { color: var(--muted); }
.empty { padding: 22px; color: var(--muted); font-style: italic; }
.summary-breakdowns {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
  margin: 0 0 28px;
}
.summary-breakdowns div {
  padding: 14px 16px;
  border-left: 4px solid var(--blue);
  border-radius: 8px;
  background: #f6f8fc;
}
.summary-breakdowns dt { color: var(--muted); font-size: 13px; font-weight: 700; }
.summary-breakdowns dd { margin: 4px 0 0; color: var(--navy); font-weight: 800; }
.back-to-contents {
  display: inline-block;
  margin-top: 12px;
  color: var(--navy);
  font-size: 13px;
  font-weight: 700;
}
.stats {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 22px;
  margin: 0;
}
.stats div {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  padding: 10px 0;
  border-bottom: 1px solid var(--line);
}
.stats dt { color: var(--muted); }
.stats dd { margin: 0; color: var(--navy); font-weight: 800; text-align: right; }
footer {
  margin-top: 48px;
  padding-top: 18px;
  border-top: 1px solid var(--line);
  color: var(--muted);
  font-size: 12px;
}
@media (max-width: 760px) {
  main { padding: 32px 20px 48px; }
  h1 { font-size: 34px; }
  .metrics { grid-template-columns: repeat(2, 1fr); }
  .summary-breakdowns { grid-template-columns: 1fr; }
  .contents { columns: 1; }
  .stats { grid-template-columns: 1fr; }
  .chart-panel .chart { width: 760px; max-width: none; }
}
@media print {
  @page { size: A4; margin: 14mm; }
  html { background: #fff; }
  body { font-size: 10pt; }
  main { max-width: none; padding: 0; }
  .privacy, .metric, .panel, .table-wrap {
    print-color-adjust: exact;
    -webkit-print-color-adjust: exact;
  }
  .contents { columns: 2; }
  h2 { break-after: avoid; }
  tr, .metric, .panel { break-inside: avoid; }
  .table-wrap { overflow: visible; }
  .chart-panel .chart { width: 100%; max-width: 100%; }
  .back-to-contents { display: none; }
  footer { margin-top: 24px; }
}
"""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f'<meta name="description" content="{html.escape(notice, quote=True)}">'
        f'<meta http-equiv="Content-Security-Policy" content="{html.escape(csp, quote=True)}">'
        f"<title>{html.escape(document_title)}</title><style>{css}</style></head><body><main>"
        f'<header><p class="eyebrow">{html.escape(eyebrow)}</p>'
        f"<h1>{html.escape(document_title)}</h1>"
        f'<p class="lede">{html.escape(lede)}</p>'
        f'<aside class="privacy">{html.escape(notice)}</aside></header>'
        f'<section id="summary"><h2>{html.escape(summary_title)}</h2>'
        f'<div class="metrics">{metric_cards}</div>'
        f'<dl class="summary-breakdowns" aria-label="Recovery count breakdowns">'
        f"{summary_statistics}</dl>"
        '<div class="panel chart-panel" tabindex="0" role="region" '
        'aria-label="Scrollable recovered library chart">'
        f"{_svg_chart(model.library_chart, title=library_chart_title)}"
        "</div></section>"
        f'<nav aria-label="Report contents"><h2 id="report-contents">Contents</h2>'
        f'<ol class="contents">{contents}'
        '<li><a href="#media-statistics">Aggregate media statistics</a></li></ol></nav>'
        + "".join(section_fragments)
        + '<section id="media-statistics"><h2>Aggregate media statistics</h2>'
        '<p class="section-note">Counts only. The visual reports do not embed or request remote '
        "media.</p>"
        f'<div class="panel"><dl class="stats">{media_statistics}</dl></div>'
        '<div class="panel chart-panel" tabindex="0" role="region" '
        'aria-label="Scrollable recovered media-reference chart">'
        f"{_svg_chart(model.media_chart, title='Recovered media references')}"
        "</div></section>"
        f"<footer>{html.escape(footer_notice)}"
        "</footer></main></body></html>"
    )


def _font_candidates() -> tuple[_FontCandidate, ...]:
    package_fonts = Path(reportlab.__file__).resolve().parent / "fonts"
    fallback = _FontCandidate(
        label="bundled Bitstream Vera",
        regular=package_fonts / "Vera.ttf",
        bold=package_fonts / "VeraBd.ttf",
        italic=package_fonts / "VeraIt.ttf",
        bold_italic=package_fonts / "VeraBI.ttf",
    )
    if sys.platform == "darwin":
        supplemental = Path("/System/Library/Fonts/Supplemental")
        return (
            _FontCandidate(
                label="macOS Arial Unicode and Arial",
                regular=supplemental / "Arial Unicode.ttf",
                bold=supplemental / "Arial Bold.ttf",
                italic=supplemental / "Arial Italic.ttf",
                bold_italic=supplemental / "Arial Bold Italic.ttf",
            ),
            _FontCandidate(
                label="macOS Arial",
                regular=supplemental / "Arial.ttf",
                bold=supplemental / "Arial Bold.ttf",
                italic=supplemental / "Arial Italic.ttf",
                bold_italic=supplemental / "Arial Bold Italic.ttf",
            ),
            fallback,
        )
    if os.name == "nt":
        windows_fonts = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
        return (
            _FontCandidate(
                label="Windows Arial Unicode and Arial",
                regular=windows_fonts / "arialuni.ttf",
                bold=windows_fonts / "arialbd.ttf",
                italic=windows_fonts / "ariali.ttf",
                bold_italic=windows_fonts / "arialbi.ttf",
            ),
            _FontCandidate(
                label="Windows Arial",
                regular=windows_fonts / "arial.ttf",
                bold=windows_fonts / "arialbd.ttf",
                italic=windows_fonts / "ariali.ttf",
                bold_italic=windows_fonts / "arialbi.ttf",
            ),
            fallback,
        )
    dejavu_roots = (
        Path("/usr/share/fonts/truetype/dejavu"),
        Path("/usr/share/fonts/dejavu"),
        Path("/usr/local/share/fonts"),
    )
    return (
        *(
            _FontCandidate(
                label="Linux DejaVu Sans",
                regular=root / "DejaVuSans.ttf",
                bold=root / "DejaVuSans-Bold.ttf",
                italic=root / "DejaVuSans-Oblique.ttf",
                bold_italic=root / "DejaVuSans-BoldOblique.ttf",
            )
            for root in dejavu_roots
        ),
        fallback,
    )


def _register_pdf_fonts() -> _FontFamily:
    for index, candidate in enumerate(_font_candidates(), 1):
        paths = (candidate.regular, candidate.bold, candidate.italic, candidate.bold_italic)
        if not all(path.is_file() and not path.is_symlink() for path in paths):
            continue
        family = _FontFamily(
            regular=f"TVTimeReport{index}",
            bold=f"TVTimeReport{index}-Bold",
            italic=f"TVTimeReport{index}-Italic",
            bold_italic=f"TVTimeReport{index}-BoldItalic",
        )
        try:
            for name, path in zip(
                (family.regular, family.bold, family.italic, family.bold_italic),
                paths,
                strict=True,
            ):
                pdfmetrics.registerFont(TTFont(name, str(path)))
            pdfmetrics.registerFontFamily(
                family.regular,
                normal=family.regular,
                bold=family.bold,
                italic=family.italic,
                boldItalic=family.bold_italic,
            )
        except Exception:
            # A platform font can exist but disallow embedding. Continue to the
            # next portable candidate without exposing its local path.
            continue
        return family
    raise PDFCapabilityError(PDF_FIDELITY_WARNING)


_SHAPING_REQUIRED_RANGES = (
    (0x0590, 0x08FF),  # Hebrew, Arabic, Syriac, Thaana, NKo and related RTL scripts
    (0x0900, 0x0DFF),  # Indic scripts through Sinhala
    (0x0E00, 0x0FFF),  # Thai, Lao and Tibetan
    (0x1000, 0x109F),  # Myanmar
    (0x1780, 0x17FF),  # Khmer
    (0x1800, 0x18AF),  # Mongolian
    (0xA840, 0xA8FF),  # Phags-pa, Saurashtra and Devanagari extensions
    (0xA980, 0xAA7F),  # Javanese, Myanmar extensions, Cham and related scripts
    (0xABC0, 0xABFF),  # Meetei Mayek
    (0xFB1D, 0xFDFF),  # Hebrew and Arabic presentation forms
    (0xFE70, 0xFEFF),  # Arabic presentation forms B
)


def _model_characters(model: VisualReportModel) -> set[str]:
    values: list[str] = [SYNTHETIC_FIXTURE_NOTICE if model.synthetic_fixture else PRIVATE_NOTICE]
    values.extend(metric.label for metric in model.metrics)
    values.extend(metric.label for metric in model.library_chart)
    values.extend(metric.label for metric in model.media_chart)
    for section in model.sections:
        values.extend((section.title, section.description))
        for row in section.rows:
            values.extend((row.name, row.details))
    for statistic in (*model.summary_statistics, *model.media_statistics):
        values.extend((statistic.label, statistic.value))
    return set("".join(values))


def _requires_complex_shaping(character: str) -> bool:
    codepoint = ord(character)
    if character in {"\u200c", "\u200d"} or unicodedata.combining(character):
        return True
    if unicodedata.bidirectional(character) in {"R", "AL", "AN", "RLE", "RLO", "RLI"}:
        return True
    return any(start <= codepoint <= end for start, end in _SHAPING_REQUIRED_RANGES)


def _validate_pdf_fidelity(model: VisualReportModel, font_family: _FontFamily) -> None:
    characters = _model_characters(model)
    if any(_requires_complex_shaping(character) for character in characters):
        raise PDFCapabilityError(PDF_FIDELITY_WARNING)
    font = pdfmetrics.getFont(font_family.regular)
    mapping = getattr(getattr(font, "face", None), "charToGlyph", {})
    for character in characters:
        if character.isspace():
            continue
        glyph = mapping.get(ord(character)) if isinstance(mapping, dict) else None
        if glyph in {None, 0}:
            raise PDFCapabilityError(PDF_FIDELITY_WARNING)


class _BarChart(Flowable):
    def __init__(
        self,
        metrics: Sequence[ReportMetric],
        *,
        font_family: _FontFamily,
        width: float,
    ) -> None:
        super().__init__()
        self.metrics = tuple(metrics) or (ReportMetric("No recovered rows", 0),)
        self.font_family = font_family
        self.width = width
        self.height = 13 * mm + len(self.metrics) * 7.2 * mm

    def wrap(self, available_width: float, _available_height: float) -> tuple[float, float]:
        self.width = min(self.width, available_width)
        return self.width, self.height

    def draw(self) -> None:
        maximum = max((metric.value for metric in self.metrics), default=0) or 1
        label_width = min(52 * mm, self.width * 0.38)
        value_width = 12 * mm
        chart_width = max(20 * mm, self.width - label_width - value_width)
        self.canv.setFont(self.font_family.regular, 7.4)
        for index, metric in enumerate(self.metrics):
            y = self.height - 10 * mm - index * 7.2 * mm
            label = metric.label if len(metric.label) <= 31 else metric.label[:28] + "..."
            self.canv.setFillColor(HexColor("#27344d"))
            self.canv.drawString(0, y + 1.5 * mm, label)
            self.canv.setFillColor(HexColor("#e5ebf4"))
            self.canv.roundRect(label_width, y, chart_width, 4.2 * mm, 1.5 * mm, fill=1, stroke=0)
            if metric.value:
                corner_radius = 1.5 * mm
                proportional_width = chart_width * metric.value / maximum
                bar_width = min(chart_width, max(2 * corner_radius, proportional_width))
                self.canv.setFillColor(HexColor("#2864c7"))
                self.canv.roundRect(
                    label_width,
                    y,
                    bar_width,
                    4.2 * mm,
                    corner_radius,
                    fill=1,
                    stroke=0,
                )
            self.canv.setFillColor(HexColor("#182a4d"))
            self.canv.setFont(self.font_family.bold, 7.4)
            self.canv.drawRightString(self.width, y + 1.5 * mm, str(metric.value))
            self.canv.setFont(self.font_family.regular, 7.4)


class _VisualReportDocTemplate(BaseDocTemplate):
    def __init__(
        self,
        filename: str | BinaryIO,
        *,
        font_family: _FontFamily,
        cancellation_check: Callable[[], None] | None,
        synthetic_fixture: bool,
    ) -> None:
        # Canonical bytes let the acceptance validator reject visual-only PDF
        # mutations such as opaque overlays before a parser touches them.
        super().__init__(
            filename,
            pagesize=A4,
            leftMargin=17 * mm,
            rightMargin=17 * mm,
            topMargin=23 * mm,
            bottomMargin=19 * mm,
            title=(
                SYNTHETIC_FIXTURE_NOTICE if synthetic_fixture else "TV Time recovered-data report"
            ),
            author="TV Time Backup Extractor",
            subject=(
                "Synthetic report-layout quality assurance fixture"
                if synthetic_fixture
                else "Private recovered TV Time data"
            ),
            invariant=1,
        )
        self.font_family = font_family
        self.cancellation_check = cancellation_check
        self.synthetic_fixture = synthetic_fixture
        frame = Frame(
            self.leftMargin,
            self.bottomMargin,
            self.width,
            self.height,
            id="report-body",
        )
        self.addPageTemplates(
            PageTemplate(id="report", frames=(frame,), onPage=self._draw_header_footer)
        )

    def _draw_header_footer(self, canvas: Canvas, _document: BaseDocTemplate) -> None:
        canvas.saveState()
        canvas._doc.Catalog.Lang = PDFString("en-AU")
        canvas.setTitle(
            SYNTHETIC_FIXTURE_NOTICE if self.synthetic_fixture else "TV Time recovered-data report"
        )
        canvas.setAuthor("TV Time Backup Extractor")
        canvas.setSubject(
            "Synthetic report-layout quality assurance fixture"
            if self.synthetic_fixture
            else "Private recovered TV Time data"
        )
        canvas.setStrokeColor(HexColor("#dce3ef"))
        canvas.setLineWidth(0.5)
        canvas.line(17 * mm, A4[1] - 17 * mm, A4[0] - 17 * mm, A4[1] - 17 * mm)
        canvas.setFont(self.font_family.bold, 7.2)
        canvas.setFillColor(HexColor("#182a4d"))
        canvas.drawString(
            17 * mm,
            A4[1] - 13.5 * mm,
            (
                "SYNTHETIC QA FIXTURE - NOT USER DATA"
                if self.synthetic_fixture
                else "TV Time private recovery report"
            ),
        )
        canvas.line(17 * mm, 14 * mm, A4[0] - 17 * mm, 14 * mm)
        canvas.setFont(self.font_family.regular, 6.8)
        canvas.setFillColor(HexColor("#687186"))
        canvas.drawString(
            17 * mm,
            9.5 * mm,
            (
                "Synthetic QA fixture - not recovered user data"
                if self.synthetic_fixture
                else "Private - contains viewing history"
            ),
        )
        canvas.drawRightString(A4[0] - 17 * mm, 9.5 * mm, f"Page {self.page}")
        canvas.restoreState()

    def afterFlowable(self, flowable: Flowable) -> None:
        if self.cancellation_check is not None:
            self.cancellation_check()
        if not isinstance(flowable, Paragraph) or flowable.style.name != "ReportHeading1":
            return
        title = flowable.getPlainText()
        identifier = re.sub(r"[^a-z0-9]+", "-", title.casefold()).strip("-") or "section"
        bookmark = f"section-{identifier}"
        self.canv.bookmarkPage(bookmark)
        self.canv.addOutlineEntry(title, bookmark, level=0, closed=False)


def _pdf_styles(font_family: _FontFamily) -> dict[str, ParagraphStyle]:
    sample = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=sample["Title"],
            fontName=font_family.bold,
            fontSize=28,
            leading=31,
            textColor=HexColor("#182a4d"),
            alignment=TA_LEFT,
            spaceAfter=5 * mm,
        ),
        "eyebrow": ParagraphStyle(
            "ReportEyebrow",
            parent=sample["Normal"],
            fontName=font_family.bold,
            fontSize=8,
            leading=10,
            textColor=HexColor("#2864c7"),
            spaceAfter=2 * mm,
        ),
        "body": ParagraphStyle(
            "ReportBody",
            parent=sample["BodyText"],
            fontName=font_family.regular,
            fontSize=9.2,
            leading=13,
            textColor=HexColor("#27344d"),
            spaceAfter=3 * mm,
        ),
        "notice": ParagraphStyle(
            "ReportNotice",
            parent=sample["BodyText"],
            fontName=font_family.bold,
            fontSize=8.3,
            leading=11,
            textColor=HexColor("#681824"),
        ),
        "heading1": ParagraphStyle(
            "ReportHeading1",
            parent=sample["Heading1"],
            fontName=font_family.bold,
            fontSize=17,
            leading=20,
            textColor=HexColor("#182a4d"),
            spaceBefore=4 * mm,
            spaceAfter=2.5 * mm,
            keepWithNext=True,
        ),
        "heading2": ParagraphStyle(
            "ReportHeading2",
            parent=sample["Heading2"],
            fontName=font_family.bold,
            fontSize=12,
            leading=15,
            textColor=HexColor("#182a4d"),
            spaceBefore=3 * mm,
            spaceAfter=2 * mm,
        ),
        "card": ParagraphStyle(
            "ReportCard",
            parent=sample["BodyText"],
            fontName=font_family.regular,
            fontSize=8,
            leading=10,
            textColor=HexColor("#5d6678"),
            alignment=TA_CENTER,
        ),
        "table_name": ParagraphStyle(
            "ReportTableName",
            parent=sample["BodyText"],
            fontName=font_family.regular,
            fontSize=8.2,
            leading=10.5,
            textColor=HexColor("#172033"),
        ),
        "table_details": ParagraphStyle(
            "ReportTableDetails",
            parent=sample["BodyText"],
            fontName=font_family.regular,
            fontSize=7.5,
            leading=9.5,
            textColor=HexColor("#5d6678"),
        ),
        "table_header": ParagraphStyle(
            "ReportTableHeader",
            parent=sample["BodyText"],
            fontName=font_family.bold,
            fontSize=7,
            leading=8.5,
            textColor=colors.white,
        ),
        "toc": ParagraphStyle(
            "ReportTOC",
            parent=sample["BodyText"],
            fontName=font_family.regular,
            fontSize=9.5,
            leading=14,
            textColor=HexColor("#27344d"),
            leftIndent=4 * mm,
            firstLineIndent=0,
        ),
    }


def _notice_box(
    text: str,
    *,
    styles: Mapping[str, ParagraphStyle],
    width: float,
) -> Table:
    box = Table(
        [[Paragraph(xml_escape(text), styles["notice"])]],
        colWidths=(width,),
    )
    box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), HexColor("#fff1f3")),
                ("BOX", (0, 0), (-1, -1), 0.7, HexColor("#d56978")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return box


def _metric_cards(
    metrics: Sequence[ReportMetric],
    *,
    styles: Mapping[str, ParagraphStyle],
    width: float,
) -> Table:
    cells = [
        Paragraph(
            f'<font size="18" color="#182a4d"><b>{metric.value}</b></font><br/>'
            f"{xml_escape(metric.label)}",
            styles["card"],
        )
        for metric in metrics
    ]
    while len(cells) % 4:
        cells.append("")
    rows = [cells[index : index + 4] for index in range(0, len(cells), 4)]
    table = Table(rows, colWidths=(width / 4,) * 4, rowHeights=(22 * mm,) * len(rows))
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f3f6fb")),
                ("BOX", (0, 0), (-1, -1), 0.6, HexColor("#dce3ef")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#dce3ef")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _summary_statistics_table(
    statistics: Sequence[AggregateStatistic],
    *,
    styles: Mapping[str, ParagraphStyle],
    width: float,
) -> Table:
    cells = [
        Paragraph(
            f"<b>{xml_escape(statistic.label)}</b><br/>"
            f'<font color="#5d6678">{xml_escape(statistic.value)}</font>',
            styles["table_name"],
        )
        for statistic in statistics
    ]
    table = Table([cells], colWidths=(width / len(cells),) * len(cells))
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f6f8fc")),
                ("BOX", (0, 0), (-1, -1), 0.6, HexColor("#dce3ef")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#dce3ef")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def _section_table(
    section: ReportSection,
    *,
    styles: Mapping[str, ParagraphStyle],
    width: float,
) -> Flowable:
    if not section.rows:
        return Paragraph("No rows were recorded for this section.", styles["body"])
    table_rows: list[list[object]] = [
        [
            Paragraph("#", styles["table_header"]),
            Paragraph("Recovered name", styles["table_header"]),
            Paragraph("Recovered details", styles["table_header"]),
        ]
    ]
    table_rows.extend(
        [
            Paragraph(str(index), styles["table_details"]),
            Paragraph(xml_escape(row.name), styles["table_name"]),
            Paragraph(xml_escape(row.details), styles["table_details"]),
        ]
        for index, row in enumerate(section.rows, 1)
    )
    table = LongTable(
        table_rows,
        colWidths=(10 * mm, 64 * mm, width - 74 * mm),
        repeatRows=1,
        splitByRow=1,
        splitInRow=1,
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#182a4d")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), (colors.white, HexColor("#f8faff"))),
                ("GRID", (0, 0), (-1, -1), 0.35, HexColor("#dce3ef")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _statistics_table(
    statistics: Sequence[AggregateStatistic],
    *,
    styles: Mapping[str, ParagraphStyle],
    width: float,
) -> LongTable:
    rows: list[list[object]] = [
        [
            Paragraph("Aggregate statistic", styles["table_header"]),
            Paragraph("Value", styles["table_header"]),
        ]
    ]
    rows.extend(
        [
            Paragraph(xml_escape(statistic.label), styles["table_name"]),
            Paragraph(xml_escape(statistic.value), styles["table_details"]),
        ]
        for statistic in statistics
    )
    table = LongTable(rows, colWidths=(width * 0.72, width * 0.28), repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#182a4d")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), (colors.white, HexColor("#f8faff"))),
                ("GRID", (0, 0), (-1, -1), 0.35, HexColor("#dce3ef")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _pdf_story(
    model: VisualReportModel,
    *,
    styles: Mapping[str, ParagraphStyle],
    font_family: _FontFamily,
    width: float,
) -> list[Flowable]:
    if model.synthetic_fixture:
        eyebrow = "SYNTHETIC VISUAL TEST CATALOGUE"
        title = SYNTHETIC_FIXTURE_NOTICE
        summary_title = "Synthetic fixture summary"
        introduction = (
            "Generated entirely from synthetic QA records to exercise multi-page report layout. "
            "These counts and names are not recovered user data."
        )
        notice = SYNTHETIC_FIXTURE_NOTICE
    else:
        eyebrow = "PRIVATE OFFLINE RECOVERY CATALOGUE"
        title = "TV Time recovered-data report"
        summary_title = "Recovery summary"
        introduction = (
            "Every recovered series, movie, favorite, episode, and watch-event record is listed "
            "in this report. Each available title/name is preserved; missing names are stated "
            "rather than guessed."
        )
        notice = PRIVATE_NOTICE
    story: list[Flowable] = [
        Paragraph(eyebrow, styles["eyebrow"]),
        Paragraph(title, styles["title"]),
        Paragraph(introduction, styles["body"]),
        Paragraph(
            "For accessible headings, navigation, and table structure, use the complete offline "
            "HTML report. This PDF is the print-friendly companion.",
            styles["body"],
        ),
        _notice_box(notice, styles=styles, width=width),
        Spacer(1, 7 * mm),
        Paragraph(summary_title, styles["heading1"]),
        _metric_cards(model.metrics, styles=styles, width=width),
        Spacer(1, 3 * mm),
        _summary_statistics_table(model.summary_statistics, styles=styles, width=width),
        Spacer(1, 3 * mm),
        _BarChart(model.library_chart, font_family=font_family, width=width),
        PageBreak(),
        Paragraph("Contents", styles["title"]),
    ]
    contents = [
        Paragraph(f"&bull; {xml_escape(title)}", styles["toc"])
        for title in (
            summary_title,
            *(section.title for section in model.sections),
            "Aggregate media statistics",
        )
    ]
    story.extend(
        [
            Paragraph(
                "The contents list is generated from the same sections rendered below.",
                styles["body"],
            ),
            *contents,
            PageBreak(),
        ]
    )
    for section in model.sections:
        story.extend(
            [
                CondPageBreak(32 * mm),
                Paragraph(xml_escape(section.title), styles["heading1"]),
                Paragraph(xml_escape(section.description), styles["body"]),
                _section_table(section, styles=styles, width=width),
                Spacer(1, 3 * mm),
            ]
        )
    story.extend(
        [
            CondPageBreak(45 * mm),
            Paragraph("Aggregate media statistics", styles["heading1"]),
            Paragraph(
                "Counts only. This PDF does not embed or request remote media.",
                styles["body"],
            ),
            _statistics_table(model.media_statistics, styles=styles, width=width),
            Spacer(1, 5 * mm),
            Paragraph("Media-reference overview", styles["heading2"]),
            _BarChart(model.media_chart, font_family=font_family, width=width),
        ]
    )
    return story


def write_html_report(
    model: VisualReportModel,
    *,
    output_path: Path,
    cancellation_check: Callable[[], None] | None = None,
) -> Path:
    if output_path.exists() or output_path.is_symlink():
        raise OutputExistsError("The staged offline HTML report already exists.")
    partial = output_path.with_name(output_path.name + ".partial")
    if partial.exists() or partial.is_symlink():
        raise OutputExistsError("An incomplete staged offline HTML report already exists.")
    content = render_html_report(model, cancellation_check=cancellation_check)
    write_text_private(partial, content)
    if cancellation_check is not None:
        cancellation_check()
    partial.replace(output_path)
    secure_file(output_path)
    return output_path


def write_pdf_report(
    model: VisualReportModel,
    *,
    output_path: Path,
    cancellation_check: Callable[[], None] | None = None,
) -> Path:
    if str(reportlab.Version) != REPORTLAB_VERSION:
        raise PDFCapabilityError(PDF_FIDELITY_WARNING)
    if output_path.exists() or output_path.is_symlink():
        raise OutputExistsError("The staged PDF report already exists.")
    partial = output_path.with_name(output_path.name + ".partial")
    if partial.exists() or partial.is_symlink():
        raise OutputExistsError("An incomplete staged PDF report already exists.")
    if cancellation_check is not None:
        cancellation_check()
    font_family = _register_pdf_fonts()
    _validate_pdf_fidelity(model, font_family)
    styles = _pdf_styles(font_family)
    output = io.BytesIO()
    document = _VisualReportDocTemplate(
        output,
        font_family=font_family,
        cancellation_check=cancellation_check,
        synthetic_fixture=model.synthetic_fixture,
    )
    try:
        document.multiBuild(
            _pdf_story(
                model,
                styles=styles,
                font_family=font_family,
                width=document.width,
            )
        )
    except LayoutError as exc:
        raise PDFCapabilityError(PDF_FIDELITY_WARNING) from exc
    write_bytes_private(partial, output.getvalue(), exclusive=True)
    if cancellation_check is not None:
        cancellation_check()
    partial.replace(output_path)
    secure_file(output_path)
    return output_path


def write_visual_reports(
    model: VisualReportModel,
    *,
    analysis_directory: Path,
    cancellation_check: Callable[[], None] | None = None,
) -> dict[str, str]:
    """Write both visual formats inside an already-private report staging directory."""

    html_path = write_html_report(
        model,
        output_path=analysis_directory / HTML_REPORT_FILENAME,
        cancellation_check=cancellation_check,
    )
    result = {
        "visual_report": str(html_path),
        "pdf_status": "generated",
        "pdf_warning": "",
    }
    try:
        pdf_path = write_pdf_report(
            model,
            output_path=analysis_directory / PDF_REPORT_FILENAME,
            cancellation_check=cancellation_check,
        )
    except PDFCapabilityError:
        result["pdf_status"] = "omitted"
        result["pdf_warning"] = PDF_FIDELITY_WARNING
    else:
        result["pdf_report"] = str(pdf_path)
    return result
