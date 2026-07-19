from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tvtime_extractor.safety import secure_directory  # noqa: E402
from tvtime_extractor.visual_report import (  # noqa: E402
    build_visual_report_model,
    write_html_report,
    write_pdf_report,
)

SYNTHETIC_REPORT_STEM = "SYNTHETIC-QA-FIXTURE-NOT-RECOVERED-USER-DATA"
SYNTHETIC_HTML_FILENAME = f"{SYNTHETIC_REPORT_STEM}.html"
SYNTHETIC_PDF_FILENAME = f"{SYNTHETIC_REPORT_STEM}.pdf"


def numbered_rows(count: int, prefix: str) -> list[dict[str, object]]:
    return [
        {
            "name": f"{prefix} {index:03d}",
            "status": "recovered",
            "followed_at": "2026-01-02T03:04:05Z",
            "last_activity_at": "2026-02-03T04:05:06Z",
            "country": "AU",
            "is_ended": index % 3 == 0,
            "watched_at": "2026-02-03T04:05:06Z",
            "first_release_date": "2025-06-07",
            "runtime_seconds": 5_400,
            "genres": "Drama | Mystery",
            "filters": "watched",
            "watched_episode_count": index % 20,
            "aired_episode_count": 20,
            "season": 2,
            "episode": index,
            "episode_name": f"Synthetic episode {index:03d}",
            "air_date": "2026-02-01T00:00:00Z",
            "seen": True,
            "seen_date": "2026-02-03T04:05:06Z",
            "is_watched": True,
            "movie_name": f"Synthetic watch event {index:03d}",
            "type": "watch",
            "runtime": 2_700,
            "created_at": "2026-02-03T04:05:06Z",
        }
        for index in range(1, count + 1)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a private synthetic report for native PDF rendering checks."
    )
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    analysis = secure_directory(arguments.output.expanduser().absolute())
    model = build_visual_report_model(
        series=numbered_rows(180, "Synthetic series"),
        watched_movies=numbered_rows(58, "Synthetic watched movie"),
        movie_watchlist=numbered_rows(11, "Synthetic saved movie"),
        favorite_shows=numbered_rows(12, "Synthetic favorite show"),
        favorite_movies=numbered_rows(9, "Synthetic favorite movie"),
        episodes=numbered_rows(44, "Synthetic show"),
        watch_events=numbered_rows(150, "Synthetic event"),
        extracted_file_count=52,
        image_cache_status="catalogued",
        trailer_count=17,
        media_url_counts={"image": 38, "trailer": 17},
        image_category_counts={"poster": 31, "episode": 7},
        size_discrepancies=[
            {
                "relative_path": f"Documents/Synthetic-{index}.bin",
                "declared_size": 1_000 + index,
                "actual_size": 990 + index,
            }
            for index in range(1, 7)
        ],
        synthetic_fixture=True,
    )
    html = write_html_report(model, output_path=analysis / SYNTHETIC_HTML_FILENAME)
    pdf = write_pdf_report(model, output_path=analysis / SYNTHETIC_PDF_FILENAME)
    for output in (html, pdf):
        if not output.is_file() or output.is_symlink():
            raise RuntimeError("Synthetic visual report output was unavailable")
    print(pdf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
