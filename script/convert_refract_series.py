from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tvtime_extractor.errors import OutputExistsError, TVTimeError, UnsafePathError  # noqa: E402
from tvtime_extractor.refract import (  # noqa: E402
    RefractConversionError,
    convert_refract_series,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Convert a private TV Time analysis directory into a Refract-compatible series JSON "
            "without using the network."
        )
    )
    parser.add_argument(
        "--analysis",
        required=True,
        type=Path,
        help="Private analysis directory containing series_library.csv.",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="New private output directory; its immediate parent must already exist.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        result = convert_refract_series(
            analysis_directory=arguments.analysis,
            output_directory=arguments.output,
        )
    except OutputExistsError:
        print(
            "[tvtime-refract] The output already exists. Choose a new private directory.",
            file=sys.stderr,
        )
        return 2
    except UnsafePathError:
        print(
            "[tvtime-refract] The input or output did not meet the private local path "
            "requirements.",
            file=sys.stderr,
        )
        return 2
    except RefractConversionError as exc:
        print(f"[tvtime-refract] {exc}", file=sys.stderr)
        return 2
    except TVTimeError:
        print("[tvtime-refract] The conversion could not be completed safely.", file=sys.stderr)
        return 1
    except Exception:
        print("[tvtime-refract] The conversion failed safely.", file=sys.stderr)
        return 1

    stats = result.stats
    print(
        f"[tvtime-refract] Converted {stats.series} series and {stats.episodes} recovered episodes."
    )
    print(
        f"[tvtime-refract] Ignored {stats.unmatched_episode_rows} unmatched episode rows, "
        f"{stats.ignored_episode_rows} unusable episode rows, and "
        f"{stats.unmatched_favorite_rows} unmatched favorite rows."
    )
    print("[tvtime-refract] Refract series JSON created successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
