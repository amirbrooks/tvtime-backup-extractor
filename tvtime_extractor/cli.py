from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .analyze import analyze_extraction
from .errors import TVTimeError, UserInputError
from .extract import extract_backup, public_summary, read_backup_password
from .report import build_report
from .safety import set_private_umask


def _progress(message: str) -> None:
    print(f"[tvtime-extractor] {message}", file=sys.stderr, flush=True)


def _add_extraction_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--backup",
        required=True,
        type=Path,
        help="Encrypted Finder, Apple Devices, or iTunes backup directory",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Private encrypted destination; TVTime-Extraction will be created inside it",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read one password line from standard input instead of prompting securely",
    )
    parser.add_argument(
        "--acknowledge-sensitive-output",
        action="store_true",
        help="Confirm that the destination will contain highly sensitive decrypted data",
    )
    parser.add_argument(
        "--include-decrypted-manifest",
        action="store_true",
        help="Also retain the full decrypted device manifest (advanced and highly sensitive)",
    )


def _add_output_format_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable JSON summary instead of the default readable summary",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tvtime-extractor",
        description=(
            "Recover TV Time data from an encrypted local iOS backup without modifying "
            "the phone or source backup."
        ),
        epilog="Read README.md and docs/privacy.md before extracting real data.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show a traceback for unexpected errors (may expose private local paths)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    recover = subparsers.add_parser(
        "recover",
        help="Run extraction, analysis, and report generation in one guided workflow",
    )
    _add_extraction_arguments(recover)
    _add_output_format_argument(recover)
    recover.add_argument(
        "--include-raw-cache",
        action="store_true",
        help="Export verbatim cached API payloads (advanced and potentially account-identifying)",
    )

    extract = subparsers.add_parser(
        "extract",
        help="Decrypt only the TV Time app container from a local iOS backup",
    )
    _add_extraction_arguments(extract)
    _add_output_format_argument(extract)

    analyze = subparsers.add_parser(
        "analyze",
        help="Create normalized private CSV/JSON tables from an existing extraction",
    )
    analyze.add_argument("--extraction", required=True, type=Path)
    _add_output_format_argument(analyze)
    analyze.add_argument(
        "--include-raw-cache",
        action="store_true",
        help="Export verbatim cached API payloads (advanced and potentially account-identifying)",
    )

    report = subparsers.add_parser(
        "report",
        help="Create a readable private report and sanitized media-reference tables",
    )
    report.add_argument("--extraction", required=True, type=Path)
    _add_output_format_argument(report)
    return parser


def _require_sensitive_output_acknowledgement(args: argparse.Namespace) -> None:
    if not args.acknowledge_sensitive_output:
        raise UserInputError(
            "Extraction writes sensitive plaintext while the destination is mounted. "
            "Read docs/privacy.md, choose encrypted storage, and rerun with "
            "--acknowledge-sensitive-output."
        )


def _run_extraction(args: argparse.Namespace):
    _require_sensitive_output_acknowledgement(args)
    passphrase = read_backup_password(password_stdin=args.password_stdin)
    try:
        _progress("Opening the encrypted backup and copying the TV Time app data...")
        return extract_backup(
            backup_directory=args.backup,
            output_directory=args.output,
            passphrase=passphrase,
            include_decrypted_manifest=args.include_decrypted_manifest,
        )
    finally:
        # Python strings cannot be reliably erased from memory. This only drops
        # the CLI's reference; the password is never intentionally written to disk.
        passphrase = ""


def _print_extraction_summary(result) -> None:
    summary = public_summary(result)
    print("TV Time extraction summary")
    print(f"  Files copied: {summary['files_extracted']} of {summary['files_expected']}")
    print(f"  Copy failures: {summary['failure_count']}")
    print(f"  Size warnings: {summary['size_discrepancy_count']}")
    print(f"  Bytes selected from backup metadata: {summary['selected_declared_bytes']}")
    print(f"  Bytes copied: {summary['bytes_extracted']}")
    print(f"  Private extraction: {summary['extraction_root']}")


def _print_analysis_summary(summary: dict[str, object]) -> None:
    movie_total = int(summary["watched_movies"]) + int(summary["movie_watchlist"])
    print("TV Time analysis summary")
    print(f"  TV series titles: {summary['series_library']}")
    print(
        f"  Movie titles: {movie_total} "
        f"({summary['watched_movies']} watched; {summary['movie_watchlist']} saved)"
    )
    print(f"  Favorites: {summary['favorite_shows']} shows; {summary['favorite_movies']} movies")
    print(
        f"  Watch events: {summary['watch_events']} "
        f"({summary['watch_events_with_titles']} matched to a title)"
    )
    print(f"  Identifiable cached episodes: {summary['episode_cache_unique']}")
    print(f"  Parser status: {summary['parser_status']}")


def _print_report_summary(summary: dict[str, object]) -> None:
    movie_total = int(summary["watched_movies"]) + int(summary["movie_watchlist"])
    print("Readable recovery report")
    print(f"  Named TV series: {summary['series']}")
    print(f"  Named movies: {movie_total}")
    print(f"  Named watch events: {summary['named_watch_events']} of {summary['watch_events']}")
    print(f"  Image references: {summary['image_cache_references']}")
    print(f"  Trailer references: {summary['trailer_references']}")
    print(f"  Report: {summary['report']}")
    print("  The report lists every identifiable recovered title/name found in the local cache.")


def main(argv: Sequence[str] | None = None) -> int:
    set_private_umask()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "extract":
            result = _run_extraction(args)
            _progress(
                f"Extracted {result.summary['files_extracted']} of "
                f"{result.summary['files_expected']} selected files."
            )
            if result.summary["size_discrepancies"]:
                _progress(
                    "Warning: some decrypted sizes differed from backup metadata; "
                    "details are retained in the private metadata summary."
                )
            if result.has_failures:
                if args.json:
                    print(json.dumps(public_summary(result), indent=2, ensure_ascii=False))
                else:
                    _print_extraction_summary(result)
                print(
                    "Extraction finished with failures. Review the private metadata/summary.json; "
                    "analysis was not started.",
                    file=sys.stderr,
                )
                return 3
            if args.json:
                print(json.dumps(public_summary(result), indent=2, ensure_ascii=False))
            else:
                _print_extraction_summary(result)
            return 0

        if args.command == "recover":
            result = _run_extraction(args)
            _progress(
                f"Extracted {result.summary['files_extracted']} of "
                f"{result.summary['files_expected']} selected files."
            )
            if result.summary["size_discrepancies"]:
                _progress(
                    "Warning: some decrypted sizes differed from backup metadata; "
                    "analysis will validate the recovered databases."
                )
            if result.has_failures:
                if args.json:
                    print(json.dumps({"extraction": public_summary(result)}, indent=2))
                else:
                    _print_extraction_summary(result)
                print(
                    "Extraction finished with failures. Review the private metadata/summary.json; "
                    "analysis was not started.",
                    file=sys.stderr,
                )
                return 3
            _progress("Analyzing the recovered TV Time cache...")
            analysis_summary = analyze_extraction(
                extraction_directory=result.extraction_root,
                include_raw_cache=args.include_raw_cache,
            )
            _progress("Building the readable report and media-reference tables...")
            report_summary = build_report(extraction_directory=result.extraction_root)
            if args.json:
                print(
                    json.dumps(
                        {
                            "extraction": public_summary(result),
                            "analysis": analysis_summary,
                            "report": report_summary,
                        },
                        indent=2,
                        ensure_ascii=False,
                    )
                )
            else:
                _print_extraction_summary(result)
                print()
                _print_analysis_summary(analysis_summary)
                print()
                _print_report_summary(report_summary)
            _progress("Recovery completed successfully.")
            return 0

        if args.command == "analyze":
            _progress("Analyzing the recovered TV Time cache...")
            summary = analyze_extraction(
                extraction_directory=args.extraction,
                include_raw_cache=args.include_raw_cache,
            )
            if args.json:
                print(json.dumps(summary, indent=2, ensure_ascii=False))
            else:
                _print_analysis_summary(summary)
            return 0

        if args.command == "report":
            _progress("Building the readable report and media-reference tables...")
            summary = build_report(extraction_directory=args.extraction)
            if args.json:
                print(json.dumps(summary, indent=2, ensure_ascii=False))
            else:
                _print_report_summary(summary)
            return 0

        parser.error(f"Unknown command: {args.command}")
    except TVTimeError as exc:
        if args.debug:
            raise
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        if args.debug:
            raise
        message = (
            f"error: unexpected {type(exc).__name__}. "
            "Rerun with --debug only in a private terminal."
        )
        print(
            message,
            file=sys.stderr,
        )
        return 1
    return 2


def entrypoint() -> None:
    raise SystemExit(main())
