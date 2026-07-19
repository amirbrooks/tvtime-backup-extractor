from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from . import __version__
from .analyze import analyze_extraction
from .errors import (
    PartialExtractionError,
    TVTimeError,
    UserInputError,
    insufficient_space_error,
    is_insufficient_space_error,
)
from .extract import public_summary, read_backup_password
from .models import (
    DestinationDirectoryIdentity,
    PreflightResult,
    RecoveryEvent,
    RecoveryEventKind,
    RecoveryRequest,
    RecoveryStage,
)
from .report import build_report
from .safety import (
    held_destination_parent,
    require_fresh_output_platform_support,
    set_private_umask,
)
from .service import RecoveryService


def _progress(message: str) -> None:
    print(f"[tvtime-extractor] {message}", file=sys.stderr, flush=True)


def _report_preflight(result: PreflightResult) -> None:
    _progress("Preflight passed: the backup is encrypted and marked finished.")
    _progress(
        f"Backup scan: {result.backup_regular_files} regular files, "
        f"{result.backup_logical_bytes} logical bytes."
    )
    _progress(
        f"Destination space: {result.destination_free_bytes} bytes free; "
        f"{result.minimum_working_bytes} bytes required for manifest processing."
    )


def _add_extraction_arguments(
    parser: argparse.ArgumentParser, *, allow_decrypted_manifest: bool = False
) -> None:
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
        help=(
            "New recovery-folder path on private encrypted storage; its parent must exist but "
            "this path must not already exist"
        ),
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
    if allow_decrypted_manifest:
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
        help=(
            "Show a private traceback that may expose backup paths, dependency details, or "
            "password text; never paste or share it"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    recover = subparsers.add_parser(
        "recover",
        help="Run extraction, analysis, and report generation in one guided workflow",
    )
    _add_extraction_arguments(recover)
    _add_output_format_argument(recover)

    extract = subparsers.add_parser(
        "extract",
        help="Decrypt only the TV Time app container from a local iOS backup",
    )
    _add_extraction_arguments(extract, allow_decrypted_manifest=True)
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


@contextmanager
def _held_cli_destination_parent(
    output: Path,
) -> Iterator[tuple[int, DestinationDirectoryIdentity, Path]]:
    with held_destination_parent(output) as (descriptor, identity_tuple, visible_output):
        identity = DestinationDirectoryIdentity(
            device=identity_tuple[0],
            inode=identity_tuple[1],
        )
        yield descriptor, identity, visible_output


def _run_extraction(args: argparse.Namespace):
    require_fresh_output_platform_support()
    _require_sensitive_output_acknowledgement(args)
    with _held_cli_destination_parent(args.output) as (
        destination_parent_descriptor,
        destination_identity,
        visible_output,
    ):
        request = RecoveryRequest(
            backup_directory=args.backup,
            output_directory=visible_output,
            acknowledge_sensitive_output=True,
            include_decrypted_manifest=args.include_decrypted_manifest,
            destination_parent_identity=destination_identity,
        )
        _progress("Checking that the encrypted backup is finished and the destination is safe...")
        service = RecoveryService()
        preflight = service.preflight(
            request,
            destination_parent_descriptor=destination_parent_descriptor,
        )
        _report_preflight(preflight)
        passphrase = read_backup_password(password_stdin=args.password_stdin)
        try:
            _progress("Opening the encrypted backup and copying the TV Time app data...")
            return service.extract(
                request,
                passphrase=passphrase,
                destination_parent_descriptor=destination_parent_descriptor,
                preflight_result=preflight,
            )
        finally:
            # Python strings cannot be reliably erased from memory. This only drops
            # the CLI's reference; the password is never intentionally written to disk.
            passphrase = ""


def _recovery_progress(event: RecoveryEvent) -> None:
    if event.stage is RecoveryStage.EXTRACTION and event.kind is RecoveryEventKind.COMPLETED:
        _progress(f"Extracted {event.current} of {event.total} selected files.")
        if event.details.get("size_discrepancy_count"):
            _progress(
                "Warning: some decrypted sizes differed from backup metadata; "
                "analysis will validate the recovered databases."
            )
        return
    if event.kind is not RecoveryEventKind.STARTED:
        return
    messages = {
        RecoveryStage.EXTRACTION: (
            "Opening the encrypted backup and copying the TV Time app data..."
        ),
        RecoveryStage.ANALYSIS: "Analyzing the recovered TV Time cache...",
        RecoveryStage.REPORT: "Building the readable report and media-reference tables...",
    }
    message = messages.get(event.stage)
    if message:
        _progress(message)


def _run_recovery(args: argparse.Namespace):
    require_fresh_output_platform_support()
    _require_sensitive_output_acknowledgement(args)
    with _held_cli_destination_parent(args.output) as (
        destination_parent_descriptor,
        destination_identity,
        visible_output,
    ):
        request = RecoveryRequest(
            backup_directory=args.backup,
            output_directory=visible_output,
            acknowledge_sensitive_output=True,
            include_raw_cache=False,
            include_decrypted_manifest=False,
            destination_parent_identity=destination_identity,
        )
        service = RecoveryService()
        _progress("Checking that the encrypted backup is finished and the destination is safe...")
        preflight = service.preflight(
            request,
            destination_parent_descriptor=destination_parent_descriptor,
        )
        _report_preflight(preflight)
        passphrase = read_backup_password(password_stdin=args.password_stdin)
        try:
            return service.recover(
                request,
                passphrase=passphrase,
                progress=_recovery_progress,
                destination_parent_descriptor=destination_parent_descriptor,
                preflight_result=preflight,
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
    print(f"  Recovered series records: {summary['series_library']}")
    print(
        f"  Recovered movie records: {movie_total} "
        f"({summary['watched_movies']} watched; {summary['movie_watchlist']} saved)"
    )
    print(f"  Favorites: {summary['favorite_shows']} shows; {summary['favorite_movies']} movies")
    print(
        f"  Watch events: {summary['watch_events']} "
        f"({summary['watch_events_with_titles']} matched to a title)"
    )
    print(f"  Recovered cached episode records: {summary['episode_cache_unique']}")
    print(f"  Parser status: {summary['parser_status']}")


def _print_report_summary(summary: dict[str, object]) -> None:
    movie_total = int(summary["watched_movies"]) + int(summary["movie_watchlist"])
    print("Readable recovery report")
    print(f"  Recovered series records: {summary['series']}")
    print(f"  Recovered movie records: {movie_total}")
    print(f"  Named watch events: {summary['named_watch_events']} of {summary['watch_events']}")
    print(f"  Image references: {summary['image_cache_references']}")
    print(f"  Trailer references: {summary['trailer_references']}")
    print(f"  Markdown report: {summary['report']}")
    if summary.get("visual_report"):
        print(f"  Offline HTML report: {summary['visual_report']}")
    if summary.get("pdf_report"):
        print(f"  Printable PDF report: {summary['pdf_report']}")
    elif summary.get("pdf_status") == "omitted":
        print(f"  PDF status: {summary.get('pdf_warning') or 'omitted for text fidelity'}")
    print("  The report lists every recovered record and each available title/name.")


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
            try:
                recovery = _run_recovery(args)
            except PartialExtractionError as exc:
                result = exc.extraction_result
                if result is not None:
                    _progress(
                        f"Extracted {result.summary['files_extracted']} of "
                        f"{result.summary['files_expected']} selected files."
                    )
                    if result.summary["size_discrepancies"]:
                        _progress(
                            "Warning: some decrypted sizes differed from backup metadata; "
                            "analysis will validate the recovered databases."
                        )
                    if args.json:
                        print(json.dumps({"extraction": public_summary(result)}, indent=2))
                    else:
                        _print_extraction_summary(result)
                print(
                    "Extraction finished with failures. Review the private metadata/summary.json; "
                    "analysis was not started.",
                    file=sys.stderr,
                )
                return exc.exit_code
            result = recovery.extraction
            analysis_summary = recovery.analysis
            report_summary = recovery.report
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
    except OSError as exc:
        if args.debug:
            raise
        if is_insufficient_space_error(exc):
            print(f"error: {insufficient_space_error()}", file=sys.stderr)
        else:
            print(
                f"error: unexpected {type(exc).__name__}. "
                "Rerun with --debug only in a private terminal.",
                file=sys.stderr,
            )
        return 1
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
