from __future__ import annotations

import os
import signal
import stat
import sys
import threading
from contextlib import suppress
from typing import Any

from . import __version__
from .errors import ErrorCode, TVTimeError, is_insufficient_space_error
from .models import (
    CancellationToken,
    DestinationDirectoryIdentity,
    RecoveryEvent,
    RecoveryRequest,
    RecoveryResult,
)
from .protocol import (
    DESTINATION_PARENT_FILE_DESCRIPTOR,
    MAX_SECRET_BYTES,
    PROTOCOL_VERSION,
    SECRET_FILE_DESCRIPTOR,
    ProtocolEOF,
    ProtocolError,
    ProtocolWriter,
    is_cancel_frame,
    read_binary_frame,
    read_control_request,
    read_json_frame,
)
from .safety import set_private_umask
from .service import RecoveryService

SAFE_ERROR_MESSAGES = {
    ErrorCode.INVALID_INPUT: (
        "The selected backup, destination, or recovery options failed a safety check. Review the "
        "selections and choose a fresh private destination."
    ),
    ErrorCode.INSUFFICIENT_SPACE: (
        "The destination ran out of usable space. Preserve the incomplete output and retry with a "
        "fresh folder on a volume with more free space."
    ),
    ErrorCode.OUTPUT_EXISTS: (
        "The destination is no longer fresh. Choose a new private output folder; existing data was "
        "not overwritten."
    ),
    ErrorCode.UNSAFE_PATH: (
        "A selected or derived path failed a safety check. Choose regular local folders that do "
        "not overlap the backup, cloud sync, shared storage, or a source repository."
    ),
    ErrorCode.BACKUP_UNENCRYPTED: (
        "The selected backup is not confirmed as encrypted. Create a completed encrypted local "
        "backup and try again."
    ),
    ErrorCode.BACKUP_UNFINISHED: (
        "The selected backup is not marked finished. Let the Apple backup complete, eject the "
        "device, and try again."
    ),
    ErrorCode.APP_DATA_MISSING: (
        "The selected backup does not contain the required TV Time app data. Choose a newer "
        "completed backup made after TV Time stored data on the device."
    ),
    ErrorCode.SOURCE_CHANGED: (
        "The source backup changed during recovery. Preserve the incomplete output and retry from "
        "a completed, disconnected backup."
    ),
    ErrorCode.UNSUPPORTED_SCHEMA: (
        "The recovered TV Time cache uses a schema this release cannot interpret safely. Preserve "
        "the private extraction and check for a newer release."
    ),
    ErrorCode.BACKUP_PASSWORD_REJECTED: (
        "The encrypted backup could not be unlocked. Check the local-backup password and try again "
        "with a new destination."
    ),
    ErrorCode.PARTIAL_EXTRACTION: (
        "One or more TV Time files could not be copied safely. The output is incomplete and was "
        "not analyzed."
    ),
    ErrorCode.CANCELLED: (
        "Recovery was cancelled. Incomplete output must be preserved for diagnosis or removed only "
        "after review; start a new attempt in a fresh destination."
    ),
    ErrorCode.RECOVERY_FAILED: (
        "Recovery stopped safely before completion. The source backup was not intentionally "
        "changed."
    ),
}


def _protocol_summary(result: RecoveryResult) -> dict[str, object]:
    extraction = result.extraction.summary
    analysis = result.analysis
    report = result.report
    artifacts = {
        "extraction_directory": "TVTime-Extraction",
        "report": "TVTime-Extraction/analysis/TVTime-Recovered-Data.md",
        "analysis_directory": "TVTime-Extraction/analysis",
        "recovery_state": "TVTime-Extraction/analysis/recovery_state.json",
    }
    if report.get("visual_report"):
        artifacts["visual_report"] = "TVTime-Extraction/analysis/TVTime-Recovered-Data.html"
    if report.get("pdf_report"):
        artifacts["pdf_report"] = "TVTime-Extraction/analysis/TVTime-Recovered-Data.pdf"
    report_summary: dict[str, object] = {
        "image_cache_references": int(report["image_cache_references"]),
        "trailer_references": int(report["trailer_references"]),
        "media_urls": int(report["media_urls"]),
        "pdf_status": str(report.get("pdf_status") or "generated"),
    }
    if report_summary["pdf_status"] == "omitted":
        report_summary["pdf_omission_reason"] = str(report.get("pdf_warning") or "")
    return {
        "preflight": result.preflight.as_dict(),
        "extraction": {
            "files_expected": int(extraction["files_expected"]),
            "files_extracted": int(extraction["files_extracted"]),
            "bytes_extracted": int(extraction["bytes_extracted"]),
            "selected_declared_bytes": int(extraction["selected_declared_bytes"]),
            "size_discrepancy_count": len(extraction["size_discrepancies"]),
        },
        "analysis": {
            "series_library": int(analysis["series_library"]),
            "watched_movies": int(analysis["watched_movies"]),
            "movie_watchlist": int(analysis["movie_watchlist"]),
            "favorite_shows": int(analysis["favorite_shows"]),
            "favorite_movies": int(analysis["favorite_movies"]),
            "watch_events": int(analysis["watch_events"]),
            "watch_events_with_titles": int(analysis["watch_events_with_titles"]),
            "episode_cache_unique": int(analysis["episode_cache_unique"]),
            "parser_status": str(analysis["parser_status"]),
        },
        "report": report_summary,
        "artifacts": artifacts,
    }


def _read_secret(token: CancellationToken) -> tuple[str, bytearray]:
    descriptor = -1
    try:
        descriptor = os.dup(SECRET_FILE_DESCRIPTOR)
        os.close(SECRET_FILE_DESCRIPTOR)
    except OSError as exc:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        raise ProtocolError("The helper secret pipe was not available.") from exc
    with os.fdopen(descriptor, "rb", buffering=0, closefd=True) as stream:
        encoded = bytearray(
            read_binary_frame(
                stream,
                maximum_bytes=MAX_SECRET_BYTES,
                cancellation_check=token.raise_if_cancelled,
            )
        )
    try:
        password = encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        for index in range(len(encoded)):
            encoded[index] = 0
        raise ProtocolError("The helper secret was not valid UTF-8.") from exc
    if not password:
        for index in range(len(encoded)):
            encoded[index] = 0
        raise ProtocolError("The helper secret was empty.")
    return password, encoded


def _hold_destination_parent_descriptor(
    expected_identity: DestinationDirectoryIdentity,
) -> int:
    descriptor = -1
    try:
        descriptor = os.dup(DESTINATION_PARENT_FILE_DESCRIPTOR)
        os.set_inheritable(descriptor, False)
        os.close(DESTINATION_PARENT_FILE_DESCRIPTOR)
        metadata = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        raise ProtocolError("The helper destination directory handle was not available.") from exc
    if not stat.S_ISDIR(metadata.st_mode) or (
        int(metadata.st_dev),
        int(metadata.st_ino),
    ) != (expected_identity.device, expected_identity.inode):
        os.close(descriptor)
        raise ProtocolError("The selected destination directory identity did not match.")
    return descriptor


def _start_control_reader(stream: Any, token: CancellationToken) -> threading.Thread:
    def read_controls() -> None:
        while True:
            try:
                frame = read_json_frame(
                    stream,
                    cancellation_check=token.raise_if_cancelled,
                    timeout_seconds=None,
                )
            except ProtocolEOF:
                token.cancel()
                return
            except ProtocolError as exc:
                token.cancel(exc)
                return
            except TVTimeError:
                return
            if is_cancel_frame(frame):
                token.cancel()
                return
            token.cancel(ProtocolError("The helper received an unsupported control frame."))
            return

    thread = threading.Thread(target=read_controls, name="recovery-control", daemon=True)
    thread.start()
    return thread


def _safe_error_payload(error: BaseException) -> tuple[str, dict[str, object], int]:
    if isinstance(error, TVTimeError):
        code = error.error_code
        exit_code = error.exit_code
    elif is_insufficient_space_error(error):
        code = ErrorCode.INSUFFICIENT_SPACE
        exit_code = 1
    else:
        code = ErrorCode.RECOVERY_FAILED
        exit_code = 1
    event_type = "cancelled" if code is ErrorCode.CANCELLED else "failed"
    return (
        event_type,
        {
            "code": code.value,
            "message": SAFE_ERROR_MESSAGES.get(
                code,
                SAFE_ERROR_MESSAGES[ErrorCode.RECOVERY_FAILED],
            ),
            "retryable": code
            in {
                ErrorCode.INVALID_INPUT,
                ErrorCode.INSUFFICIENT_SPACE,
                ErrorCode.OUTPUT_EXISTS,
                ErrorCode.UNSAFE_PATH,
                ErrorCode.BACKUP_UNENCRYPTED,
                ErrorCode.BACKUP_UNFINISHED,
                ErrorCode.APP_DATA_MISSING,
                ErrorCode.SOURCE_CHANGED,
                ErrorCode.BACKUP_PASSWORD_REJECTED,
                ErrorCode.PARTIAL_EXTRACTION,
                ErrorCode.CANCELLED,
            },
        },
        exit_code,
    )


def main() -> int:
    set_private_umask()
    protocol_descriptor = os.dup(sys.stdout.fileno())
    null_descriptor = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(null_descriptor, sys.stdout.fileno())
        os.dup2(null_descriptor, sys.stderr.fileno())
    finally:
        os.close(null_descriptor)
    protocol_stream = os.fdopen(
        protocol_descriptor,
        "w",
        encoding="utf-8",
        closefd=True,
    )
    writer = ProtocolWriter(protocol_stream)
    writer.write(
        "ready",
        {
            "helperVersion": __version__,
            "minimumProtocolVersion": PROTOCOL_VERSION,
            "maximumProtocolVersion": PROTOCOL_VERSION,
            "capabilities": [
                "preflight",
                "recover",
                "cancel",
                "destination-parent-fd",
                "source-receipt-v1",
            ],
        },
    )
    token = CancellationToken()

    def request_cancel(_signal: int, _frame: object) -> None:
        # A Python signal can interrupt the main thread while CancellationToken's
        # non-reentrant lock is held. Record only a lock-free flag here; the next
        # cooperative checkpoint translates it into terminal cancellation.
        token.mark_signal_pending()

    signal.signal(signal.SIGINT, request_cancel)
    signal.signal(signal.SIGTERM, request_cancel)
    password = ""
    secret_buffer = bytearray()
    destination_parent_descriptor = -1
    exit_code = 1
    try:
        request_frame = read_control_request(
            sys.stdin.buffer,
            cancellation_check=token.raise_if_cancelled,
        )
        request = RecoveryRequest.from_dict(request_frame.payload)
        if request.destination_parent_identity is None:
            raise ProtocolError("The helper request did not bind a destination identity.")
        destination_parent_descriptor = _hold_destination_parent_descriptor(
            request.destination_parent_identity
        )
        _start_control_reader(sys.stdin.buffer, token)
        service = RecoveryService()

        def progress(event: RecoveryEvent) -> None:
            payload: dict[str, object] = {
                "stage": event.stage.value,
                "kind": event.kind.value,
            }
            if event.current is not None:
                payload["current"] = event.current
            if event.total is not None:
                payload["total"] = event.total
            writer.write("progress", payload)

        if request_frame.action == "preflight":
            if request.backup_receipt is not None:
                raise ProtocolError("A preflight request cannot supply a backup receipt.")
            result = service.preflight(
                request,
                progress=progress,
                cancellation=token,
                destination_parent_descriptor=destination_parent_descriptor,
            )
            terminal: dict[str, object] = {
                "preflight": result.as_dict(),
                "backup_receipt": service.preflight_receipt(result).as_dict(),
            }
            if not token.try_finish():
                token.raise_if_cancelled()
        else:
            if request.backup_receipt is None:
                raise ProtocolError(
                    "A native recovery request requires its confirmed backup receipt."
                )
            password, secret_buffer = _read_secret(token)
            recovery = service.recover(
                request,
                passphrase=password,
                progress=progress,
                cancellation=token,
                destination_parent_descriptor=destination_parent_descriptor,
            )
            terminal = _protocol_summary(recovery)
        writer.write("completed", terminal)
        exit_code = 0
    except BaseException as exc:
        event_type, payload, exit_code = _safe_error_payload(exc)
        with suppress(Exception):
            writer.write(event_type, payload)
    finally:
        password = ""
        for index in range(len(secret_buffer)):
            secret_buffer[index] = 0
        if destination_parent_descriptor >= 0:
            with suppress(OSError):
                os.close(destination_parent_descriptor)
        protocol_stream.close()
    return exit_code


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
