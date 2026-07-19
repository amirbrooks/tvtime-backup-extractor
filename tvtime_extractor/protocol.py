from __future__ import annotations

import json
import os
import select
import struct
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, BinaryIO, TextIO

from .errors import UserInputError

PROTOCOL_VERSION = 3
MAX_CONTROL_FRAME_BYTES = 1024 * 1024
MAX_SECRET_BYTES = 16 * 1024
SECRET_FILE_DESCRIPTOR = 3
DESTINATION_PARENT_FILE_DESCRIPTOR = 4
_REQUEST_FIELDS = frozenset(
    {
        "backup_directory",
        "output_directory",
        "destination_parent_identity",
        "acknowledge_sensitive_output",
        "include_raw_cache",
        "include_decrypted_manifest",
        "backup_receipt",
    }
)


class ProtocolError(UserInputError):
    """The local app/helper control protocol was malformed or unsupported."""


class ProtocolEOF(ProtocolError):
    """The app closed its control channel before the helper reached a terminal event."""


@dataclass(frozen=True)
class ControlRequest:
    action: str
    payload: dict[str, object]


def _read_exact(
    stream: BinaryIO,
    length: int,
    *,
    cancellation_check: Callable[[], None] | None,
    timeout_seconds: float | None,
) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
    while remaining:
        if cancellation_check is not None:
            cancellation_check()
        wait_seconds = 0.25
        if deadline is not None:
            wait_seconds = min(wait_seconds, max(0.0, deadline - time.monotonic()))
            if wait_seconds == 0.0:
                raise ProtocolError("The helper timed out waiting for a complete local frame.")
        try:
            readable, _, _ = select.select([stream.fileno()], [], [], wait_seconds)
        except (OSError, ValueError) as exc:
            raise ProtocolError("The helper could not monitor its local control pipe.") from exc
        if not readable:
            continue
        try:
            chunk = os.read(stream.fileno(), remaining)
        except OSError as exc:
            raise ProtocolError("The helper could not read its local control pipe.") from exc
        if not chunk:
            if not chunks:
                raise ProtocolEOF("The helper control pipe closed before a terminal event.")
            raise ProtocolError("The helper control pipe closed during a frame.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_binary_frame(
    stream: BinaryIO,
    *,
    maximum_bytes: int,
    cancellation_check: Callable[[], None] | None = None,
    timeout_seconds: float | None = 30.0,
) -> bytes:
    header = _read_exact(
        stream,
        4,
        cancellation_check=cancellation_check,
        timeout_seconds=timeout_seconds,
    )
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > maximum_bytes:
        raise ProtocolError("The helper received an invalid frame length.")
    return _read_exact(
        stream,
        length,
        cancellation_check=cancellation_check,
        timeout_seconds=timeout_seconds,
    )


def read_json_frame(
    stream: BinaryIO,
    *,
    cancellation_check: Callable[[], None] | None = None,
    timeout_seconds: float | None = 30.0,
) -> dict[str, object]:
    encoded = read_binary_frame(
        stream,
        maximum_bytes=MAX_CONTROL_FRAME_BYTES,
        cancellation_check=cancellation_check,
        timeout_seconds=timeout_seconds,
    )
    try:
        value = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("The helper received an invalid UTF-8 JSON control frame.") from exc
    if not isinstance(value, dict):
        raise ProtocolError("The helper control frame must be a JSON object.")
    return value


def read_control_request(
    stream: BinaryIO,
    *,
    cancellation_check: Callable[[], None] | None = None,
) -> ControlRequest:
    frame = read_json_frame(stream, cancellation_check=cancellation_check)
    if set(frame) != {"protocolVersion", "type", "payload"}:
        raise ProtocolError("The helper control request had unexpected fields.")
    if frame.get("protocolVersion") != PROTOCOL_VERSION:
        raise ProtocolError("The app and helper protocol versions are incompatible.")
    action = frame.get("type")
    if action not in {"preflight", "recover"}:
        raise ProtocolError("The helper control request had an unsupported action.")
    payload = frame.get("payload")
    if not isinstance(payload, dict):
        raise ProtocolError("The helper request payload must be an object.")
    if set(payload) != _REQUEST_FIELDS:
        raise ProtocolError("The helper request payload did not match the required fields.")
    return ControlRequest(action=str(action), payload=dict(payload))


def is_cancel_frame(frame: Mapping[str, object]) -> bool:
    return (
        set(frame) == {"protocolVersion", "type"}
        and frame.get("protocolVersion") == PROTOCOL_VERSION
        and frame.get("type") == "cancel"
    )


class ProtocolWriter:
    """Write the only allowed stdout stream: bounded, sequenced JSON Lines events."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream
        self._sequence = 0
        self._lock = threading.Lock()

    def write(self, event_type: str, payload: Mapping[str, Any]) -> None:
        with self._lock:
            self._sequence += 1
            frame = {
                "protocolVersion": PROTOCOL_VERSION,
                "sequence": self._sequence,
                "type": event_type,
                "payload": dict(payload),
            }
            encoded = json.dumps(frame, ensure_ascii=True, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > MAX_CONTROL_FRAME_BYTES:
                raise ProtocolError("The helper attempted to emit an oversized event.")
            self._stream.write(encoded + "\n")
            self._stream.flush()
