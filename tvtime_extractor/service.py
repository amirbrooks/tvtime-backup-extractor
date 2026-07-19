from __future__ import annotations

import hashlib
import os
import plistlib
import stat
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from .analyze import analyze_extraction
from .errors import (
    BackupUnencryptedError,
    BackupUnfinishedError,
    InsufficientSpaceError,
    OutputExistsError,
    PartialExtractionError,
    SourceChangedError,
    TVTimeError,
    UnsafePathError,
    UserInputError,
)
from .extract import (
    MAXIMUM_STATUS_PLIST_BYTES,
    BackupFileSnapshot,
    BackupPreflightSnapshot,
    ExtractionResult,
    _held_backup_root,
    _require_bound_backup_root,
    extract_backup,
)
from .models import (
    BackupPreflightReceipt,
    CancellationToken,
    DestinationDirectoryIdentity,
    PreflightResult,
    ProgressCallback,
    RecoveryEvent,
    RecoveryEventKind,
    RecoveryRequest,
    RecoveryResult,
    RecoveryStage,
)
from .report import build_report
from .safety import (
    anchored_bound_output_root,
    bound_directory_free_bytes,
    held_destination_parent,
    is_within,
    nearest_git_root,
    no_link_absolute_path,
    require_bound_destination_parent,
    require_fresh_output_platform_support,
    require_private_local_destination,
    validate_backup_directory,
)

MAXIMUM_MANIFEST_PLIST_BYTES = 16 * 1024 * 1024


def _emit(callback: ProgressCallback | None, event: RecoveryEvent) -> None:
    if callback is not None:
        callback(event)


def _iso_date(value: object) -> str:
    if not isinstance(value, datetime):
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _backup_stats(
    backup: Path,
    *,
    cancellation: CancellationToken,
    progress: ProgressCallback | None,
) -> tuple[int, int]:
    file_count = 0
    logical_bytes = 0
    directories = [backup]
    while directories:
        cancellation.raise_if_cancelled()
        current = directories.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise TVTimeError("Could not inspect a backup entry safely.") from exc
                    if _is_link_or_reparse(metadata):
                        raise UnsafePathError(
                            "The selected backup contains a symbolic link or reparse point; "
                            "refusing to traverse it."
                        )
                    if stat.S_ISDIR(metadata.st_mode):
                        directories.append(Path(entry.path))
                    elif stat.S_ISREG(metadata.st_mode):
                        file_count += 1
                        logical_bytes += int(metadata.st_size)
                        if file_count % 2_000 == 0:
                            cancellation.raise_if_cancelled()
                            _emit(
                                progress,
                                RecoveryEvent(
                                    stage=RecoveryStage.PREFLIGHT,
                                    kind=RecoveryEventKind.PROGRESS,
                                    message=(
                                        "Inspecting the selected backup without modifying it..."
                                    ),
                                    current=file_count,
                                    details={"logical_bytes": logical_bytes},
                                ),
                            )
                    else:
                        raise UnsafePathError(
                            "The selected backup contains a non-regular filesystem entry; "
                            "refusing to traverse it."
                        )
        except (TVTimeError, UnsafePathError):
            raise
        except OSError as exc:
            raise TVTimeError("Could not inspect the backup safely.") from exc
    return file_count, logical_bytes


def _stable_regular_file_snapshot(
    path: Path,
    *,
    cancellation: CancellationToken,
    maximum_bytes: int | None = None,
    retain_payload: bool = False,
) -> tuple[BackupFileSnapshot, bytes | None]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise UserInputError("Required backup metadata was unavailable.") from exc
    if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
        raise UnsafePathError("Required backup metadata was not a regular file.")
    if before.st_size <= 0 or (maximum_bytes is not None and before.st_size > maximum_bytes):
        raise UserInputError("Required backup metadata had an unsafe byte size.")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    digest = hashlib.sha256()
    payload = bytearray() if retain_payload else None
    byte_count = 0
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise SourceChangedError("Backup metadata changed while preflight opened it.")
        while True:
            cancellation.raise_if_cancelled()
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            byte_count += len(chunk)
            if maximum_bytes is not None and byte_count > maximum_bytes:
                raise UserInputError("Required backup metadata had an unsafe byte size.")
            digest.update(chunk)
            if payload is not None:
                payload.extend(chunk)
        after = os.fstat(descriptor)
    except (TVTimeError, UnsafePathError):
        raise
    except OSError as exc:
        raise TVTimeError("Required backup metadata could not be read safely.") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if byte_count != opened.st_size or any(
        getattr(opened, field) != getattr(after, field) for field in stable_fields
    ):
        raise SourceChangedError("Backup metadata changed while preflight read it.")
    try:
        path_after = path.lstat()
    except OSError as exc:
        raise SourceChangedError("Backup metadata changed during preflight.") from exc
    if _is_link_or_reparse(path_after) or any(
        getattr(after, field) != getattr(path_after, field) for field in stable_fields
    ):
        raise SourceChangedError("Backup metadata changed during preflight.")
    return (
        BackupFileSnapshot(
            device=int(after.st_dev),
            inode=int(after.st_ino),
            mode=int(after.st_mode),
            size=int(after.st_size),
            modified_ns=int(after.st_mtime_ns),
            changed_ns=int(after.st_ctime_ns),
            sha256=digest.hexdigest(),
        ),
        bytes(payload) if payload is not None else None,
    )


def _capture_backup_preflight_snapshot(
    backup: Path,
    *,
    cancellation: CancellationToken,
) -> tuple[BackupPreflightSnapshot, bytes, bytes]:
    try:
        root_before = backup.lstat()
    except OSError as exc:
        raise UserInputError("The selected backup root was unavailable.") from exc
    if _is_link_or_reparse(root_before) or not stat.S_ISDIR(root_before.st_mode):
        raise UnsafePathError("The selected backup root was not a regular directory.")

    manifest_plist, manifest_payload = _stable_regular_file_snapshot(
        backup / "Manifest.plist",
        cancellation=cancellation,
        maximum_bytes=MAXIMUM_MANIFEST_PLIST_BYTES,
        retain_payload=True,
    )
    manifest_database, _ = _stable_regular_file_snapshot(
        backup / "Manifest.db",
        cancellation=cancellation,
    )
    status_plist, status_payload = _stable_regular_file_snapshot(
        backup / "Status.plist",
        cancellation=cancellation,
        maximum_bytes=MAXIMUM_STATUS_PLIST_BYTES,
        retain_payload=True,
    )
    try:
        root_after = backup.lstat()
    except OSError as exc:
        raise SourceChangedError("The selected backup root changed during preflight.") from exc
    if _is_link_or_reparse(root_after) or (
        int(root_before.st_dev),
        int(root_before.st_ino),
    ) != (int(root_after.st_dev), int(root_after.st_ino)):
        raise SourceChangedError("The selected backup root changed during preflight.")
    if manifest_payload is None or status_payload is None:
        raise TVTimeError("Required backup metadata could not be retained safely.")
    return (
        BackupPreflightSnapshot(
            root_device=int(root_after.st_dev),
            root_inode=int(root_after.st_ino),
            manifest_plist=manifest_plist,
            manifest_database=manifest_database,
            status_plist=status_plist,
        ),
        manifest_payload,
        status_payload,
    )


def _load_plist_dictionary(payload: bytes) -> dict[str, object]:
    try:
        value = plistlib.loads(payload)
    except plistlib.InvalidFileException as exc:
        raise UserInputError("Backup metadata could not be parsed safely.") from exc
    if not isinstance(value, dict):
        raise UserInputError("Backup metadata had an unexpected format.")
    return value


def _destination_parent(output: Path) -> Path:
    expanded = output.expanduser()
    if expanded.is_symlink():
        raise UnsafePathError("Refusing a symbolic-link destination.")
    candidate = no_link_absolute_path(expanded)
    if candidate.exists():
        raise OutputExistsError(
            "The destination already exists. Choose a new dedicated folder so nothing can be "
            "overwritten or mixed."
        )
    parent = candidate.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    if not parent.is_dir() or parent.is_symlink():
        raise UnsafePathError("Could not find a safe existing parent for the destination.")
    return parent


def _bound_destination_identity(
    request: RecoveryRequest,
    destination_parent_descriptor: int | None,
) -> tuple[int, int] | None:
    identity = request.destination_parent_identity
    if (identity is None) != (destination_parent_descriptor is None):
        raise UnsafePathError("Destination identity binding was incomplete.")
    if identity is None:
        return None
    return (identity.device, identity.inode)


@dataclass(frozen=True)
class _PreparedPreflight:
    request: RecoveryRequest
    destination_parent_identity: tuple[int, int] | None
    result: PreflightResult
    backup_snapshot: BackupPreflightSnapshot


def _visible_extraction_result(
    result: ExtractionResult,
    visible_output: Path,
) -> ExtractionResult:
    extraction_root = result.extraction_root
    if extraction_root.is_absolute():
        try:
            extraction_root = extraction_root.relative_to(visible_output)
        except ValueError as exc:
            raise UnsafePathError(
                "The private extraction path escaped its trusted destination."
            ) from exc
    if ".." in extraction_root.parts:
        raise UnsafePathError("The private extraction path escaped its trusted destination.")
    return ExtractionResult(
        extraction_root=visible_output / extraction_root,
        summary=result.summary,
    )


def _visible_recovery_result(result: RecoveryResult, visible_output: Path) -> RecoveryResult:
    extraction = _visible_extraction_result(result.extraction, visible_output)
    report = dict(result.report)
    for key in ("report", "visual_report", "pdf_report"):
        value = report.get(key)
        if not value:
            continue
        relative = Path(str(value))
        if relative.is_absolute():
            try:
                relative = relative.relative_to(visible_output)
            except ValueError as exc:
                raise UnsafePathError(
                    "A private report path escaped its trusted destination."
                ) from exc
        if ".." in relative.parts:
            raise UnsafePathError("A private report path escaped its trusted destination.")
        report[key] = str(visible_output / relative)
    return RecoveryResult(
        preflight=result.preflight,
        extraction=extraction,
        analysis=result.analysis,
        report=report,
    )


def _run_recovery_stages(
    request: RecoveryRequest,
    *,
    passphrase: str,
    preflight: PreflightResult,
    backup_directory: Path,
    output_directory: Path,
    output_root_is_anchored: bool,
    source_root_descriptor: int,
    expected_source_root_identity: tuple[int, int],
    expected_backup_snapshot: BackupPreflightSnapshot,
    progress: ProgressCallback | None,
    token: CancellationToken,
) -> RecoveryResult:
    _emit(
        progress,
        RecoveryEvent(
            stage=RecoveryStage.EXTRACTION,
            kind=RecoveryEventKind.STARTED,
            message="Decrypting only the TV Time app container into the fresh destination...",
        ),
    )
    extraction = extract_backup(
        backup_directory=backup_directory,
        output_directory=output_directory,
        passphrase=passphrase,
        include_decrypted_manifest=request.include_decrypted_manifest,
        output_root_is_anchored=output_root_is_anchored,
        source_root_descriptor=source_root_descriptor,
        expected_source_root_identity=expected_source_root_identity,
        expected_backup_snapshot=expected_backup_snapshot,
        progress_callback=lambda current, total: _emit(
            progress,
            RecoveryEvent(
                stage=RecoveryStage.EXTRACTION,
                kind=RecoveryEventKind.PROGRESS,
                message="Copying selected TV Time files...",
                current=current,
                total=total,
            ),
        ),
        cancellation_check=token.raise_if_cancelled,
    )
    if extraction.has_failures:
        raise PartialExtractionError(
            "One or more selected TV Time files could not be copied. The output remains marked "
            "incomplete and analysis was not started.",
            extraction_result=extraction,
        )
    _emit(
        progress,
        RecoveryEvent(
            stage=RecoveryStage.EXTRACTION,
            kind=RecoveryEventKind.COMPLETED,
            message=(
                "The selected TV Time files were copied and inventoried; any byte-count "
                "differences remain explicit salvage warnings."
            ),
            current=int(extraction.summary["files_extracted"]),
            total=int(extraction.summary["files_expected"]),
            details={"size_discrepancy_count": len(extraction.summary["size_discrepancies"])},
        ),
    )
    token.raise_if_cancelled()

    _emit(
        progress,
        RecoveryEvent(
            stage=RecoveryStage.ANALYSIS,
            kind=RecoveryEventKind.STARTED,
            message="Recovering readable titles, favorites, episodes, and watch events...",
        ),
    )
    analysis = analyze_extraction(
        extraction_directory=extraction.extraction_root,
        include_raw_cache=request.include_raw_cache,
        cancellation_check=token.raise_if_cancelled,
    )
    _emit(
        progress,
        RecoveryEvent(
            stage=RecoveryStage.ANALYSIS,
            kind=RecoveryEventKind.COMPLETED,
            message="Readable TV Time tables were created.",
        ),
    )
    token.raise_if_cancelled()

    _emit(
        progress,
        RecoveryEvent(
            stage=RecoveryStage.REPORT,
            kind=RecoveryEventKind.STARTED,
            message="Building the human-readable private recovery report...",
        ),
    )
    report = build_report(
        extraction_directory=extraction.extraction_root,
        cancellation_check=token.raise_if_cancelled,
        commit_seal=token.seal_for_commit,
    )
    if not token.try_finish():
        token.raise_if_cancelled()
    _emit(
        progress,
        RecoveryEvent(
            stage=RecoveryStage.REPORT,
            kind=RecoveryEventKind.COMPLETED,
            message="The private report and media-reference tables are ready.",
        ),
    )
    return RecoveryResult(
        preflight=preflight,
        extraction=extraction,
        analysis=analysis,
        report=report,
    )


class RecoveryService:
    """UI-neutral orchestration shared by the CLI and native macOS helper."""

    def __init__(self) -> None:
        self._prepared_preflight: _PreparedPreflight | None = None

    def preflight(
        self,
        request: RecoveryRequest,
        *,
        progress: ProgressCallback | None = None,
        cancellation: CancellationToken | None = None,
        destination_parent_descriptor: int | None = None,
    ) -> PreflightResult:
        if destination_parent_descriptor is None:
            if request.destination_parent_identity is not None:
                raise UnsafePathError("Destination identity binding was incomplete.")
            with held_destination_parent(request.output_directory) as (
                parent_handle,
                parent_identity,
                visible_output,
            ):
                bound_request = replace(
                    request,
                    output_directory=visible_output,
                    destination_parent_identity=DestinationDirectoryIdentity(
                        device=parent_identity[0],
                        inode=parent_identity[1],
                    ),
                )
                result = self.preflight(
                    bound_request,
                    progress=progress,
                    cancellation=cancellation,
                    destination_parent_descriptor=parent_handle,
                )
            # A preflight-only public call cannot safely retain an operating-system
            # handle for a later call. Recover without an externally held handle
            # therefore runs its own complete preflight under one fresh binding.
            self._prepared_preflight = None
            return result
        token = cancellation or CancellationToken()
        token.raise_if_cancelled()
        _emit(
            progress,
            RecoveryEvent(
                stage=RecoveryStage.PREFLIGHT,
                kind=RecoveryEventKind.STARTED,
                message="Validating the completed encrypted backup and destination...",
            ),
        )
        backup = validate_backup_directory(request.backup_directory)
        output = no_link_absolute_path(request.output_directory)
        parent = _destination_parent(output)
        bound_identity = _bound_destination_identity(request, destination_parent_descriptor)
        if destination_parent_descriptor is not None and bound_identity is not None:
            parent = require_bound_destination_parent(
                output,
                destination_parent_descriptor=destination_parent_descriptor,
                expected_identity=bound_identity,
            )
        require_private_local_destination(output)
        if is_within(output, backup) or is_within(backup, output):
            raise UnsafePathError("The backup and destination directories must not overlap.")
        if nearest_git_root(output) is not None:
            raise UnsafePathError(
                "Refusing to place decrypted output inside a Git repository. Choose private "
                "encrypted storage."
            )

        backup_snapshot, manifest_payload, status_payload = _capture_backup_preflight_snapshot(
            backup,
            cancellation=token,
        )
        manifest = _load_plist_dictionary(manifest_payload)
        status = _load_plist_dictionary(status_payload)
        encrypted = manifest.get("IsEncrypted") is True
        if not encrypted:
            raise BackupUnencryptedError(
                "The selected backup is not confirmed as encrypted. Create a completed encrypted "
                "local backup before recovery."
            )
        snapshot_state = str(status.get("SnapshotState") or "").strip().casefold()
        if snapshot_state != "finished":
            raise BackupUnfinishedError(
                "The selected backup is not marked finished. Let Finder or Apple Devices finish "
                "the backup, then eject the phone before recovery."
            )

        regular_files, logical_bytes = _backup_stats(
            backup,
            cancellation=token,
            progress=progress,
        )
        token.raise_if_cancelled()
        stable_snapshot, stable_manifest_payload, stable_status_payload = (
            _capture_backup_preflight_snapshot(
                backup,
                cancellation=token,
            )
        )
        if (
            stable_snapshot != backup_snapshot
            or stable_manifest_payload != manifest_payload
            or stable_status_payload != status_payload
        ):
            raise SourceChangedError(
                "The selected backup metadata changed during preflight. Retry after the backup "
                "is complete and disconnected."
            )
        manifest_database_bytes = stable_snapshot.manifest_database.size
        minimum_working_bytes = max(512 * 1024 * 1024, manifest_database_bytes * 2)
        destination_free_bytes = bound_directory_free_bytes(
            parent,
            handle=destination_parent_descriptor,
        )
        if destination_free_bytes < minimum_working_bytes:
            raise InsufficientSpaceError(
                "The destination does not have enough free space for safe manifest processing. "
                "Choose a destination with more space."
            )
        result = PreflightResult(
            encrypted=encrypted,
            snapshot_state=snapshot_state,
            backup_date=_iso_date(status.get("Date") or manifest.get("Date")),
            backup_regular_files=regular_files,
            backup_logical_bytes=logical_bytes,
            manifest_database_bytes=manifest_database_bytes,
            destination_free_bytes=destination_free_bytes,
            minimum_working_bytes=minimum_working_bytes,
            warnings=(),
        )
        _emit(
            progress,
            RecoveryEvent(
                stage=RecoveryStage.PREFLIGHT,
                kind=RecoveryEventKind.COMPLETED,
                message="The backup and destination passed preflight checks.",
                details=result.as_dict(),
            ),
        )
        self._prepared_preflight = _PreparedPreflight(
            request=request,
            destination_parent_identity=bound_identity,
            result=result,
            backup_snapshot=stable_snapshot,
        )
        return result

    def preflight_receipt(self, result: PreflightResult) -> BackupPreflightReceipt:
        """Export the exact current source receipt without exposing it in user-facing output."""

        prepared = self._prepared_preflight
        if prepared is None or result is not prepared.result:
            raise UserInputError("The preflight receipt was not produced by this service instance.")
        return BackupPreflightReceipt(
            snapshot=prepared.backup_snapshot,
            backup_regular_files=result.backup_regular_files,
            backup_logical_bytes=result.backup_logical_bytes,
        )

    def _run_with_preflight_binding(
        self,
        request: RecoveryRequest,
        *,
        destination_parent_descriptor: int,
        preflight_result: PreflightResult | None,
        token: CancellationToken,
        progress: ProgressCallback | None,
        operation: Callable[
            [
                PreflightResult,
                Path,
                Path,
                int,
                tuple[int, int],
                BackupPreflightSnapshot,
            ],
            ExtractionResult | RecoveryResult,
        ],
    ) -> tuple[ExtractionResult | RecoveryResult, Path]:
        """Consume one same-service receipt before creating or writing the output root."""

        bound_identity = _bound_destination_identity(request, destination_parent_descriptor)
        if preflight_result is None:
            preflight = self.preflight(
                request,
                progress=progress,
                cancellation=token,
                destination_parent_descriptor=destination_parent_descriptor,
            )
        else:
            prepared = self._prepared_preflight
            if (
                prepared is None
                or preflight_result is not prepared.result
                or request != prepared.request
                or bound_identity != prepared.destination_parent_identity
            ):
                raise UserInputError(
                    "The supplied preflight result was not produced for this recovery request "
                    "by the same service instance. Run preflight again."
                )
            preflight = prepared.result

        prepared = self._prepared_preflight
        self._prepared_preflight = None
        token.raise_if_cancelled()
        if bound_identity is None:
            raise UnsafePathError("Destination identity binding was incomplete.")
        source_backup = validate_backup_directory(request.backup_directory)
        visible_output = no_link_absolute_path(request.output_directory)
        if prepared is None:
            raise SourceChangedError("The preflight backup identity receipt was unavailable.")
        detached_receipt = request.backup_receipt
        if detached_receipt is not None and not detached_receipt.matches(
            snapshot=prepared.backup_snapshot,
            backup_regular_files=preflight.backup_regular_files,
            backup_logical_bytes=preflight.backup_logical_bytes,
        ):
            raise SourceChangedError(
                "The selected backup no longer matched the confirmed preflight receipt. No "
                "output was created; select the completed backup again."
            )
        expected_source_identity = (
            prepared.backup_snapshot.root_device,
            prepared.backup_snapshot.root_inode,
        )
        with _held_backup_root(
            source_backup,
            expected_identity=expected_source_identity,
        ) as (source_root_descriptor, source_root_identity, bound_backup):
            current_snapshot, _, _ = _capture_backup_preflight_snapshot(
                bound_backup,
                cancellation=token,
            )
            if current_snapshot != prepared.backup_snapshot:
                raise SourceChangedError(
                    "The selected backup metadata changed after preflight. No output was created; "
                    "retry after the backup is complete and disconnected."
                )
            _require_bound_backup_root(
                bound_backup,
                descriptor=source_root_descriptor,
                expected_identity=source_root_identity,
            )
            with anchored_bound_output_root(
                visible_output,
                destination_parent_descriptor=destination_parent_descriptor,
                expected_parent_identity=bound_identity,
            ) as bound_output:
                _require_bound_backup_root(
                    bound_backup,
                    descriptor=source_root_descriptor,
                    expected_identity=source_root_identity,
                )
                result = operation(
                    preflight,
                    bound_backup,
                    bound_output,
                    source_root_descriptor,
                    source_root_identity,
                    prepared.backup_snapshot,
                )
        return result, visible_output

    def extract(
        self,
        request: RecoveryRequest,
        *,
        passphrase: str,
        progress: ProgressCallback | None = None,
        cancellation: CancellationToken | None = None,
        destination_parent_descriptor: int | None = None,
        preflight_result: PreflightResult | None = None,
    ) -> ExtractionResult:
        """Extract through the same identity-bound, single-use preflight receipt as recovery."""

        require_fresh_output_platform_support()
        if not request.acknowledge_sensitive_output:
            raise UserInputError(
                "Extraction writes sensitive plaintext while the destination is mounted. Confirm "
                "that the destination is private encrypted storage."
            )
        if not passphrase:
            raise UserInputError("No backup password was supplied.")
        if destination_parent_descriptor is None:
            if request.destination_parent_identity is not None:
                raise UnsafePathError("Destination identity binding was incomplete.")
            if preflight_result is not None:
                raise UserInputError(
                    "A preflight receipt can be reused only while its exact destination-parent "
                    "handle remains open. Run extract without the detached receipt, or hold the "
                    "binding across both calls."
                )
            with held_destination_parent(request.output_directory) as (
                parent_handle,
                parent_identity,
                visible_output,
            ):
                bound_request = replace(
                    request,
                    output_directory=visible_output,
                    destination_parent_identity=DestinationDirectoryIdentity(
                        device=parent_identity[0],
                        inode=parent_identity[1],
                    ),
                )
                return self.extract(
                    bound_request,
                    passphrase=passphrase,
                    progress=progress,
                    cancellation=cancellation,
                    destination_parent_descriptor=parent_handle,
                )

        token = cancellation or CancellationToken()

        def extraction_progress(current: int, total: int) -> None:
            _emit(
                progress,
                RecoveryEvent(
                    stage=RecoveryStage.EXTRACTION,
                    kind=RecoveryEventKind.PROGRESS,
                    message="Copying selected TV Time files...",
                    current=current,
                    total=total,
                ),
            )

        def run_bound_extract(
            _preflight: PreflightResult,
            backup_directory: Path,
            output_directory: Path,
            source_root_descriptor: int,
            source_root_identity: tuple[int, int],
            backup_snapshot: BackupPreflightSnapshot,
        ) -> ExtractionResult:
            _emit(
                progress,
                RecoveryEvent(
                    stage=RecoveryStage.EXTRACTION,
                    kind=RecoveryEventKind.STARTED,
                    message=(
                        "Decrypting only the TV Time app container into the fresh destination..."
                    ),
                ),
            )
            return extract_backup(
                backup_directory=backup_directory,
                output_directory=output_directory,
                passphrase=passphrase,
                include_decrypted_manifest=request.include_decrypted_manifest,
                output_root_is_anchored=True,
                source_root_descriptor=source_root_descriptor,
                expected_source_root_identity=source_root_identity,
                expected_backup_snapshot=backup_snapshot,
                progress_callback=extraction_progress,
                cancellation_check=token.raise_if_cancelled,
            )

        result, visible_output = self._run_with_preflight_binding(
            request,
            destination_parent_descriptor=destination_parent_descriptor,
            preflight_result=preflight_result,
            token=token,
            progress=progress,
            operation=run_bound_extract,
        )
        if not isinstance(result, ExtractionResult):
            raise RuntimeError("The bound extraction operation returned an invalid result.")
        visible_result = _visible_extraction_result(result, visible_output)
        _emit(
            progress,
            RecoveryEvent(
                stage=RecoveryStage.EXTRACTION,
                kind=RecoveryEventKind.COMPLETED,
                message="The selected TV Time files were copied and inventoried.",
                current=int(visible_result.summary["files_extracted"]),
                total=int(visible_result.summary["files_expected"]),
            ),
        )
        return visible_result

    def recover(
        self,
        request: RecoveryRequest,
        *,
        passphrase: str,
        progress: ProgressCallback | None = None,
        cancellation: CancellationToken | None = None,
        destination_parent_descriptor: int | None = None,
        preflight_result: PreflightResult | None = None,
    ) -> RecoveryResult:
        require_fresh_output_platform_support()
        if not request.acknowledge_sensitive_output:
            raise UserInputError(
                "Recovery writes sensitive plaintext while the destination is mounted. Confirm "
                "that the destination is private encrypted storage."
            )
        if request.include_raw_cache or request.include_decrypted_manifest:
            raise UserInputError(
                "The sealed recover workflow supports privacy-preserving defaults only. Use the "
                "separate extract or analyze command for advanced high-sensitivity exports; "
                "those exports are intentionally excluded from native completion validation."
            )
        if not passphrase:
            raise UserInputError("No backup password was supplied.")
        if destination_parent_descriptor is None:
            if request.destination_parent_identity is not None:
                raise UnsafePathError("Destination identity binding was incomplete.")
            if preflight_result is not None:
                raise UserInputError(
                    "A preflight receipt can be reused only while its exact destination-parent "
                    "handle remains open. Run recover without the detached receipt, or hold the "
                    "binding across both calls."
                )
            with held_destination_parent(request.output_directory) as (
                parent_handle,
                parent_identity,
                visible_output,
            ):
                bound_request = replace(
                    request,
                    output_directory=visible_output,
                    destination_parent_identity=DestinationDirectoryIdentity(
                        device=parent_identity[0],
                        inode=parent_identity[1],
                    ),
                )
                return self.recover(
                    bound_request,
                    passphrase=passphrase,
                    progress=progress,
                    cancellation=cancellation,
                    destination_parent_descriptor=parent_handle,
                )
        token = cancellation or CancellationToken()

        def run_bound_recovery(
            preflight: PreflightResult,
            backup_directory: Path,
            output_directory: Path,
            source_root_descriptor: int,
            source_root_identity: tuple[int, int],
            backup_snapshot: BackupPreflightSnapshot,
        ) -> RecoveryResult:
            return _run_recovery_stages(
                request,
                passphrase=passphrase,
                preflight=preflight,
                backup_directory=backup_directory,
                output_directory=output_directory,
                output_root_is_anchored=True,
                source_root_descriptor=source_root_descriptor,
                expected_source_root_identity=source_root_identity,
                expected_backup_snapshot=backup_snapshot,
                progress=progress,
                token=token,
            )

        result, visible_output = self._run_with_preflight_binding(
            request,
            destination_parent_descriptor=destination_parent_descriptor,
            preflight_result=preflight_result,
            token=token,
            progress=progress,
            operation=run_bound_recovery,
        )
        if not isinstance(result, RecoveryResult):
            raise RuntimeError("The bound recovery operation returned an invalid result.")
        result = _visible_recovery_result(result, visible_output)
        _emit(
            progress,
            RecoveryEvent(
                stage=RecoveryStage.COMPLETE,
                kind=RecoveryEventKind.COMPLETED,
                message="Recovery completed successfully.",
            ),
        )
        return result
