from __future__ import annotations

import gc
import getpass
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Callable
from contextlib import redirect_stdout, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import TVTimeError, UserInputError
from .safety import (
    ExtractionLayout,
    prepare_extraction_layout,
    safe_domain_component,
    safe_join,
    safe_manifest_relative_path,
    secure_directory,
    secure_file,
    set_private_umask,
    validate_file_id,
    write_bytes_private,
    write_csv_private,
    write_json_private,
    write_text_private,
)

TVTIME_BUNDLE_ID = "com.tozelabs.tvshowtime"
PRIMARY_DOMAIN = f"AppDomain-{TVTIME_BUNDLE_ID}"
RELATED_PLUGIN_DOMAIN_PREFIX = f"AppDomainPlugin-{TVTIME_BUNDLE_ID}."


@dataclass(frozen=True)
class ExtractionResult:
    extraction_root: Path
    summary: dict[str, Any]

    @property
    def has_failures(self) -> bool:
        return bool(self.summary["failures"])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_backup_password(*, password_stdin: bool) -> str:
    if password_stdin:
        passphrase = sys.stdin.readline().rstrip("\r\n")
    else:
        try:
            passphrase = getpass.getpass("Encrypted iOS backup password: ")
        except (EOFError, KeyboardInterrupt) as exc:
            raise UserInputError("No backup password was supplied.") from exc
    if not passphrase:
        raise UserInputError("No backup password was supplied.")
    return passphrase


def _load_decryption_dependency() -> tuple[type[Any], type[Any]]:
    try:
        from iphone_backup_decrypt import EncryptedBackup
        from iphone_backup_decrypt.utils import FilePlist
    except ModuleNotFoundError as exc:
        raise TVTimeError(
            "iphone-backup-decrypt is not installed. Run the installation step from README.md."
        ) from exc
    return EncryptedBackup, FilePlist


def _iso_mtime(value: object) -> str:
    if not isinstance(value, (int, float)) or not value:
        return ""
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _restore_timestamp(path: Path, value: object) -> None:
    if isinstance(value, (int, float)) and value:
        if os.utime not in os.supports_follow_symlinks:
            return
        os.utime(path, (value, value), follow_symlinks=False)


def _query_domains(backup: Any) -> list[str]:
    with backup.manifest_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT DISTINCT domain
            FROM Files
            WHERE domain = ?
               OR domain LIKE ?
            ORDER BY domain
            """,
            (PRIMARY_DOMAIN, f"{RELATED_PLUGIN_DOMAIN_PREFIX}%"),
        )
        domains = [str(row[0]) for row in cursor.fetchall()]
    for domain in domains:
        safe_domain_component(domain)
    if PRIMARY_DOMAIN not in domains:
        raise TVTimeError(f"TV Time app domain was not present in this backup: {PRIMARY_DOMAIN}")
    return domains


def _query_files(backup: Any, domains: list[str]) -> list[tuple[Any, ...]]:
    placeholders = ",".join("?" for _ in domains)
    with backup.manifest_db_cursor() as cursor:
        cursor.execute(
            f"""
            SELECT fileID, domain, relativePath, file
            FROM Files
            WHERE flags = 1 AND domain IN ({placeholders})
            ORDER BY domain, relativePath
            """,
            domains,
        )
        return list(cursor.fetchall())


def _extract_one_file(
    *,
    backup: Any,
    file_plist_factory: Callable[[Any], Any],
    layout: ExtractionLayout,
    file_id_value: object,
    domain_value: object,
    relative_path_value: object,
    file_bplist: Any,
) -> dict[str, Any]:
    file_id = validate_file_id(str(file_id_value))
    domain = safe_domain_component(str(domain_value))
    relative_path = str(relative_path_value)
    relative = safe_manifest_relative_path(relative_path)
    domain_root = secure_directory(safe_join(layout.raw_root, domain))
    target = safe_join(domain_root, relative)
    secure_directory(target.parent)
    if target.exists() or target.is_symlink():
        raise ValueError(f"Refusing to overwrite extracted file: {relative_path}")

    file_plist = file_plist_factory(file_bplist)
    declared_size = int(file_plist.filesize or 0)
    if declared_size == 0:
        write_bytes_private(target, b"", exclusive=True)
    else:
        if file_plist.encryption_key is None:
            raise ValueError("A non-empty encrypted file had no wrapped encryption key")
        key = backup._keybag.unwrapKeyForClass(
            file_plist.protection_class,
            file_plist.encryption_key,
        )
        # The pinned dependency prints absolute output paths in size warnings.
        # Capture that output because this function independently records the
        # declared and actual sizes in the private inventory.
        with redirect_stdout(io.StringIO()):
            backup._decrypt_file_to_disk(
                file_id=file_id,
                key=key,
                file_plist=file_plist,
                output_filepath=str(target),
            )
        if not target.is_file() or target.is_symlink():
            raise ValueError("The decryption library did not create a regular output file")
        secure_file(target)

    _restore_timestamp(target, file_plist.mtime)
    actual_size = target.stat().st_size
    return {
        "file_id": file_id,
        "domain": domain,
        "relative_path": relative_path,
        "declared_size": declared_size,
        "actual_size": actual_size,
        "size_match": actual_size == declared_size,
        "mtime": _iso_mtime(file_plist.mtime),
        "sha256": sha256_file(target),
    }


def extract_backup(
    *,
    backup_directory: Path,
    output_directory: Path,
    passphrase: str,
    include_decrypted_manifest: bool = False,
    dependency_loader: Callable[[], tuple[type[Any], type[Any]]] = _load_decryption_dependency,
) -> ExtractionResult:
    """Extract TV Time files from an encrypted local iOS backup."""

    set_private_umask()
    encrypted_backup_factory, file_plist_factory = dependency_loader()
    layout = prepare_extraction_layout(backup_directory, output_directory)
    run_state_path = layout.metadata_root / "run_state.json"
    write_json_private(
        run_state_path,
        {
            "status": "incomplete",
            "message": "Extraction did not reach its verified completion checkpoint.",
        },
    )
    source_backup = backup_directory.expanduser().resolve()
    source_manifest_state = {
        name: (
            (source_backup / name).stat().st_size,
            (source_backup / name).stat().st_mtime_ns,
        )
        for name in ("Manifest.plist", "Manifest.db")
    }

    previous_tmpdir = os.environ.get("TMPDIR")
    previous_tempdir = tempfile.tempdir
    os.environ["TMPDIR"] = str(layout.temp_root)
    tempfile.tempdir = str(layout.temp_root)

    backup: Any | None = None
    try:
        backup = encrypted_backup_factory(
            backup_directory=str(source_backup),
            passphrase=passphrase,
        )
        backup.test_decryption()

        manifest_sha256 = ""
        if include_decrypted_manifest:
            decrypted_manifest = layout.manifest_root / "Manifest.decrypted.db"
            backup.save_manifest_file(str(decrypted_manifest))
            secure_file(decrypted_manifest)
            manifest_sha256 = sha256_file(decrypted_manifest)

        domains = _query_domains(backup)
        rows = _query_files(backup, domains)
        selected_declared_bytes = 0
        for *_file_fields, file_bplist in rows:
            try:
                selected_declared_bytes += max(
                    0,
                    int(file_plist_factory(file_bplist).filesize or 0),
                )
            except Exception:
                # The normal extraction loop records malformed per-file metadata
                # in its private failure inventory.
                continue
        free_bytes = shutil.disk_usage(layout.output_root).free
        required_headroom = max(64 * 1024 * 1024, selected_declared_bytes // 10)
        if free_bytes < selected_declared_bytes + required_headroom:
            raise TVTimeError(
                "The destination does not have enough free space for the selected TV Time "
                "files and safe working headroom. Choose a new destination with more space."
            )

        inventory: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        for file_id, domain, relative_path, file_bplist in rows:
            try:
                inventory.append(
                    _extract_one_file(
                        backup=backup,
                        file_plist_factory=file_plist_factory,
                        layout=layout,
                        file_id_value=file_id,
                        domain_value=domain,
                        relative_path_value=relative_path,
                        file_bplist=file_bplist,
                    )
                )
            except Exception as exc:  # keep a complete private failure inventory
                failures.append(
                    {
                        "file_id": str(file_id),
                        "domain": str(domain),
                        "relative_path": str(relative_path),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )

        write_csv_private(
            layout.metadata_root / "inventory.csv",
            inventory,
            [
                "file_id",
                "domain",
                "relative_path",
                "declared_size",
                "actual_size",
                "size_match",
                "mtime",
                "sha256",
            ],
        )
        discrepancies = [
            {
                "domain": row["domain"],
                "relative_path": row["relative_path"],
                "declared_size": row["declared_size"],
                "actual_size": row["actual_size"],
            }
            for row in inventory
            if not row["size_match"]
        ]
        current_manifest_state = {
            name: (
                (source_backup / name).stat().st_size,
                (source_backup / name).stat().st_mtime_ns,
            )
            for name in source_manifest_state
        }
        if current_manifest_state != source_manifest_state:
            raise TVTimeError(
                "The backup manifest changed during extraction. Preserve this incomplete output, "
                "wait for the backup to finish, and retry into a new destination."
            )
        completed_utc = datetime.now(timezone.utc).isoformat()
        summary: dict[str, Any] = {
            "bundle_id": TVTIME_BUNDLE_ID,
            "domains": domains,
            "files_expected": len(rows),
            "files_extracted": len(inventory),
            "failures": failures,
            "bytes_extracted": sum(int(row["actual_size"]) for row in inventory),
            "selected_declared_bytes": selected_declared_bytes,
            "size_discrepancies": discrepancies,
            "decrypted_manifest_included": include_decrypted_manifest,
            "completed_utc": completed_utc,
        }
        if manifest_sha256:
            summary["manifest_sha256"] = manifest_sha256
        write_json_private(layout.metadata_root / "summary.json", summary)
        write_text_private(layout.metadata_root / "domains.txt", "\n".join(domains) + "\n")
        write_json_private(
            run_state_path,
            {
                "status": "complete",
                "completed_utc": completed_utc,
            },
        )
        return ExtractionResult(extraction_root=layout.extraction_root, summary=summary)
    except TVTimeError:
        raise
    except Exception as exc:
        raise TVTimeError(f"Extraction failed: {type(exc).__name__}: {exc}") from exc
    finally:
        if backup is not None:
            del backup
        gc.collect()
        with suppress(OSError):
            layout.temp_root.rmdir()
        tempfile.tempdir = previous_tempdir
        if previous_tmpdir is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = previous_tmpdir


def public_summary(result: ExtractionResult) -> dict[str, Any]:
    summary = result.summary
    return {
        "extraction_root": str(result.extraction_root),
        "files_expected": summary["files_expected"],
        "files_extracted": summary["files_extracted"],
        "failure_count": len(summary["failures"]),
        "size_discrepancy_count": len(summary["size_discrepancies"]),
        "selected_declared_bytes": summary["selected_declared_bytes"],
        "bytes_extracted": summary["bytes_extracted"],
        "decrypted_manifest_included": summary["decrypted_manifest_included"],
    }


def public_summary_json(result: ExtractionResult) -> str:
    return json.dumps(public_summary(result), indent=2, ensure_ascii=False)
