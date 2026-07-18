from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, TextIO
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .errors import UserInputError

EXTRACTION_DIRECTORY_NAME = "TVTime-Extraction"
WINDOWS_INVALID_CHARACTERS = frozenset('<>:"|?*')
WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
)
FILE_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class ExtractionLayout:
    output_root: Path
    extraction_root: Path
    raw_root: Path
    metadata_root: Path
    manifest_root: Path
    temp_root: Path


def set_private_umask() -> None:
    """Make subsequently created files private on POSIX systems."""

    if os.name != "nt":
        os.umask(0o077)


def canonical_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def is_within(path: Path, parent: Path) -> bool:
    resolved_path = canonical_path(path)
    resolved_parent = canonical_path(parent)
    return resolved_path == resolved_parent or resolved_parent in resolved_path.parents


def nearest_git_root(path: Path) -> Path | None:
    candidate = canonical_path(path)
    if not candidate.is_dir():
        candidate = candidate.parent
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    for current in (candidate, *candidate.parents):
        if (current / ".git").exists():
            return current
    return None


def secure_directory(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise UserInputError(f"Refusing to use a symbolic-link directory: {expanded}")
    resolved = canonical_path(expanded)
    resolved.mkdir(parents=True, exist_ok=True)
    if not resolved.is_dir():
        raise UserInputError(f"Expected a directory: {resolved}")
    try:
        resolved.chmod(0o700)
    except OSError:
        # Windows ACLs are not represented by POSIX modes. The platform guide
        # requires an encrypted destination and explains the OS-specific controls.
        if os.name != "nt":
            raise
    return resolved


def _is_link_or_reparse_point(path: Path) -> bool:
    """Return whether an existing path redirects traversal to another location."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _reject_linked_components(root: Path, target: Path) -> None:
    """Reject symbolic links or Windows reparse points beneath a trusted root."""

    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Output path escaped its root: {target}") from exc
    current = root
    for component in relative.parts:
        current /= component
        if _is_link_or_reparse_point(current):
            raise ValueError(f"Refusing path through a symbolic link or reparse point: {current}")


def secure_file(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        if os.name != "nt":
            raise


def validate_backup_directory(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise UserInputError(f"Refusing to use a symbolic-link backup directory: {expanded}")
    backup = canonical_path(expanded)
    if not backup.is_dir():
        raise UserInputError(f"Backup directory was not found: {backup}")
    for required_name in ("Manifest.plist", "Manifest.db"):
        required = backup / required_name
        if not required.is_file() or required.is_symlink():
            raise UserInputError(
                f"{required_name} was not found as a regular backup file: {backup}"
            )
    return backup


def prepare_extraction_layout(backup: Path, output: Path) -> ExtractionLayout:
    backup = validate_backup_directory(backup)
    expanded_output = output.expanduser()
    if expanded_output.is_symlink():
        raise UserInputError(f"Refusing to use a symbolic-link output path: {expanded_output}")
    output_root = canonical_path(expanded_output)
    if is_within(output_root, backup) or is_within(backup, output_root):
        raise UserInputError("The backup and output directories must not overlap.")

    if output_root.exists():
        raise UserInputError(
            f"Output path already exists: {output_root}. "
            "Choose a new dedicated folder so existing permissions and files remain untouched."
        )

    extraction_root = output_root / EXTRACTION_DIRECTORY_NAME
    git_root = nearest_git_root(extraction_root)
    if git_root is not None:
        raise UserInputError(
            "Refusing to place decrypted data inside a Git repository "
            f"({git_root}). Choose a separate encrypted destination."
        )
    if extraction_root.exists() or extraction_root.is_symlink():
        raise UserInputError(
            f"Extraction output already exists: {extraction_root}. "
            "Choose a new destination so results cannot be overwritten or mixed."
        )

    secure_directory(output_root)
    extraction_root = secure_directory(extraction_root)
    raw_root = secure_directory(extraction_root / "raw")
    metadata_root = secure_directory(extraction_root / "metadata")
    manifest_root = secure_directory(extraction_root / "manifest")
    temp_root = secure_directory(extraction_root / ".tmp")
    return ExtractionLayout(
        output_root=output_root,
        extraction_root=extraction_root,
        raw_root=raw_root,
        metadata_root=metadata_root,
        manifest_root=manifest_root,
        temp_root=temp_root,
    )


def validate_extraction_directory(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise UserInputError(f"Refusing to use a symbolic-link extraction directory: {expanded}")
    extraction = canonical_path(expanded)
    if not extraction.is_dir():
        raise UserInputError(f"Extraction directory was not found: {extraction}")
    try:
        raw = safe_join(extraction, "raw")
        metadata = safe_join(extraction, "metadata")
    except ValueError as exc:
        raise UserInputError(str(exc)) from exc
    if raw.is_symlink() or not raw.is_dir():
        raise UserInputError(f"Expected extracted raw data at: {raw}")
    run_state = metadata / "run_state.json"
    if run_state.exists():
        if not run_state.is_file() or run_state.is_symlink():
            raise UserInputError(f"Refusing unsafe extraction state file: {run_state}")
        try:
            state = json.loads(run_state.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UserInputError(f"Could not validate extraction state: {run_state}") from exc
        if not isinstance(state, dict) or state.get("status") != "complete":
            raise UserInputError(
                "The extraction is marked incomplete. Preserve it for diagnosis and run a fresh "
                "recovery into a new output folder."
            )
    git_root = nearest_git_root(extraction)
    if git_root is not None:
        raise UserInputError(
            "Refusing to process decrypted data inside a Git repository "
            f"({git_root}). Move it to private storage first."
        )
    return extraction


def prepare_new_analysis_directory(extraction: Path) -> Path:
    extraction = validate_extraction_directory(extraction)
    analysis = extraction / "analysis"
    if analysis.exists() or analysis.is_symlink():
        raise UserInputError(
            f"Analysis output already exists: {analysis}. "
            "Use a fresh extraction or move the old analysis aside."
        )
    return secure_directory(analysis)


def _validate_portable_component(value: str, *, label: str) -> str:
    if not value or value in {".", ".."}:
        raise ValueError(f"Unsafe {label}: {value!r}")
    if value != value.rstrip(" ."):
        raise ValueError(f"Unsafe {label} with a trailing space or dot: {value!r}")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"Unsafe control character in {label}: {value!r}")
    if any(character in WINDOWS_INVALID_CHARACTERS for character in value):
        raise ValueError(f"Unsafe cross-platform character in {label}: {value!r}")
    base_name = value.split(".", 1)[0].upper()
    if base_name in WINDOWS_RESERVED_NAMES:
        raise ValueError(f"Unsafe reserved Windows name in {label}: {value!r}")
    return value


def safe_manifest_relative_path(value: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError(f"Unsafe backup path: {value!r}")
    posix = PurePosixPath(value)
    if posix.is_absolute() or not posix.parts or posix.as_posix() != value:
        raise ValueError(f"Unsafe backup path: {value!r}")
    for part in posix.parts:
        _validate_portable_component(part, label="backup path component")
    return Path(*posix.parts)


def safe_domain_component(value: str) -> str:
    if not isinstance(value, str) or "/" in value or "\\" in value or "\x00" in value:
        raise ValueError(f"Unsafe backup domain: {value!r}")
    return _validate_portable_component(value, label="backup domain")


def validate_file_id(value: str) -> str:
    if not isinstance(value, str) or FILE_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("Manifest file ID was not a 40-character hexadecimal value")
    return value.lower()


def safe_join(root: Path, *parts: str | Path) -> Path:
    root = canonical_path(root)
    target = Path(os.path.abspath(os.fspath(root.joinpath(*parts))))
    _reject_linked_components(root, target)
    resolved_target = canonical_path(target)
    if not is_within(resolved_target, root):
        raise ValueError(f"Output path escaped its root: {target}")
    return resolved_target


def private_source_id(key: object, subkey: object) -> str:
    value = f"{key!s}\x00{subkey!s}".encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(value).hexdigest()[:24]


def sanitize_public_url(value: str) -> str:
    """Remove credentials, fragments, and nonessential query data from a URL."""

    if not isinstance(value, str) or not value.startswith(("https://", "http://")):
        return ""
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        if parsed.username is not None or parsed.password is not None:
            return ""
        port = parsed.port
    except ValueError:
        return ""

    hostname = parsed.hostname.lower()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname if port is None else f"{hostname}:{port}"
    query = ""
    if parsed.hostname.lower() in {"youtube.com", "www.youtube.com", "m.youtube.com"}:
        video_ids = [item for item in parse_qsl(parsed.query) if item[0] == "v" and item[1]]
        if video_ids:
            query = urlencode([video_ids[0]])
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))


def _open_flags() -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


@contextmanager
def private_text_writer(path: Path, *, newline: str | None = None) -> Iterator[TextIO]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, _open_flags(), 0o600)
    with open(descriptor, "w", newline=newline, encoding="utf-8") as handle:
        yield handle
    secure_file(path)


def write_text_private(path: Path, value: str) -> None:
    with private_text_writer(path) as handle:
        handle.write(value)


def write_json_private(path: Path, value: Any) -> None:
    write_text_private(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def write_bytes_private(path: Path, value: bytes, *, exclusive: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(value)
    secure_file(path)


def write_csv_private(
    path: Path,
    rows: Iterable[Mapping[str, Any]],
    fields: Sequence[str],
) -> None:
    with private_text_writer(path, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(
            {
                key: f"'{value}"
                if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r"))
                else value
                for key, value in row.items()
            }
            for row in rows
        )
