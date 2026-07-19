from __future__ import annotations

import argparse
import copy
import gzip
import os
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

IDENTITY_KEYS = frozenset({"gid", "gname", "uid", "uname"})
TIMESTAMP_KEYS = frozenset({"atime", "creationtime", "ctime", "mtime"})
NORMALIZED_MTIME = 0
DIRECTORY_MODE = 0o755
EXECUTABLE_MODE = 0o755
REGULAR_MODE = 0o644


def _validate_member_name(name: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise RuntimeError("source archive contains an unsafe member path")


def _contains_pax_header(headers: dict[str, str], forbidden_keys: frozenset[str]) -> bool:
    return any(key.casefold().split(".")[-1] in forbidden_keys for key in headers)


def _expected_mode(member: tarfile.TarInfo) -> int:
    if member.isdir():
        return DIRECTORY_MODE
    return EXECUTABLE_MODE if member.mode & 0o111 else REGULAR_MODE


def _verify_gzip_header(archive: Path) -> None:
    with archive.open("rb") as handle:
        header = handle.read(10)
    if len(header) != 10 or header[:2] != b"\x1f\x8b":
        raise RuntimeError("source archive does not have a valid gzip header")
    if int.from_bytes(header[4:8], byteorder="little") != NORMALIZED_MTIME:
        raise RuntimeError("source archive gzip timestamp is not normalized")
    if header[3] & 0x08:
        raise RuntimeError("source archive gzip header exposes an original filename")


def verify_sdist_metadata(archive: Path) -> None:
    if not archive.is_file() or archive.is_symlink():
        raise RuntimeError("source archive must be a regular file")
    _verify_gzip_header(archive)
    with tarfile.open(archive, "r:gz") as source:
        if _contains_pax_header(source.pax_headers, IDENTITY_KEYS):
            raise RuntimeError("source archive global metadata contains an owner identity")
        if _contains_pax_header(source.pax_headers, TIMESTAMP_KEYS):
            raise RuntimeError("source archive global metadata contains a timestamp")
        members = source.getmembers()
        if not members:
            raise RuntimeError("source archive is empty")
        if [member.name for member in members] != sorted(member.name for member in members):
            raise RuntimeError("source archive member order is not deterministic")
        seen: set[str] = set()
        for member in members:
            _validate_member_name(member.name)
            if member.name in seen:
                raise RuntimeError("source archive contains a duplicate member path")
            seen.add(member.name)
            if member.uid != 0 or member.gid != 0 or member.uname or member.gname:
                raise RuntimeError("source archive exposes local owner metadata")
            if _contains_pax_header(member.pax_headers, IDENTITY_KEYS):
                raise RuntimeError("source archive member metadata exposes an owner identity")
            if _contains_pax_header(member.pax_headers, TIMESTAMP_KEYS):
                raise RuntimeError("source archive member metadata contains a timestamp")
            if not (member.isfile() or member.isdir()):
                raise RuntimeError("source archive contains an unsupported link or special entry")
            if member.mtime != NORMALIZED_MTIME:
                raise RuntimeError("source archive member timestamp is not normalized")
            if member.mode != _expected_mode(member):
                raise RuntimeError("source archive member mode is not normalized")


def normalize_sdist_metadata(archive: Path) -> None:
    if not archive.is_file() or archive.is_symlink():
        raise RuntimeError("source archive must be a regular file")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=archive.parent,
        prefix=f".{archive.name}.",
        suffix=".partial",
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with (
            tarfile.open(archive, "r:gz") as source,
            temporary.open("wb") as raw_output,
            gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=0) as compressed,
            tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as target,
        ):
            seen: set[str] = set()
            for original in sorted(source.getmembers(), key=lambda item: item.name):
                _validate_member_name(original.name)
                if original.name in seen:
                    raise RuntimeError("source archive contains a duplicate member path")
                seen.add(original.name)
                if not (original.isfile() or original.isdir()):
                    raise RuntimeError(
                        "source archive contains an unsupported link or special entry"
                    )

                member = copy.copy(original)
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                member.mtime = NORMALIZED_MTIME
                member.mode = _expected_mode(original)
                member.pax_headers = {}
                if member.isfile():
                    contents = source.extractfile(original)
                    if contents is None:
                        raise RuntimeError("source archive regular file has no readable contents")
                    with contents:
                        target.addfile(member, contents)
                else:
                    target.addfile(member)

        verify_sdist_metadata(temporary)
        temporary.chmod(REGULAR_MODE)
        os.replace(temporary, archive)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Normalize or verify deterministic private Python source archive metadata."
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--normalize", action="store_true")
    action.add_argument("--verify", action="store_true")
    parser.add_argument("archives", type=Path, nargs="+")
    arguments = parser.parse_args()

    for archive in arguments.archives:
        if arguments.normalize:
            normalize_sdist_metadata(archive)
        verify_sdist_metadata(archive)
        print(f"Source archive privacy metadata passed: {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
