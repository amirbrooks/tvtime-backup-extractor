from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
GENERATED_DIRECTORY = ".build-tools"


@dataclass(frozen=True)
class SourceEntry:
    kind: str
    executable: bool
    sha256: str | None


def git_output(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["/usr/bin/git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def validate_source_identity(repository: Path, source_commit: str) -> str:
    if not GIT_OBJECT_PATTERN.fullmatch(source_commit):
        raise RuntimeError("release source commit must be a full lowercase Git hash")
    actual_commit = git_output(repository, "rev-parse", "HEAD^{commit}")
    if actual_commit != source_commit:
        raise RuntimeError("release source commit does not match the checked-out HEAD")
    if git_output(repository, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("release source staging requires a completely clean Git worktree")
    source_tree = git_output(repository, "rev-parse", f"{source_commit}^{{tree}}")
    if not GIT_OBJECT_PATTERN.fullmatch(source_tree):
        raise RuntimeError("release source commit has an invalid Git tree")
    return source_tree


def safe_member_path(value: str) -> Path:
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or ".." in candidate.parts
        or "\\" in value
        or ":" in value
    ):
        raise RuntimeError("Git source archive contains an unsafe member path")
    return Path(*candidate.parts)


def git_archive(repository: Path, source_commit: str) -> bytes:
    completed = subprocess.run(
        ["/usr/bin/git", "-C", str(repository), "archive", "--format=tar", source_commit],
        check=True,
        capture_output=True,
    )
    return completed.stdout


def archive_inventory(archive_bytes: bytes) -> dict[str, SourceEntry]:
    inventory: dict[str, SourceEntry] = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        for member in archive.getmembers():
            relative = safe_member_path(member.name).as_posix()
            if relative in inventory:
                raise RuntimeError("Git source archive contains a duplicate member path")
            if member.isdir():
                inventory[relative] = SourceEntry("directory", False, None)
                continue
            if not member.isfile():
                raise RuntimeError("Git source archive contains a link or special entry")
            contents = archive.extractfile(member)
            if contents is None:
                raise RuntimeError("Git source archive member could not be read")
            digest = hashlib.sha256()
            with contents:
                while chunk := contents.read(1024 * 1024):
                    digest.update(chunk)
            inventory[relative] = SourceEntry(
                "file",
                bool(member.mode & 0o111),
                digest.hexdigest(),
            )
    if not inventory:
        raise RuntimeError("Git source archive is empty")
    return inventory


def extract_archive(archive_bytes: bytes, destination: Path) -> None:
    seen: set[str] = set()
    tracked_directories: list[Path] = []
    tracked_files: list[tuple[Path, bool]] = []
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        for member in archive.getmembers():
            relative = safe_member_path(member.name)
            relative_text = relative.as_posix()
            if relative_text in seen:
                raise RuntimeError("Git source archive contains a duplicate member path")
            seen.add(relative_text)
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                if not target.is_dir() or target.is_symlink():
                    raise RuntimeError("Git source archive has a colliding directory entry")
                tracked_directories.append(target)
                continue
            if not member.isfile():
                raise RuntimeError("Git source archive contains a link or special entry")
            target.parent.mkdir(parents=True, exist_ok=True)
            contents = archive.extractfile(member)
            if contents is None:
                raise RuntimeError("Git source archive member could not be read")
            with contents, target.open("xb") as output:
                while chunk := contents.read(1024 * 1024):
                    output.write(chunk)
            executable = bool(member.mode & 0o111)
            target.chmod(0o555 if executable else 0o444)
            tracked_files.append((target, executable))

    generated = destination / GENERATED_DIRECTORY
    generated.mkdir(mode=0o700)
    for directory in sorted(tracked_directories, key=lambda path: len(path.parts), reverse=True):
        directory.chmod(0o555)
    for target, executable in tracked_files:
        expected_mode = 0o555 if executable else 0o444
        if stat.S_IMODE(target.stat().st_mode) != expected_mode:
            raise RuntimeError("staged Git source file mode could not be made read-only")
    destination.chmod(0o555)


def actual_inventory(source: Path) -> dict[str, SourceEntry]:
    inventory: dict[str, SourceEntry] = {}

    def fail_walk(error: OSError) -> None:
        raise RuntimeError("staged Git source could not be traversed safely") from error

    for current, directory_names, file_names in os.walk(
        source,
        followlinks=False,
        onerror=fail_walk,
    ):
        current_path = Path(current)
        if current_path == source:
            generated = source / GENERATED_DIRECTORY
            if GENERATED_DIRECTORY not in directory_names:
                raise RuntimeError("staged Git source build root is unavailable")
            mode = generated.lstat().st_mode
            if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
                raise RuntimeError("staged Git source build root is unsafe")
            directory_names.remove(GENERATED_DIRECTORY)
        for directory_name in directory_names:
            directory = current_path / directory_name
            mode = directory.lstat().st_mode
            if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
                raise RuntimeError("staged Git source contains an unsafe directory")
            relative = directory.relative_to(source).as_posix()
            inventory[relative] = SourceEntry("directory", False, None)
        for file_name in file_names:
            path = current_path / file_name
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                raise RuntimeError("staged Git source contains an unsafe file")
            digest = hashlib.sha256()
            try:
                with path.open("rb") as handle:
                    while chunk := handle.read(1024 * 1024):
                        digest.update(chunk)
            except OSError:
                raise RuntimeError("staged Git source contains an unreadable file") from None
            relative = path.relative_to(source).as_posix()
            inventory[relative] = SourceEntry(
                "file",
                bool(mode & 0o111),
                digest.hexdigest(),
            )
    return inventory


def verify_source_stage(repository: Path, source_commit: str, source: Path) -> None:
    if not source.is_dir() or source.is_symlink():
        raise RuntimeError("staged Git source must be a regular directory")
    expected = archive_inventory(git_archive(repository, source_commit))
    actual = actual_inventory(source)
    if actual != expected:
        raise RuntimeError("staged Git source does not exactly match the reviewed commit")
    if stat.S_IMODE(source.stat().st_mode) != 0o555:
        raise RuntimeError("staged Git source root is not read-only")
    for relative, entry in actual.items():
        mode = stat.S_IMODE((source / relative).stat().st_mode)
        expected_mode = 0o555 if entry.kind == "directory" or entry.executable else 0o444
        if mode != expected_mode:
            raise RuntimeError("staged Git source entry is not read-only")


def prepare_source_stage(repository: Path, source_commit: str) -> Path:
    repository = repository.resolve(strict=True)
    validate_source_identity(repository, source_commit)
    output_parent = repository / "dist"
    if output_parent.is_symlink():
        raise RuntimeError("release output root must not be a symbolic link")
    output_parent.mkdir(mode=0o700, exist_ok=True)
    release_stage = Path(tempfile.mkdtemp(prefix=".macos-release.", dir=output_parent)).resolve(
        strict=True
    )
    release_stage.chmod(0o700)
    source = release_stage / "source"
    source.mkdir(mode=0o700)
    try:
        archive_bytes = git_archive(repository, source_commit)
        extract_archive(archive_bytes, source)
        verify_source_stage(repository, source_commit, source)
    except Exception:
        make_source_removable(source)
        shutil.rmtree(release_stage)
        raise
    return release_stage


def make_source_removable(source: Path) -> None:
    if not source.exists() or source.is_symlink():
        return
    for current, directory_names, _file_names in os.walk(source, topdown=False):
        for directory_name in directory_names:
            directory = Path(current) / directory_name
            if not directory.is_symlink():
                directory.chmod(0o700)
        Path(current).chmod(0o700)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare or verify a read-only Git-commit source stage."
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--prepare", action="store_true")
    action.add_argument("--verify", action="store_true")
    action.add_argument("--unlock", action="store_true")
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--source", type=Path)
    arguments = parser.parse_args()

    if arguments.prepare:
        if arguments.repository is None or arguments.source_commit is None or arguments.source:
            parser.error("--prepare requires --repository and --source-commit only")
        print(prepare_source_stage(arguments.repository, arguments.source_commit))
        return 0
    if arguments.source is None:
        parser.error("--verify and --unlock require --source")
    source = arguments.source.resolve(strict=True)
    if arguments.verify:
        if arguments.repository is None or arguments.source_commit is None:
            parser.error("--verify requires --repository and --source-commit")
        verify_source_stage(
            arguments.repository.resolve(strict=True),
            arguments.source_commit,
            source,
        )
        print("Read-only Git source stage matches the reviewed commit.")
        return 0
    if arguments.repository is not None or arguments.source_commit is not None:
        parser.error("--unlock accepts only --source")
    make_source_removable(source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
