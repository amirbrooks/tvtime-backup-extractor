from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))
from sdist_metadata import verify_sdist_metadata  # noqa: E402

GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative_path(value: str) -> Path:
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or ".." in candidate.parts
        or "\\" in value
        or ":" in value
    ):
        raise RuntimeError("Python distribution contains an unsafe archive member")
    return Path(*candidate.parts)


def extract_sdist(archive: Path, destination: Path) -> None:
    verify_sdist_metadata(archive)
    seen: set[str] = set()
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            relative = safe_relative_path(member.name)
            if member.name in seen:
                raise RuntimeError("Python source archive contains a duplicate member")
            seen.add(member.name)
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o755)
                continue
            if not member.isfile():
                raise RuntimeError("Python source archive contains an unsupported entry")
            target.parent.mkdir(parents=True, exist_ok=True)
            contents = source.extractfile(member)
            if contents is None:
                raise RuntimeError("Python source archive member could not be read")
            with contents, target.open("xb") as output:
                while chunk := contents.read(1024 * 1024):
                    output.write(chunk)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def extract_wheel(archive: Path, destination: Path) -> None:
    seen: set[str] = set()
    with zipfile.ZipFile(archive) as source:
        for member in source.infolist():
            relative = safe_relative_path(member.filename)
            if member.filename in seen:
                raise RuntimeError("Python wheel contains a duplicate member")
            seen.add(member.filename)
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise RuntimeError("Python wheel contains a symbolic link")
            target = destination / relative
            if member.is_dir():
                if stat.S_IFMT(mode) not in (0, stat.S_IFDIR):
                    raise RuntimeError("Python wheel contains an unsupported directory entry")
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o755)
                continue
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise RuntimeError("Python wheel contains an unsupported file entry")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open(member) as contents, target.open("xb") as output:
                for chunk in iter(lambda: contents.read(1024 * 1024), b""):
                    output.write(chunk)
            target.chmod(0o755 if mode & 0o111 else 0o644)


def scan_extracted_tree(root: Path, forbidden_values: list[str]) -> None:
    arguments = [
        sys.executable,
        "-I",
        str(SCRIPT_DIRECTORY / "scan_macos_release.py"),
        "--root",
        str(root),
    ]
    for value in forbidden_values:
        if value:
            arguments.extend(("--forbidden-value", value))
    subprocess.run(arguments, check=True)


def verify_release_set(
    root: Path,
    *,
    source_commit: str,
    source_tree: str,
    forbidden_values: list[str],
) -> None:
    if not GIT_OBJECT_PATTERN.fullmatch(source_commit) or not GIT_OBJECT_PATTERN.fullmatch(
        source_tree
    ):
        raise RuntimeError("Python release source identity is invalid")
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("Python release output must be a regular directory")
    manifest_path = root / "python-release-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise RuntimeError("Python release manifest is unavailable or unsafe")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != {"artifacts", "schema", "source"}:
        raise RuntimeError("Python release manifest structure is invalid")
    if manifest.get("schema") != "tvtime-python-release-manifest-v1":
        raise RuntimeError("Python release manifest schema is unsupported")
    if manifest.get("source") != {
        "git_commit": source_commit,
        "git_tree": source_tree,
        "worktree": "clean",
    }:
        raise RuntimeError("Python release manifest source identity does not match")
    artifact_records = manifest.get("artifacts")
    if not isinstance(artifact_records, list) or len(artifact_records) != 2:
        raise RuntimeError("Python release manifest artifact inventory is invalid")
    expected_names = {"python-release-manifest.json"}
    for record in artifact_records:
        if (
            not isinstance(record, dict)
            or set(record) != {"name", "sha256", "size"}
            or not isinstance(record.get("name"), str)
            or not isinstance(record.get("size"), int)
            or not isinstance(record.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
        ):
            raise RuntimeError("Python release manifest artifact record is invalid")
        name = record["name"]
        if Path(name).name != name or name in expected_names:
            raise RuntimeError("Python release manifest artifact name is unsafe")
        expected_names.add(name)
        artifact = root / name
        if not artifact.is_file() or artifact.is_symlink():
            raise RuntimeError("Python release artifact is unavailable or unsafe")
        if record["size"] != artifact.stat().st_size or record["sha256"] != sha256_file(artifact):
            raise RuntimeError("Python release artifact does not match its manifest")
    actual_names = {path.name for path in root.iterdir()}
    if actual_names != expected_names:
        raise RuntimeError("Python release output contains an unmanifested artifact")

    source_archives = [
        root / record["name"] for record in artifact_records if record["name"].endswith(".tar.gz")
    ]
    wheels = [
        root / record["name"] for record in artifact_records if record["name"].endswith(".whl")
    ]
    if len(source_archives) != 1 or len(wheels) != 1:
        raise RuntimeError("Python release must contain one source archive and one wheel")
    with tempfile.TemporaryDirectory(prefix="tvtime-python-release-verify-") as temporary:
        temporary_root = Path(temporary)
        sdist_root = temporary_root / "sdist"
        wheel_root = temporary_root / "wheel"
        sdist_root.mkdir()
        wheel_root.mkdir()
        extract_sdist(source_archives[0], sdist_root)
        extract_wheel(wheels[0], wheel_root)
        scan_extracted_tree(sdist_root, [*forbidden_values, str(temporary_root)])
        scan_extracted_tree(wheel_root, [*forbidden_values, str(temporary_root)])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a source-bound Python release artifact set."
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--forbidden-value", action="append", default=[])
    arguments = parser.parse_args()
    verify_release_set(
        arguments.root.resolve(strict=True),
        source_commit=arguments.source_commit,
        source_tree=arguments.source_tree,
        forbidden_values=arguments.forbidden_value,
    )
    print("Python release source, membership, content, and privacy verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
