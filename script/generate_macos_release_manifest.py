from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

PIN_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)$")
GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_version(arguments: list[str]) -> str:
    completed = subprocess.run(
        arguments,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return " ".join(line.strip() for line in completed.stdout.splitlines() if line.strip())


def dependency_records(requirement_paths: list[Path]) -> list[dict[str, str]]:
    records: dict[str, dict[str, str]] = {}
    for path in requirement_paths:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            match = PIN_PATTERN.fullmatch(line)
            if match is None:
                raise RuntimeError(f"Release requirement is not an exact simple pin: {path.name}")
            name, expected = match.groups()
            distribution = metadata.distribution(name)
            if distribution.version != expected:
                raise RuntimeError(f"Installed dependency does not match release pin: {name}")
            normalized = re.sub(r"[-_.]+", "-", name.casefold())
            records[normalized] = {
                "name": distribution.metadata.get("Name", name),
                "version": distribution.version,
                "source": path.name,
            }
    pip_distribution = metadata.distribution("pip")
    records["pip"] = {
        "name": pip_distribution.metadata.get("Name", "pip"),
        "version": pip_distribution.version,
        "source": "build-environment",
    }
    return [records[name] for name in sorted(records)]


def macho_architectures(path: Path) -> list[str]:
    completed = subprocess.run(
        ["/usr/bin/lipo", "-archs", str(path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return []
    return sorted(completed.stdout.split())


def file_records(app: Path) -> list[dict[str, object]]:
    root = app.parent
    records: list[dict[str, object]] = []
    for path in sorted(app.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata_value = path.lstat()
        if stat.S_ISLNK(metadata_value.st_mode):
            records.append({"path": relative, "type": "symlink", "target": os.readlink(path)})
        elif stat.S_ISDIR(metadata_value.st_mode):
            records.append({"path": relative, "type": "directory"})
        elif stat.S_ISREG(metadata_value.st_mode):
            record: dict[str, object] = {
                "path": relative,
                "type": "file",
                "size": metadata_value.st_size,
                "sha256": sha256_file(path),
            }
            architectures = macho_architectures(path)
            if architectures:
                record["macho_architectures"] = architectures
            records.append(record)
        else:
            raise RuntimeError("Release app contains an unsupported filesystem entry")
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--architecture", choices=("arm64", "x86_64"), required=True)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--swift-lockfile", type=Path, required=True)
    parser.add_argument("--dependency-lock", type=Path, action="append", required=True)
    parser.add_argument("--requirements", type=Path, action="append", required=True)
    arguments = parser.parse_args()

    app = arguments.app.resolve(strict=True)
    artifact = arguments.artifact.resolve(strict=True)
    swift_lockfile = arguments.swift_lockfile.resolve(strict=True)
    dependency_locks = [path.resolve(strict=True) for path in arguments.dependency_lock]
    output = arguments.output
    if output.exists() or output.is_symlink():
        raise RuntimeError("Release manifest output must be fresh")
    if not app.is_dir() or not artifact.is_file():
        raise RuntimeError("Release app or installation artifact is unavailable")
    if not swift_lockfile.is_file() or any(not path.is_file() for path in dependency_locks):
        raise RuntimeError("Release dependency lock input is unavailable")
    if not GIT_OBJECT_PATTERN.fullmatch(arguments.source_commit):
        raise RuntimeError("Release source commit must be a full lowercase Git object ID")
    if not GIT_OBJECT_PATTERN.fullmatch(arguments.source_tree):
        raise RuntimeError("Release source tree must be a full lowercase Git object ID")

    with (app / "Contents" / "Info.plist").open("rb") as handle:
        info = plistlib.load(handle)
    app_file_records = file_records(app)
    macho_records = [record for record in app_file_records if "macho_architectures" in record]
    expected_architectures = [arguments.architecture]
    if not macho_records or any(
        record["macho_architectures"] != expected_architectures for record in macho_records
    ):
        raise RuntimeError("Release app does not exactly match its declared architecture")
    manifest = {
        "schema": "tvtime-macos-release-manifest-v2",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source": {
            "git_commit": arguments.source_commit,
            "git_tree": arguments.source_tree,
            "worktree": "clean",
        },
        "application": {
            "bundle_identifier": info["CFBundleIdentifier"],
            "short_version": info["CFBundleShortVersionString"],
            "bundle_version": info["CFBundleVersion"],
            "architecture": arguments.architecture,
        },
        "installation_artifact": {
            "name": artifact.name,
            "size": artifact.stat().st_size,
            "sha256": sha256_file(artifact),
        },
        "build_environment": {
            "python": sys.version.split()[0],
            "xcode": command_version(["/usr/bin/xcodebuild", "-version"]),
            "swift": command_version(["/usr/bin/xcrun", "swift", "--version"]),
            "pyinstaller": command_version([sys.executable, "-m", "PyInstaller", "--version"]),
        },
        "dependency_locks": [
            {"name": swift_lockfile.name, "sha256": sha256_file(swift_lockfile)},
            *[
                {"name": path.name, "sha256": sha256_file(path)}
                for path in sorted(dependency_locks, key=lambda item: item.name)
            ],
        ],
        "dependencies": dependency_records(arguments.requirements),
        "app_files": app_file_records,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
