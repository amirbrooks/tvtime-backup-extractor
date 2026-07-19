from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))
from sdist_metadata import normalize_sdist_metadata, verify_sdist_metadata  # noqa: E402
from verify_python_release import sha256_file, verify_release_set  # noqa: E402

GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PYTHON_ENVIRONMENT_OVERRIDES = (
    "PYTHONCASEOK",
    "PYTHONEXECUTABLE",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "PYTHONPLATLIBDIR",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
    "__PYVENV_LAUNCHER__",
)


def reject_python_environment_overrides() -> None:
    for name in PYTHON_ENVIRONMENT_OVERRIDES:
        if name in os.environ:
            raise RuntimeError(f"{name} must be unset for a Python release build")


def git_output(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def capture_source_identity(
    root: Path,
    expected_commit: str,
    *,
    controlled_build_root: Path | None = None,
) -> tuple[str, int]:
    if not GIT_OBJECT_PATTERN.fullmatch(expected_commit):
        raise RuntimeError("--source-commit must be a full lowercase Git commit hash")
    actual_commit = git_output(root, "rev-parse", "HEAD^{commit}")
    if actual_commit != expected_commit:
        raise RuntimeError("--source-commit does not match the checked-out Git commit")
    status_arguments = ["status", "--porcelain=v1", "--untracked-files=all"]
    if controlled_build_root is not None:
        repository = root.resolve(strict=True)
        build_root = controlled_build_root.resolve(strict=True)
        try:
            relative_build_root = build_root.relative_to(repository)
        except ValueError:
            pass
        else:
            if relative_build_root == Path("."):
                raise RuntimeError("controlled build root cannot be the Git worktree")
            status_arguments.extend(
                [
                    "--",
                    ".",
                    f":(exclude,top,literal){relative_build_root.as_posix()}",
                ]
            )
    status = git_output(root, *status_arguments)
    if status:
        raise RuntimeError("Python releases require a completely clean Git worktree")
    source_tree = git_output(root, "rev-parse", f"{expected_commit}^{{tree}}")
    if not GIT_OBJECT_PATTERN.fullmatch(source_tree):
        raise RuntimeError("Git returned an invalid source tree identity")
    timestamp_text = git_output(root, "show", "-s", "--format=%ct", expected_commit)
    try:
        timestamp = int(timestamp_text)
    except ValueError:
        raise RuntimeError("Git returned an invalid source commit timestamp") from None
    if timestamp < 0:
        raise RuntimeError("Git returned an invalid source commit timestamp")
    return source_tree, timestamp


def safe_archive_path(value: str) -> Path:
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


def stage_git_archive(root: Path, source_commit: str, destination: Path) -> None:
    completed = subprocess.run(
        ["git", "-C", str(root), "archive", "--format=tar", source_commit],
        check=True,
        capture_output=True,
    )
    seen: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(completed.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            relative = safe_archive_path(member.name)
            if member.name in seen:
                raise RuntimeError("Git source archive contains a duplicate member path")
            seen.add(member.name)
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=False)
                target.chmod(0o755)
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
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def write_release_manifest(
    output: Path,
    *,
    source_commit: str,
    source_tree: str,
) -> None:
    artifacts = sorted(
        (
            {
                "name": artifact.name,
                "sha256": sha256_file(artifact),
                "size": artifact.stat().st_size,
            }
            for artifact in output.iterdir()
        ),
        key=lambda record: record["name"],
    )
    manifest = {
        "artifacts": artifacts,
        "schema": "tvtime-python-release-manifest-v1",
        "source": {
            "git_commit": source_commit,
            "git_tree": source_tree,
            "worktree": "clean",
        },
    }
    manifest_path = output / "python-release-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o644)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a fresh, source-bound wheel and deterministic private Python source archive."
        )
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--outdir", type=Path, default=Path("dist"))
    arguments = parser.parse_args()

    reject_python_environment_overrides()
    root = Path(__file__).resolve().parent.parent
    source_tree, source_timestamp = capture_source_identity(root, arguments.source_commit)
    output = (
        (root / arguments.outdir).resolve()
        if not arguments.outdir.is_absolute()
        else arguments.outdir
    )
    if output.exists() or output.is_symlink():
        raise RuntimeError("distribution output must be a fresh path")
    output.parent.mkdir(parents=True, exist_ok=True)
    build_root = Path(tempfile.mkdtemp(dir=output.parent, prefix=f".{output.name}.build-"))
    source = build_root / "source"
    stage = build_root / "artifacts"
    source.mkdir(mode=0o755)
    stage.mkdir(mode=0o755)
    try:
        stage_git_archive(root, arguments.source_commit, source)
        environment = dict(os.environ)
        environment["SOURCE_DATE_EPOCH"] = str(source_timestamp)
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "build",
                "--no-isolation",
                "--outdir",
                str(stage),
                str(source),
            ],
            check=True,
            cwd=source,
            env=environment,
        )
        source_archives = list(stage.glob("*.tar.gz"))
        wheels = list(stage.glob("*.whl"))
        if len(source_archives) != 1 or len(wheels) != 1 or len(list(stage.iterdir())) != 2:
            raise RuntimeError(
                "build frontend did not create exactly one wheel and one source archive"
            )
        normalize_sdist_metadata(source_archives[0])
        verify_sdist_metadata(source_archives[0])
        write_release_manifest(
            stage,
            source_commit=arguments.source_commit,
            source_tree=source_tree,
        )
        forbidden_values = [str(root), str(Path.home()), str(build_root)]
        verify_release_set(
            stage,
            source_commit=arguments.source_commit,
            source_tree=source_tree,
            forbidden_values=forbidden_values,
        )
        final_tree, final_timestamp = capture_source_identity(
            root,
            arguments.source_commit,
            controlled_build_root=build_root,
        )
        if (final_tree, final_timestamp) != (source_tree, source_timestamp):
            raise RuntimeError("Python release source identity changed during the build")
        os.replace(stage, output)
    finally:
        if build_root.exists():
            shutil.rmtree(build_root)

    print(f"Built fresh source-bound verified distributions at {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
