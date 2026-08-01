from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

try:
    from script.release_version import parse_release_version
except ModuleNotFoundError:
    from release_version import parse_release_version

GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
THUMBPRINT_PATTERN = re.compile(r"^[0-9A-F]{40}$")
SAFE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,159}$")
MAXIMUM_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
DEPENDENCY_LOCK_PATHS = (
    "global.json",
    "requirements-windows-build.lock",
    "windows/TVTimeRecovery.Windows/packages.lock.json",
)


def sha256_file(path: Path) -> str:
    metadata = path.lstat()
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("A Windows release artifact was not a regular file.")
    if metadata.st_size <= 0 or metadata.st_size > MAXIMUM_ARTIFACT_BYTES:
        raise RuntimeError("A Windows release artifact had an unsafe byte size.")
    digest = hashlib.sha256()
    byte_count = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            byte_count += len(chunk)
            digest.update(chunk)
    if byte_count != metadata.st_size:
        raise RuntimeError("A Windows release artifact changed while it was read.")
    return digest.hexdigest()


def artifact_record(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    if SAFE_NAME_PATTERN.fullmatch(resolved.name) is None:
        raise RuntimeError("A Windows release artifact name was unsafe.")
    return {
        "name": resolved.name,
        "size": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def dependency_lock_records(source_root: Path) -> list[dict[str, str]]:
    resolved_root = source_root.resolve(strict=True)
    if not resolved_root.is_dir() or resolved_root.is_symlink():
        raise RuntimeError("The Windows release source root was unsafe.")
    records: list[dict[str, str]] = []
    for relative in DEPENDENCY_LOCK_PATHS:
        path = (resolved_root / relative).resolve(strict=True)
        if resolved_root not in path.parents or not path.is_file() or path.is_symlink():
            raise RuntimeError("A Windows release dependency lock was unsafe.")
        records.append({"path": relative, "sha256": sha256_file(path)})
    return records


def generate(arguments: argparse.Namespace) -> None:
    parse_release_version(arguments.release_version)
    if not GIT_OBJECT_PATTERN.fullmatch(arguments.source_commit):
        raise RuntimeError("The Windows release source commit was invalid.")
    if not GIT_OBJECT_PATTERN.fullmatch(arguments.source_tree):
        raise RuntimeError("The Windows release source tree was invalid.")
    if not SHA256_PATTERN.fullmatch(arguments.unsigned_package_sha256):
        raise RuntimeError("The unsigned Windows package digest was invalid.")
    if not SHA256_PATTERN.fullmatch(arguments.block_map_sha256):
        raise RuntimeError("The Windows package block-map digest was invalid.")
    if not THUMBPRINT_PATTERN.fullmatch(arguments.certificate_thumbprint):
        raise RuntimeError("The Windows signing certificate thumbprint was invalid.")
    if arguments.output.exists() or arguments.output.is_symlink():
        raise RuntimeError("The Windows release manifest output must be fresh.")

    named_inputs = {
        "package": arguments.package,
        "certificate": arguments.certificate,
        "installer": arguments.installer,
        "uninstaller": arguments.uninstaller,
        "trust_helper": arguments.trust_helper,
        "readme": arguments.readme,
        "license": arguments.license,
        "third_party_notices": arguments.third_party_notices,
    }
    records = {name: artifact_record(path) for name, path in named_inputs.items()}
    if len({record["name"].casefold() for record in records.values()}) != len(records):
        raise RuntimeError("Windows release artifact names were ambiguous.")

    manifest = {
        "schema": "tvtime-windows-alpha-release-v1",
        "release": {
            "version": arguments.release_version,
            "channel": "experimental-alpha",
            "architecture": "x64",
            "package_identity": arguments.package_identity,
        },
        "source": {
            "git_commit": arguments.source_commit,
            "git_tree": arguments.source_tree,
            "stage": "verified-git-archive",
        },
        "signing": {
            "kind": "ephemeral-self-signed-alpha",
            "certificate_thumbprint": arguments.certificate_thumbprint,
            "private_key_included": False,
        },
        "integrity": {
            "unsigned_package_sha256": arguments.unsigned_package_sha256,
            "signed_block_map_sha256": arguments.block_map_sha256,
        },
        "build_environment": {
            "python": arguments.python_version,
            "dotnet_sdk": arguments.dotnet_sdk_version,
        },
        "dependency_locks": dependency_lock_records(arguments.source_root),
        "artifacts": records,
        "known_limits": [
            "final-msix-binary-to-component-inventory",
            "self-signed-certificate-requires-explicit-local-trust",
            "physical-device-and-ui-coverage-remains-tester-dependent",
            "windows-build-is-prerelease-only",
        ],
    }
    arguments.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--release-version", required=True)
    result.add_argument("--source-commit", required=True)
    result.add_argument("--source-tree", required=True)
    result.add_argument("--package-identity", required=True)
    result.add_argument("--certificate-thumbprint", required=True)
    result.add_argument("--unsigned-package-sha256", required=True)
    result.add_argument("--block-map-sha256", required=True)
    result.add_argument("--python-version", required=True)
    result.add_argument("--dotnet-sdk-version", required=True)
    result.add_argument("--source-root", type=Path, required=True)
    result.add_argument("--package", type=Path, required=True)
    result.add_argument("--certificate", type=Path, required=True)
    result.add_argument("--installer", type=Path, required=True)
    result.add_argument("--uninstaller", type=Path, required=True)
    result.add_argument("--trust-helper", type=Path, required=True)
    result.add_argument("--readme", type=Path, required=True)
    result.add_argument("--license", type=Path, required=True)
    result.add_argument("--third-party-notices", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


if __name__ == "__main__":
    generate(parser().parse_args())
