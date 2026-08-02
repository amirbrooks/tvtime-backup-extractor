from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import stat
import sys
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Mapping
from importlib import metadata
from pathlib import Path, PurePosixPath

PYTHON_DISTRIBUTIONS = {
    "altgraph": "0.17.5",
    "charset-normalizer": "3.4.9",
    "iphone-backup-decrypt": "0.9.0",
    "packaging": "25.0",
    "pefile": "2024.8.26",
    "pillow": "12.3.0",
    "pycryptodome": "3.23.0",
    "pyinstaller": "6.21.0",
    "pyinstaller-hooks-contrib": "2026.6",
    "pywin32-ctypes": "0.2.3",
    "reportlab": "5.0.0",
    "setuptools": "83.0.0",
}
BUILD_ONLY_NUGET_PACKAGES = {
    ("Microsoft.Windows.SDK.BuildTools", "10.0.26100.4948"),
}
REVIEWED_CPYTHON_VERSION = "3.13.12"
PRIVATE_WINDOWS_VERSION = "0.3.1-alpha.1"
DOTNET_SDK_VERSION = "8.0.423"
DOTNET_RUNTIME_PACKAGE = (
    "Microsoft.NETCore.App.Runtime.win-x64",
    "8.0.29",
    "Xic9teVR3xPPivqfC1ZtTUUuuUaDou8aJMqDs9ThXqXWi4Jb174IhlgyQzsM8tke9dBTIombzgEU+oTwnyzNtg==",
    "XBQUNw6xNOTWm+vblnnpxpPYJOm1eYzSjJpk5wlHvodNU5JXmX5dxffRz8qvqkO4rU5UzN8oruz63yrvP5oHEQ==",
)
REVIEWED_NUGET_PACKAGE_SHA512 = {
    ("Microsoft.Web.WebView2", "1.0.3719.77"): (
        "Cpq7EGgijiCN0lg1RlTZuZcRkzyo/USU9cEJMSPh6FG4PLjmTEpJ5NKuJqQ06ONnVVARCcTLf31IjjhFJUrApw=="
    ),
    ("Microsoft.Windows.SDK.BuildTools", "10.0.26100.4948"): (
        "cmungnLvmFQo50GkX+tJ//+hevjgL1VIM1H6kx6QAjxyAIzmZ5op/v5GPa3k8/cVSlVukWZDFVTHFPKRDL/Eeg=="
    ),
    ("Microsoft.Windows.SDK.BuildTools.MSIX", "1.7.251221100"): (
        "3OEJjmDvPQH649p73taTt2n4AeY9dMg/gaDdZHQZh4xOOTAjdfuzuuw2FxSedpQuP9Pbki7FNGoE1mM4kjf0Mw=="
    ),
    ("Microsoft.WindowsAppSDK.Base", "2.0.4"): (
        "Mjy6K7l9kj1+5UNPg8y/fkHx2be0TdLYaIWJsf7SlkZHEcFd6bl5L8uSjPNYK0Xz5vfaYELO5yKszHHIbaO75A=="
    ),
    ("Microsoft.WindowsAppSDK.Foundation", "2.1.0"): (
        "R7jyix4rXyFtGva55FvSaVt1nw2TGS0bVWEJMlTo46Hprrnvyz8LKtUsc02P5tByuc9DN7v742LsY0/pJ8O3dg=="
    ),
    ("Microsoft.WindowsAppSDK.InteractiveExperiences", "2.0.15"): (
        "TCJ88/ggWwMXd23u38HHjhPDATu14CgMC6OFqIsP7Kll6QVxIjA9+XVo6XPmGxnzn71UK71XJYR2QHRbRYOiqQ=="
    ),
    ("Microsoft.WindowsAppSDK.Runtime", "2.2.0"): (
        "Lx/BvrhrYrSecSkUcCfBzV8I3ye7Zd5AFSLeObSuhmap+rMsVmQUKQ1tzdtZfMOUgDYOuyfQFyWG0x7m3VrWNA=="
    ),
    ("Microsoft.WindowsAppSDK.WinUI", "2.2.1"): (
        "rfTm/Deoj5PrhmUXu4YziVSgqv8oxeDUSTyYdOVsxy7CRm/zsbIgQZrcp23i2i6tZ1abW+x8311q7DbyGk8dgg=="
    ),
}
MAXIMUM_NOTICE_BYTES = 4 * 1024 * 1024
MAXIMUM_NUGET_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:\.\d+)?$")


def _is_link_or_reparse(path: Path, metadata_value: object) -> bool:
    if path.is_symlink():
        return True
    attributes = int(getattr(metadata_value, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return bool(reparse_flag and attributes & reparse_flag)


def _regular_bytes(path: Path) -> bytes:
    metadata_value = path.lstat()
    if not stat.S_ISREG(metadata_value.st_mode) or _is_link_or_reparse(path, metadata_value):
        raise RuntimeError("A required third-party notice was not a regular file.")
    if metadata_value.st_size <= 0 or metadata_value.st_size > MAXIMUM_NOTICE_BYTES:
        raise RuntimeError("A required third-party notice had an unsafe byte size.")
    payload = path.read_bytes()
    if len(payload) != metadata_value.st_size:
        raise RuntimeError("A required third-party notice changed while it was read.")
    return payload


def _safe_component(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")
    if not normalized or normalized in {".", ".."}:
        raise RuntimeError("A third-party component name was unsafe.")
    return normalized


def _sha512_base64(path: Path) -> str:
    metadata_value = path.lstat()
    if (
        not stat.S_ISREG(metadata_value.st_mode)
        or _is_link_or_reparse(path, metadata_value)
        or metadata_value.st_size <= 0
        or metadata_value.st_size > MAXIMUM_NUGET_PACKAGE_BYTES
    ):
        raise RuntimeError("A restored NuGet package had an unsafe file shape or byte size.")
    digest = hashlib.sha512()
    byte_count = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            byte_count += len(chunk)
            digest.update(chunk)
    if byte_count != metadata_value.st_size:
        raise RuntimeError("A restored NuGet package changed while it was hashed.")
    return base64.b64encode(digest.digest()).decode("ascii")


def _write_bound_file(root: Path, relative: PurePosixPath, payload: bytes) -> dict[str, object]:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise RuntimeError("A generated third-party notice path was unsafe.")
    target = root.joinpath(*relative.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        raise RuntimeError("A generated third-party notice path was duplicated.")
    target.write_bytes(payload)
    return {
        "relative_path": relative.as_posix(),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _python_license_files(distribution: metadata.Distribution) -> list[Path]:
    selected: list[Path] = []
    for entry in distribution.files or ():
        parts = tuple(part.casefold() for part in entry.parts)
        if not parts or not parts[0].endswith(".dist-info"):
            continue
        basename = parts[-1]
        if not (
            any(part in {"license", "licenses"} for part in parts)
            or basename.startswith(("license", "copying", "notice"))
        ):
            continue
        candidate = Path(distribution.locate_file(entry))
        if candidate.is_file() and not candidate.is_symlink():
            selected.append(candidate)
    return sorted(set(selected), key=lambda path: path.name.casefold())


def _validate_distribution_record(distribution: metadata.Distribution) -> None:
    entries = tuple(distribution.files or ())
    if not entries:
        raise RuntimeError("A pinned Python component had no installed RECORD binding.")
    for entry in entries:
        expected_hash = entry.hash
        if expected_hash is None:
            if entry.name == "RECORD" and entry.parent.name.endswith(".dist-info"):
                continue
            raise RuntimeError("A pinned Python component contained an unbound installed file.")
        if expected_hash.mode.casefold() != "sha256":
            raise RuntimeError("A pinned Python component used an unsupported RECORD hash.")
        source = Path(distribution.locate_file(entry))
        source_metadata = source.lstat()
        if not stat.S_ISREG(source_metadata.st_mode) or _is_link_or_reparse(
            source, source_metadata
        ):
            raise RuntimeError("A pinned Python component contained an unsafe installed file.")
        if entry.size is not None and source_metadata.st_size != entry.size:
            raise RuntimeError("A pinned Python component changed after installation.")
        digest = hashlib.sha256()
        byte_count = 0
        with source.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                byte_count += len(chunk)
                digest.update(chunk)
        if byte_count != source_metadata.st_size:
            raise RuntimeError("A pinned Python component changed while it was inspected.")
        observed = base64.urlsafe_b64encode(digest.digest()).rstrip(b"=")
        if observed.decode("ascii") != expected_hash.value:
            raise RuntimeError("A pinned Python component changed after installation.")


def verify_python_installation() -> None:
    for name, expected_version in sorted(PYTHON_DISTRIBUTIONS.items()):
        distribution = metadata.distribution(name)
        if distribution.version != expected_version:
            raise RuntimeError("A Python component did not match its reviewed version.")
        _validate_distribution_record(distribution)


def _collect_python(root: Path) -> list[dict[str, object]]:
    verify_python_installation()
    components: list[dict[str, object]] = []
    for name, expected_version in sorted(PYTHON_DISTRIBUTIONS.items()):
        distribution = metadata.distribution(name)
        if distribution.version != expected_version:
            raise RuntimeError("A Python license component did not match its reviewed version.")
        licenses = _python_license_files(distribution)
        if not licenses:
            raise RuntimeError("A pinned Python component did not ship a discoverable license.")
        bindings = []
        for index, source in enumerate(licenses, 1):
            filename = f"{index:02d}-{_safe_component(source.name)}"
            bindings.append(
                _write_bound_file(
                    root,
                    PurePosixPath("python", _safe_component(name), filename),
                    _regular_bytes(source),
                )
            )
        components.append(
            {"ecosystem": "python", "name": name, "version": expected_version, "files": bindings}
        )
    return components


def _nuget_bindings(lock: dict[str, object]) -> dict[tuple[str, str], str]:
    if set(lock) != {"version", "dependencies"} or lock.get("version") != 1:
        raise RuntimeError("The NuGet lock file had an unsupported shape.")
    targets = lock.get("dependencies")
    if not isinstance(targets, dict) or not targets:
        raise RuntimeError("The NuGet lock file did not contain dependency targets.")
    selected: dict[tuple[str, str], str] = {}
    for dependencies in targets.values():
        if not isinstance(dependencies, dict):
            raise RuntimeError("The NuGet lock dependency target was malformed.")
        for name, binding in dependencies.items():
            if not isinstance(name, str) or not isinstance(binding, dict):
                raise RuntimeError("A NuGet lock binding was malformed.")
            version = binding.get("resolved")
            content_hash = binding.get("contentHash")
            if (
                not isinstance(version, str)
                or VERSION_PATTERN.fullmatch(version) is None
                or not isinstance(content_hash, str)
            ):
                raise RuntimeError("A NuGet lock binding was incomplete.")
            key = (name, version)
            if key in selected and selected[key] != content_hash:
                raise RuntimeError("A NuGet package had conflicting content hashes.")
            selected[key] = content_hash
    return selected


def _nuspec_license(package_root: Path) -> tuple[str, str]:
    nuspecs = list(package_root.glob("*.nuspec"))
    if len(nuspecs) != 1:
        raise RuntimeError("A locked NuGet package did not have one exact nuspec.")
    root = ET.fromstring(_regular_bytes(nuspecs[0]))
    metadata_nodes = [node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "metadata"]
    if len(metadata_nodes) != 1:
        raise RuntimeError("A locked NuGet package had malformed metadata.")
    licenses = [node for node in metadata_nodes[0] if node.tag.rsplit("}", 1)[-1] == "license"]
    if len(licenses) != 1 or licenses[0].attrib.get("type") not in {"file", "expression"}:
        raise RuntimeError("A redistributed NuGet package lacked exact license metadata.")
    value = (licenses[0].text or "").strip()
    if not value or len(value.encode("utf-8")) > 1024:
        raise RuntimeError("A NuGet package license declaration was malformed.")
    return licenses[0].attrib["type"], value


def _is_nuget_packaging_member(relative: PurePosixPath) -> bool:
    parts = tuple(part.casefold() for part in relative.parts)
    return (
        parts == ("[content_types].xml",)
        or parts == ("_rels", ".rels")
        or parts[:4] == ("package", "services", "metadata", "core-properties")
    )


def _validate_expanded_nuget_package(package_root: Path, package: Path) -> None:
    try:
        with zipfile.ZipFile(package) as archive:
            archive_entries: dict[str, zipfile.ZipInfo] = {}
            for info in archive.infolist():
                if info.is_dir():
                    continue
                relative = PurePosixPath(info.filename.replace("\\", "/"))
                if relative.is_absolute() or any(
                    part in {"", ".", ".."} for part in relative.parts
                ):
                    raise RuntimeError("A restored NuGet archive contained an unsafe path.")
                key = relative.as_posix().casefold()
                if key in archive_entries:
                    raise RuntimeError("A restored NuGet archive contained ambiguous paths.")
                archive_entries[key] = info

            required_archive_entries = {
                key
                for key, info in archive_entries.items()
                if not _is_nuget_packaging_member(PurePosixPath(info.filename.replace("\\", "/")))
            }
            ignored = {
                package.name.casefold(),
                f"{package.name}.sha512".casefold(),
                ".nupkg.metadata",
            }
            expanded_entries: set[str] = set()
            for expanded in package_root.rglob("*"):
                metadata_value = expanded.lstat()
                if _is_link_or_reparse(expanded, metadata_value):
                    raise RuntimeError("A restored NuGet package contained a linked asset.")
                if stat.S_ISDIR(metadata_value.st_mode):
                    continue
                if not stat.S_ISREG(metadata_value.st_mode):
                    raise RuntimeError("A restored NuGet package contained an unsafe asset.")
                relative = expanded.relative_to(package_root).as_posix()
                if relative.casefold() in ignored:
                    continue
                key = relative.casefold()
                if key in expanded_entries:
                    raise RuntimeError("A restored NuGet package contained ambiguous paths.")
                expanded_entries.add(key)
                info = archive_entries.get(key)
                if info is None:
                    raise RuntimeError(
                        "An expanded NuGet asset was not bound to its package archive."
                    )
                if metadata_value.st_size != info.file_size:
                    raise RuntimeError("An expanded NuGet asset changed after restore.")
                expanded_hash = hashlib.sha256()
                archive_hash = hashlib.sha256()
                with expanded.open("rb") as handle:
                    while chunk := handle.read(1024 * 1024):
                        expanded_hash.update(chunk)
                with archive.open(info, "r") as handle:
                    while chunk := handle.read(1024 * 1024):
                        archive_hash.update(chunk)
                if expanded_hash.digest() != archive_hash.digest():
                    raise RuntimeError("An expanded NuGet asset changed after restore.")
            if expanded_entries != required_archive_entries:
                raise RuntimeError(
                    "A restored NuGet package omitted a required package archive member."
                )
    except (OSError, zipfile.BadZipFile) as exc:
        raise RuntimeError("A restored NuGet package could not be validated safely.") from exc


def _collect_nuget(
    root: Path,
    lock_path: Path,
    nuget_root: Path,
    reviewed_package_sha512: Mapping[tuple[str, str], str] | None = None,
) -> list[dict[str, object]]:
    lock = json.loads(_regular_bytes(lock_path).decode("utf-8"))
    bindings = _nuget_bindings(lock)
    reviewed_hashes = dict(
        REVIEWED_NUGET_PACKAGE_SHA512
        if reviewed_package_sha512 is None
        else reviewed_package_sha512
    )
    if set(reviewed_hashes) != set(bindings):
        raise RuntimeError(
            "The reviewed NuGet package hash inventory did not match the committed lock."
        )
    components: list[dict[str, object]] = []
    for (name, version), expected_hash in sorted(bindings.items()):
        package_root = nuget_root / name.casefold() / version
        sha_files = list(package_root.glob("*.nupkg.sha512"))
        packages = list(package_root.glob("*.nupkg"))
        metadata_files = list(package_root.glob(".nupkg.metadata"))
        if len(sha_files) != 1 or len(packages) != 1 or len(metadata_files) != 1:
            raise RuntimeError("A locked NuGet package or hash binding was unavailable.")
        package_hash = _regular_bytes(sha_files[0]).decode("ascii").strip()
        try:
            base64.b64decode(package_hash, validate=True)
        except ValueError as exc:
            raise RuntimeError("A locked NuGet package hash was malformed.") from exc
        if _sha512_base64(packages[0]) != package_hash:
            raise RuntimeError("A restored NuGet package did not match its downloaded hash.")
        if package_hash != reviewed_hashes[(name, version)]:
            raise RuntimeError("A restored NuGet package did not match its reviewed package hash.")
        package_metadata = json.loads(_regular_bytes(metadata_files[0]).decode("utf-8"))
        if package_metadata.get("contentHash") != expected_hash:
            raise RuntimeError("A restored NuGet package did not match the committed content hash.")
        _validate_expanded_nuget_package(package_root, packages[0])
        if (name, version) in BUILD_ONLY_NUGET_PACKAGES:
            components.append(
                {
                    "ecosystem": "nuget-build-only",
                    "name": name,
                    "version": version,
                    "content_hash": expected_hash,
                    "package_sha512": package_hash,
                    "files": [],
                }
            )
            continue
        license_type, license_value = _nuspec_license(package_root)
        bindings = []
        if license_type == "file":
            relative = PurePosixPath(license_value.replace("\\", "/"))
            if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
                raise RuntimeError("A NuGet license file path was unsafe.")
            source = package_root.joinpath(*relative.parts)
            bindings.append(
                _write_bound_file(
                    root,
                    PurePosixPath("nuget", _safe_component(name), _safe_component(source.name)),
                    _regular_bytes(source),
                )
            )
        else:
            bindings.append(
                _write_bound_file(
                    root,
                    PurePosixPath("nuget", _safe_component(name), "license-expression.txt"),
                    (license_value + "\n").encode("utf-8"),
                )
            )
        for notice in sorted(package_root.rglob("*")):
            if not notice.is_file() or notice.is_symlink():
                continue
            basename = notice.name.casefold()
            if "notice" not in basename and "thirdparty" not in basename:
                continue
            bindings.append(
                _write_bound_file(
                    root,
                    PurePosixPath(
                        "nuget",
                        _safe_component(name),
                        f"notice-{len(bindings):02d}-{_safe_component(notice.name)}",
                    ),
                    _regular_bytes(notice),
                )
            )
        components.append(
            {
                "ecosystem": "nuget",
                "name": name,
                "version": version,
                "content_hash": expected_hash,
                "package_sha512": package_hash,
                "files": bindings,
            }
        )
    return components


def _collect_dotnet_runtime(
    root: Path,
    nuget_root: Path,
) -> dict[str, object]:
    name, version, expected_content_hash, expected_package_sha512 = DOTNET_RUNTIME_PACKAGE
    package_root = nuget_root / name.casefold() / version
    sha_files = list(package_root.glob("*.nupkg.sha512"))
    packages = list(package_root.glob("*.nupkg"))
    metadata_files = list(package_root.glob(".nupkg.metadata"))
    if len(sha_files) != 1 or len(packages) != 1 or len(metadata_files) != 1:
        raise RuntimeError("The pinned .NET runtime package was unavailable.")
    package_hash = _regular_bytes(sha_files[0]).decode("ascii").strip()
    if (
        package_hash != expected_package_sha512
        or _sha512_base64(packages[0]) != expected_package_sha512
    ):
        raise RuntimeError("The .NET runtime package did not match its reviewed hash.")
    package_metadata = json.loads(_regular_bytes(metadata_files[0]).decode("utf-8"))
    if package_metadata.get("contentHash") != expected_content_hash:
        raise RuntimeError("The .NET runtime package metadata did not match its reviewed hash.")
    _validate_expanded_nuget_package(package_root, packages[0])
    license_type, license_value = _nuspec_license(package_root)
    if license_type != "expression" or license_value != "MIT":
        raise RuntimeError("The .NET runtime package license declaration changed.")

    runtime_license = package_root / "LICENSE.TXT"
    runtime_notices = package_root / "THIRD-PARTY-NOTICES.TXT"
    bindings = [
        _write_bound_file(
            root,
            PurePosixPath("dotnet", "runtime-license-expression.txt"),
            b"MIT\n",
        ),
        _write_bound_file(
            root,
            PurePosixPath("dotnet", "LICENSE.txt"),
            _regular_bytes(runtime_license),
        ),
        _write_bound_file(
            root,
            PurePosixPath("dotnet", "ThirdPartyNotices.txt"),
            _regular_bytes(runtime_notices),
        ),
    ]
    return {
        "ecosystem": "dotnet-runtime",
        "name": name,
        "version": version,
        "content_hash": expected_content_hash,
        "package_sha512": expected_package_sha512,
        "sdk_version": DOTNET_SDK_VERSION,
        "files": bindings,
    }


def _candidate_scope(
    source_commit: str | None,
    source_tree: str | None,
) -> dict[str, object]:
    source_bound = bool(source_commit and source_tree)
    if bool(source_commit) != bool(source_tree):
        raise RuntimeError("Windows release source binding must name both commit and tree.")
    if source_bound and (
        re.fullmatch(r"[0-9a-f]{40}", source_commit) is None
        or re.fullmatch(r"[0-9a-f]{40}", source_tree) is None
    ):
        raise RuntimeError("Windows release source binding was invalid.")
    known_release_gaps = ["final-msix-binary-to-component-inventory"]
    if not source_bound:
        known_release_gaps.append("immutable-reviewed-source-staging")
    return {
        "distribution_status": (
            "public-experimental-alpha" if source_bound else "private-unreleased"
        ),
        "final_msix_inventory_complete": False,
        "source_commit_bound": source_bound,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "known_release_gaps": known_release_gaps,
    }


def collect(args: argparse.Namespace) -> None:
    output = args.output.absolute()
    try:
        output_metadata = output.lstat()
    except OSError as exc:
        raise RuntimeError(
            "The Windows license output must be a caller-owned empty directory."
        ) from exc
    if (
        not stat.S_ISDIR(output_metadata.st_mode)
        or _is_link_or_reparse(output, output_metadata)
        or any(output.iterdir())
    ):
        raise RuntimeError("The Windows license output must be a caller-owned empty directory.")
    components = _collect_python(output)

    python_license_candidates = (
        Path(sys.base_prefix) / "LICENSE.txt",
        Path(sys.base_prefix) / "LICENSE",
    )
    python_license = next(
        (candidate for candidate in python_license_candidates if candidate.is_file()), None
    )
    if python_license is None:
        raise RuntimeError("The reviewed CPython installation license was unavailable.")
    python_version = ".".join(str(value) for value in sys.version_info[:3])
    if python_version != REVIEWED_CPYTHON_VERSION:
        raise RuntimeError("The CPython runtime did not match its reviewed Windows version.")
    components.append(
        {
            "ecosystem": "runtime",
            "name": "CPython",
            "version": python_version,
            "files": [
                _write_bound_file(
                    output,
                    PurePosixPath("runtime", "CPython-LICENSE.txt"),
                    _regular_bytes(python_license),
                )
            ],
        }
    )
    components.extend(_collect_nuget(output, args.nuget_lock, args.nuget_root))
    components.append(_collect_dotnet_runtime(output, args.nuget_root))
    project_notices = (
        ("Project-LICENSE", args.project_license),
        ("THIRD_PARTY_NOTICES", args.notice),
    )
    for label, source in project_notices:
        components.append(
            {
                "ecosystem": "project",
                "name": label,
                "version": PRIVATE_WINDOWS_VERSION,
                "files": [
                    _write_bound_file(
                        output,
                        PurePosixPath("project", _safe_component(source.name)),
                        _regular_bytes(source),
                    )
                ],
            }
        )
    manifest = {
        "schema_version": 1,
        "candidate_scope": _candidate_scope(args.source_commit, args.source_tree),
        "components": components,
    }
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_bound_file(output, PurePosixPath("MANIFEST.json"), encoded)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--nuget-lock", type=Path, required=True)
    result.add_argument("--nuget-root", type=Path, required=True)
    result.add_argument("--project-license", type=Path, required=True)
    result.add_argument("--notice", type=Path, required=True)
    result.add_argument("--source-commit")
    result.add_argument("--source-tree")
    return result


if __name__ == "__main__":
    collect(parser().parse_args())
