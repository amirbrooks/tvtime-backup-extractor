from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import sysconfig
import tempfile
from collections.abc import Iterator
from importlib import metadata
from pathlib import Path, PurePosixPath

PIN_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)$")
LICENSE_PREFIXES = ("license", "copying", "notice", "copyright")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
OPENSSL_LIBRARY_PATTERN = re.compile(r"^lib(?:crypto|ssl)\.[0-9]+(?:\.[0-9]+)*\.dylib$")
MPDECIMAL_LIBRARY_PATTERN = re.compile(r"^libmpdec\.[0-9]+(?:\.[0-9]+)*\.dylib$")
SQLITE_LIBRARY_PATTERN = re.compile(r"^libsqlite3(?:\.[0-9]+(?:\.[0-9]+)*)?\.dylib$")
STATIC_MPDECIMAL_PATTERN = re.compile(r"^_decimal\.cpython-[A-Za-z0-9_-]+\.so$")
STATIC_SQLITE_PATTERN = re.compile(r"^_sqlite3\.cpython-[A-Za-z0-9_-]+\.so$")
MPDECIMAL_DYLIB_NAME_PATTERN = re.compile(rb"libmpdec\.[0-9]+(?:\.[0-9]+)*\.dylib")
SQLITE_DYLIB_NAME_PATTERN = re.compile(rb"libsqlite3(?:\.[0-9]+(?:\.[0-9]+)*)?\.dylib")

LICENSE_SCHEMA = "tvtime-macos-license-manifest-v5"
PROVENANCE_SCHEMA = "tvtime-native-license-provenance-v3"
MACHO_HASH_SCOPE = "macho-codesign-removed-linkedit-normalized-v2"
REQUIRED_NATIVE_COMPONENTS = {"openssl", "mpdecimal", "sqlite"}
REQUIRED_NATIVE_BINARY_COUNTS = {"openssl": 2, "mpdecimal": 1, "sqlite": 1}
SQLITE_LICENSE_EXTRACTION = (
    "sqlite3.h lines 4-9; remove leading '**' and at most one following space; "
    "join with LF and end with exactly one LF"
)
REQUIRED_LICENSE_EXTRACTIONS = {
    "openssl": "byte-exact-whole-file",
    "mpdecimal": "byte-exact-whole-file",
    "sqlite": SQLITE_LICENSE_EXTRACTION,
}
MACHO_64_MAGICS = {
    b"\xcf\xfa\xed\xfe": "<",
    b"\xfe\xed\xfa\xcf": ">",
}
UNSUPPORTED_MACHO_MAGICS = {
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
CPU_ARCHITECTURES = {
    0x01000007: "x86_64",
    0x0100000C: "arm64",
}
LC_CODE_SIGNATURE = 0x1D
DYLIB_LOAD_COMMANDS = {
    0xC,  # LC_LOAD_DYLIB
    0x20,  # LC_LAZY_LOAD_DYLIB
    0x80000018,  # LC_LOAD_WEAK_DYLIB
    0x8000001F,  # LC_REEXPORT_DYLIB
    0x80000023,  # LC_LOAD_UPWARD_DYLIB
}
PROVENANCE_COMPONENT_KEYS = {
    "component",
    "display_name",
    "license_files",
    "runtime_version",
    "upstream_archive_sha256",
    "upstream_archive_url",
    "upstream_license_extraction",
    "upstream_license_path",
    "upstream_release",
    "upstream_source",
}
PROVENANCE_PYTHON_LICENSE_KEYS = {
    "license_files",
    "upstream_archive_sha256",
    "upstream_archive_url",
    "upstream_license_extraction",
    "upstream_license_path",
    "upstream_release",
    "upstream_source",
}
PROVENANCE_PROFILE_KEYS = {
    "id",
    "python_version",
    "python_license",
    "release_eligible",
    "source",
    "components",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.casefold())


def pinned_requirements(paths: list[Path]) -> dict[str, str]:
    requirements: dict[str, str] = {}
    for path in paths:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            match = PIN_PATTERN.fullmatch(line)
            if match is None:
                raise RuntimeError(f"Release requirement is not an exact simple pin: {path.name}")
            name, version = match.groups()
            normalized = normalized_name(name)
            previous = requirements.get(normalized)
            if previous is not None and previous != version:
                raise RuntimeError(f"Conflicting release requirement: {name}")
            requirements[normalized] = version
    return requirements


def is_license_file(relative: PurePosixPath) -> bool:
    lowered_name = relative.name.casefold()
    return lowered_name.startswith(LICENSE_PREFIXES) or "license" in lowered_name


def portable_relative(value: object) -> PurePosixPath | None:
    relative = PurePosixPath(str(value))
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        return None
    return relative


def copy_distribution_licenses(
    output: Path,
    requirements: dict[str, str],
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for requirement_name, expected_version in sorted(requirements.items()):
        distribution = metadata.distribution(requirement_name)
        actual_version = distribution.version
        if actual_version != expected_version:
            raise RuntimeError(
                f"Installed {requirement_name} version does not match its release pin"
            )
        destination = output / "third-party" / f"{requirement_name}-{actual_version}"
        copied: list[str] = []
        for entry in distribution.files or ():
            relative = portable_relative(entry)
            if relative is None or not is_license_file(relative):
                continue
            source = Path(distribution.locate_file(entry))
            if not source.is_file() or source.is_symlink():
                continue
            flattened_name = "__".join(relative.parts)
            target = destination / flattened_name
            if target.exists() or target.is_symlink():
                raise RuntimeError(f"License-file destination collision for {requirement_name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            copied.append(target.relative_to(output).as_posix())
        if not copied:
            raise RuntimeError(f"No complete license text was found for {requirement_name}")
        records.append(
            {
                "name": distribution.metadata.get("Name", requirement_name),
                "version": actual_version,
                "license_files": sorted(copied),
            }
        )
    return records


def _walk_error(error: OSError) -> None:
    raise RuntimeError("A required tree could not be traversed safely") from error


def regular_tree_files(root: Path) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("A required inventory root is not a regular directory")
    paths: list[Path] = []
    for current, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=_walk_error,
    ):
        directory_names.sort()
        file_names.sort()
        current_path = Path(current)
        for directory_name in directory_names:
            directory = current_path / directory_name
            mode = directory.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise RuntimeError("A required inventory tree contains an unsafe directory entry")
        for file_name in file_names:
            path = current_path / file_name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise RuntimeError("A required inventory tree contains a non-regular file")
            paths.append(path)
    return paths


def license_file_records(output: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in regular_tree_files(output):
        if path.name == "LICENSES.json" and path.parent == output:
            continue
        records.append(
            {
                "path": path.relative_to(output).as_posix(),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
        )
    return sorted(records, key=lambda record: str(record["path"]))


def _require_string(record: dict[str, object], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"Native-license provenance has an invalid {key}")
    return value


def validate_native_provenance(
    root: Path,
    *,
    output_prefix: str,
) -> list[dict[str, object]]:
    provenance_path = root / "PROVENANCE.json"
    if not provenance_path.is_file() or provenance_path.is_symlink():
        raise RuntimeError("Native-license provenance is unavailable")
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("Native-license provenance is unreadable") from error
    if (
        not isinstance(provenance, dict)
        or set(provenance) != {"schema", "profiles"}
        or provenance.get("schema") != PROVENANCE_SCHEMA
        or not isinstance(provenance.get("profiles"), list)
        or not provenance.get("profiles")
    ):
        raise RuntimeError("Native-license provenance schema is unsupported")

    profiles: list[dict[str, object]] = []
    expected_paths = {"PROVENANCE.json"}
    seen_profile_ids: set[str] = set()
    seen_runtime_tuples: set[tuple[str, ...]] = set()
    for raw_profile in provenance["profiles"]:
        if not isinstance(raw_profile, dict) or set(raw_profile) != PROVENANCE_PROFILE_KEYS:
            raise RuntimeError("Native-license provenance profile shape is unsupported")
        profile_id = _require_string(raw_profile, "id")
        python_version = _require_string(raw_profile, "python_version")
        profile_source = _require_string(raw_profile, "source")
        raw_python_license = raw_profile.get("python_license")
        release_eligible = raw_profile.get("release_eligible")
        raw_components = raw_profile.get("components")
        if profile_id in seen_profile_ids:
            raise RuntimeError("Native-license provenance repeats a profile ID")
        seen_profile_ids.add(profile_id)
        if not isinstance(release_eligible, bool):
            raise RuntimeError("Native-license profile eligibility is invalid")
        if (
            not isinstance(raw_python_license, dict)
            or set(raw_python_license) != PROVENANCE_PYTHON_LICENSE_KEYS
        ):
            raise RuntimeError("CPython-license provenance shape is unsupported")
        python_license_extraction = _require_string(
            raw_python_license,
            "upstream_license_extraction",
        )
        if python_license_extraction != "byte-exact-whole-file":
            raise RuntimeError("CPython-license provenance has an unsupported extraction method")
        python_archive_hash = _require_string(
            raw_python_license,
            "upstream_archive_sha256",
        )
        if SHA256_PATTERN.fullmatch(python_archive_hash) is None:
            raise RuntimeError("CPython-license provenance has an invalid archive hash")
        python_archive_url = _require_string(raw_python_license, "upstream_archive_url")
        if not python_archive_url.startswith("https://"):
            raise RuntimeError("CPython-license provenance requires an HTTPS archive URL")
        python_upstream_license_path = portable_relative(
            _require_string(raw_python_license, "upstream_license_path")
        )
        if python_upstream_license_path is None:
            raise RuntimeError("CPython-license provenance has an unsafe upstream license path")
        raw_python_license_files = raw_python_license.get("license_files")
        if not isinstance(raw_python_license_files, list) or not raw_python_license_files:
            raise RuntimeError("CPython-license provenance lacks exact license files")

        mapped_python_license_files: list[dict[str, str]] = []
        seen_python_license_paths: set[str] = set()
        for raw_license in raw_python_license_files:
            if not isinstance(raw_license, dict) or set(raw_license) != {"path", "sha256"}:
                raise RuntimeError("CPython-license provenance license shape is unsupported")
            relative = portable_relative(raw_license.get("path"))
            expected_hash = raw_license.get("sha256")
            if (
                relative is None
                or len(relative.parts) != 1
                or not isinstance(expected_hash, str)
                or SHA256_PATTERN.fullmatch(expected_hash) is None
            ):
                raise RuntimeError("CPython-license provenance has an unsafe license mapping")
            relative_text = relative.as_posix()
            if relative_text in seen_python_license_paths:
                raise RuntimeError("CPython-license provenance repeats a license file")
            seen_python_license_paths.add(relative_text)
            expected_paths.add(relative_text)
            source = root / relative_text
            if not source.is_file() or source.is_symlink():
                raise RuntimeError("The source-controlled CPython license text is missing")
            if sha256_file(source) != expected_hash:
                raise RuntimeError("The CPython license hash does not match provenance")
            mapped_python_license_files.append(
                {
                    "path": f"{output_prefix}/{relative_text}",
                    "sha256": expected_hash,
                }
            )
        python_license = {
            "license_files": sorted(
                mapped_python_license_files,
                key=lambda item: item["path"],
            ),
            "upstream_archive_sha256": python_archive_hash,
            "upstream_archive_url": python_archive_url,
            "upstream_license_extraction": python_license_extraction,
            "upstream_license_path": python_upstream_license_path.as_posix(),
            "upstream_release": _require_string(raw_python_license, "upstream_release"),
            "upstream_source": _require_string(raw_python_license, "upstream_source"),
        }
        if not isinstance(raw_components, list) or len(raw_components) != 3:
            raise RuntimeError("Native-license profile must contain exactly three components")

        components: list[dict[str, object]] = []
        seen_components: set[str] = set()
        for raw_component in raw_components:
            if (
                not isinstance(raw_component, dict)
                or set(raw_component) != PROVENANCE_COMPONENT_KEYS
            ):
                raise RuntimeError("Native-license provenance component shape is unsupported")
            component = _require_string(raw_component, "component")
            runtime_version = _require_string(raw_component, "runtime_version")
            if component in seen_components or component not in REQUIRED_NATIVE_COMPONENTS:
                raise RuntimeError("Native-license profile has duplicate or unexpected components")
            seen_components.add(component)
            display_name = _require_string(raw_component, "display_name")
            license_extraction = _require_string(
                raw_component,
                "upstream_license_extraction",
            )
            if license_extraction != REQUIRED_LICENSE_EXTRACTIONS[component]:
                raise RuntimeError("Native-license provenance has an unsupported extraction method")
            archive_hash = _require_string(raw_component, "upstream_archive_sha256")
            if SHA256_PATTERN.fullmatch(archive_hash) is None:
                raise RuntimeError("Native-license provenance has an invalid archive hash")
            upstream_archive_url = _require_string(raw_component, "upstream_archive_url")
            if not upstream_archive_url.startswith("https://"):
                raise RuntimeError("Native-license provenance requires an HTTPS archive URL")
            upstream_license_path = portable_relative(
                _require_string(raw_component, "upstream_license_path")
            )
            if upstream_license_path is None:
                raise RuntimeError("Native-license provenance has an unsafe upstream license path")
            license_files = raw_component.get("license_files")
            if not isinstance(license_files, list) or not license_files:
                raise RuntimeError("Native-license provenance lacks exact license files")

            mapped_license_files: list[dict[str, str]] = []
            seen_license_paths: set[str] = set()
            for raw_license in license_files:
                if not isinstance(raw_license, dict) or set(raw_license) != {"path", "sha256"}:
                    raise RuntimeError("Native-license provenance license shape is unsupported")
                relative = portable_relative(raw_license.get("path"))
                expected_hash = raw_license.get("sha256")
                if (
                    relative is None
                    or len(relative.parts) != 1
                    or not isinstance(expected_hash, str)
                    or SHA256_PATTERN.fullmatch(expected_hash) is None
                ):
                    raise RuntimeError("Native-license provenance has an unsafe license mapping")
                relative_text = relative.as_posix()
                if relative_text in seen_license_paths:
                    raise RuntimeError("Native-license provenance repeats a license file")
                seen_license_paths.add(relative_text)
                expected_paths.add(relative_text)
                source = root / relative_text
                if not source.is_file() or source.is_symlink():
                    raise RuntimeError("A native-component license text is missing")
                if sha256_file(source) != expected_hash:
                    raise RuntimeError("A native-component license hash does not match provenance")
                mapped_license_files.append(
                    {
                        "path": f"{output_prefix}/{relative_text}",
                        "sha256": expected_hash,
                    }
                )
            components.append(
                {
                    "component": component,
                    "display_name": display_name,
                    "runtime_version": runtime_version,
                    "license_files": sorted(
                        mapped_license_files,
                        key=lambda item: item["path"],
                    ),
                    "upstream_archive_sha256": archive_hash,
                    "upstream_archive_url": upstream_archive_url,
                    "upstream_license_extraction": license_extraction,
                    "upstream_license_path": upstream_license_path.as_posix(),
                    "upstream_release": _require_string(raw_component, "upstream_release"),
                    "upstream_source": _require_string(raw_component, "upstream_source"),
                }
            )
        if seen_components != REQUIRED_NATIVE_COMPONENTS:
            raise RuntimeError("Native-license profile is not component-complete")
        components.sort(key=lambda record: str(record["component"]))
        runtime_tuple = (
            python_version,
            *(str(record["runtime_version"]) for record in components),
        )
        if runtime_tuple in seen_runtime_tuples:
            raise RuntimeError("Native-license profiles repeat an exact runtime tuple")
        seen_runtime_tuples.add(runtime_tuple)
        profiles.append(
            {
                "id": profile_id,
                "python_version": python_version,
                "python_license": python_license,
                "release_eligible": release_eligible,
                "source": profile_source,
                "components": components,
            }
        )

    actual_paths = {path.relative_to(root).as_posix() for path in regular_tree_files(root)}
    if actual_paths != expected_paths:
        raise RuntimeError("Native-license provenance has missing or unreferenced material")
    return sorted(profiles, key=lambda record: str(record["id"]))


def _native_profile_document(profile: dict[str, object]) -> dict[str, object]:
    python_license = dict(profile["python_license"])
    python_license["license_files"] = [
        {
            "path": PurePosixPath(str(record["path"])).name,
            "sha256": record["sha256"],
        }
        for record in profile["python_license"]["license_files"]
    ]
    raw_components: list[dict[str, object]] = []
    for component in profile["components"]:
        assert isinstance(component, dict)
        raw_component = dict(component)
        raw_component["license_files"] = [
            {
                "path": PurePosixPath(str(record["path"])).name,
                "sha256": record["sha256"],
            }
            for record in component["license_files"]
        ]
        raw_components.append(raw_component)
    return {
        "schema": PROVENANCE_SCHEMA,
        "profiles": [
            {
                "id": profile["id"],
                "python_version": profile["python_version"],
                "python_license": python_license,
                "release_eligible": profile["release_eligible"],
                "source": profile["source"],
                "components": raw_components,
            }
        ],
    }


def native_profile_summary(profile: dict[str, object]) -> dict[str, object]:
    return {
        "id": profile["id"],
        "python_version": profile["python_version"],
        "python_license": profile["python_license"],
        "release_eligible": profile["release_eligible"],
        "source": profile["source"],
    }


def copy_native_license_material(
    source_root: Path,
    output: Path,
    app: Path,
    *,
    required_profile: str | None,
) -> dict[str, object]:
    source_profiles = validate_native_provenance(source_root, output_prefix="native-components")
    selected_profile = select_native_profile(
        app,
        source_profiles,
        required_profile=required_profile,
    )
    destination = output / "native-components"
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "PROVENANCE.json").write_text(
        json.dumps(_native_profile_document(selected_profile), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    copied_names: set[str] = set()
    license_sources = [selected_profile["python_license"], *selected_profile["components"]]
    for record in license_sources:
        assert isinstance(record, dict)
        for license_record in record["license_files"]:
            assert isinstance(license_record, dict)
            destination_name = PurePosixPath(str(license_record["path"])).name
            if destination_name in copied_names:
                continue
            copied_names.add(destination_name)
            target = destination / destination_name
            if target.exists() or target.is_symlink():
                raise RuntimeError("Native-license destination collision")
            shutil.copyfile(source_root / destination_name, target)
    copied_profiles = validate_native_provenance(
        destination,
        output_prefix="native-components",
    )
    copied_profile = select_native_profile(
        app,
        copied_profiles,
        required_profile=required_profile,
    )
    if copied_profile != selected_profile:
        raise RuntimeError("Copied native-license provenance changed unexpectedly")
    return copied_profile


def reconcile_bundled_licenses(
    bundled_licenses: list[Path],
    files: list[dict[str, object]],
) -> list[dict[str, object]]:
    reconciled: list[dict[str, object]] = []
    seen_names: set[str] = set()
    for bundled_license in bundled_licenses:
        if not bundled_license.is_file() or bundled_license.is_symlink():
            raise RuntimeError("A bundled license resource is not a regular file")
        resource_name = bundled_license.name
        if resource_name in seen_names:
            raise RuntimeError("A bundled license resource name was repeated")
        seen_names.add(resource_name)
        resource_hash = sha256_file(bundled_license)
        matching_inventory_paths = sorted(
            str(record["path"])
            for record in files
            if str(record["path"]).startswith("third-party/") and record["sha256"] == resource_hash
        )
        if not matching_inventory_paths:
            raise RuntimeError(
                "A shipped third-party resource license is absent from the license inventory"
            )
        reconciled.append(
            {
                "resource_name": resource_name,
                "sha256": resource_hash,
                "inventory_paths": matching_inventory_paths,
            }
        )
    return reconciled


def app_project_version(app: Path) -> str:
    info_plist = app / "Contents" / "Info.plist"
    if not info_plist.is_file() or info_plist.is_symlink():
        raise RuntimeError("The app bundle has no regular Info.plist")
    try:
        info = plistlib.loads(info_plist.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise RuntimeError("The app bundle version metadata is unreadable") from error
    version = info.get("CFBundleShortVersionString") if isinstance(info, dict) else None
    if not isinstance(version, str) or not version:
        raise RuntimeError("The app bundle has no usable project version")
    return version


def _reviewed_version_from_binary(
    data: bytes,
    component: str,
    reviewed_versions: set[str],
) -> str:
    matches: list[str] = []
    for version in sorted(reviewed_versions):
        encoded = version.encode("ascii")
        if component == "openssl":
            marker = b"OpenSSL " + encoded + b" "
        elif component == "mpdecimal":
            marker = b"\0" + encoded + b"\0"
        elif component == "sqlite":
            marker = encoded + b"\0"
        else:
            raise RuntimeError("Unsupported static native-version probe")
        if marker in data:
            matches.append(version)
    if len(matches) != 1:
        raise RuntimeError(f"Bundled {component} library does not match one exact reviewed version")
    return matches[0]


def bundled_native_versions(
    app: Path,
    reviewed_versions: dict[str, set[str]],
) -> dict[str, str]:
    internal = (
        app
        / "Contents"
        / "Helpers"
        / "TVTimeHelper.bundle"
        / "Contents"
        / "Resources"
        / "_internal"
    )
    if not internal.is_dir() or internal.is_symlink():
        raise RuntimeError("Frozen helper native-library root is unavailable")
    paths = bundled_native_component_paths(internal)
    extensions = bundled_native_extension_paths(internal)

    canonical_data: dict[Path, bytes] = {}
    architectures: set[str] = set()
    for component_paths in [*paths.values(), list(extensions.values())]:
        for path in component_paths:
            if path in canonical_data:
                continue
            snapshot = canonical_macho_snapshot(path)
            if snapshot is None:
                raise RuntimeError("A required frozen native library is not a signed Mach-O")
            architecture, data = snapshot
            architectures.add(architecture)
            canonical_data[path] = data
    if len(architectures) != 1:
        raise RuntimeError("Frozen native libraries do not share one architecture")

    crypto_path = next(path for path in paths["openssl"] if path.name.startswith("libcrypto."))
    versions = {
        "openssl": _reviewed_version_from_binary(
            canonical_data[crypto_path], "openssl", reviewed_versions["openssl"]
        ),
        "mpdecimal": _reviewed_version_from_binary(
            canonical_data[paths["mpdecimal"][0]],
            "mpdecimal",
            reviewed_versions["mpdecimal"],
        ),
        "sqlite": _reviewed_version_from_binary(
            canonical_data[paths["sqlite"][0]], "sqlite", reviewed_versions["sqlite"]
        ),
    }
    openssl_major = versions["openssl"].split(".", 1)[0].encode("ascii")
    ssl_path = next(path for path in paths["openssl"] if path.name.startswith("libssl."))
    expected_crypto_dependency = b"@rpath/libcrypto." + openssl_major + b".dylib"
    if expected_crypto_dependency not in macho_dylib_load_paths(canonical_data[ssl_path]):
        raise RuntimeError("Bundled libssl is not bound to the reviewed libcrypto major version")
    dylib_name_patterns = {
        "mpdecimal": MPDECIMAL_DYLIB_NAME_PATTERN,
        "sqlite": SQLITE_DYLIB_NAME_PATTERN,
    }
    for component in ("mpdecimal", "sqlite"):
        selected = paths[component][0]
        extension_data = canonical_data[extensions[component]]
        dependencies = macho_dylib_load_paths(extension_data)
        if selected.parent == internal:
            expected_dependency = b"@rpath/" + selected.name.encode("ascii")
            if expected_dependency not in dependencies:
                raise RuntimeError(
                    f"Bundled {component} extension is not bound to its selected library"
                )
        elif any(
            dylib_name_patterns[component].fullmatch(dependency.rsplit(b"/", 1)[-1]) is not None
            for dependency in dependencies
        ):
            raise RuntimeError(
                f"Bundled {component} extension has an unexpected dynamic-library binding"
            )
    return versions


def bundled_native_extension_paths(internal: Path) -> dict[str, Path]:
    patterns = {
        "mpdecimal": STATIC_MPDECIMAL_PATTERN,
        "sqlite": STATIC_SQLITE_PATTERN,
    }
    extensions: dict[str, Path] = {}
    for component, pattern in patterns.items():
        candidates = sorted(
            (
                path
                for path in internal.glob("python*/lib-dynload/*.so")
                if pattern.fullmatch(path.name) and path.is_file() and not path.is_symlink()
            ),
            key=lambda path: path.as_posix(),
        )
        if len(candidates) != 1:
            raise RuntimeError("Frozen helper native-library set is incomplete or ambiguous")
        extensions[component] = candidates[0]
    return extensions


def bundled_native_component_paths(internal: Path) -> dict[str, list[Path]]:
    paths: dict[str, list[Path]] = {
        "openssl": [],
        "mpdecimal": [],
        "sqlite": [],
    }
    for path in sorted(internal.iterdir(), key=lambda item: item.name):
        if path.is_symlink() or not path.is_file():
            continue
        if OPENSSL_LIBRARY_PATTERN.fullmatch(path.name):
            paths["openssl"].append(path)
        elif MPDECIMAL_LIBRARY_PATTERN.fullmatch(path.name):
            paths["mpdecimal"].append(path)
        elif SQLITE_LIBRARY_PATTERN.fullmatch(path.name):
            paths["sqlite"].append(path)
    openssl_names = {path.name.split(".", 1)[0] for path in paths["openssl"]}
    if openssl_names != {"libcrypto", "libssl"} or len(paths["openssl"]) != 2:
        raise RuntimeError("Frozen helper must contain exactly one libcrypto and one libssl")
    extensions: dict[str, Path] | None = None
    for component in ("mpdecimal", "sqlite"):
        if len(paths[component]) == 1:
            continue
        if paths[component]:
            raise RuntimeError("Frozen helper native-library set is incomplete or ambiguous")
        if extensions is None:
            extensions = bundled_native_extension_paths(internal)
        paths[component] = [extensions[component]]
    return paths


def static_native_component_artifact_paths(app: Path) -> dict[str, set[str]]:
    internal = (
        app
        / "Contents"
        / "Helpers"
        / "TVTimeHelper.bundle"
        / "Contents"
        / "Resources"
        / "_internal"
    )
    selected = bundled_native_component_paths(internal)
    artifacts = {component: set() for component in REQUIRED_NATIVE_COMPONENTS}
    for component in ("mpdecimal", "sqlite"):
        path = selected[component][0]
        if path.parent != internal:
            artifacts[component].add(path.relative_to(internal).as_posix())
    return artifacts


def select_native_profile(
    app: Path,
    reviewed_profiles: list[dict[str, object]],
    *,
    required_profile: str | None,
) -> dict[str, object]:
    reviewed_versions: dict[str, set[str]] = {
        component: set() for component in REQUIRED_NATIVE_COMPONENTS
    }
    for profile in reviewed_profiles:
        for record in profile["components"]:
            component = str(record["component"])
            reviewed_versions[component].add(str(record["runtime_version"]))
    actual_versions = bundled_native_versions(app, reviewed_versions)
    python_version = ".".join(str(value) for value in sys.version_info[:3])
    matching_profiles: list[dict[str, object]] = []
    for profile in reviewed_profiles:
        profile_versions = {
            str(record["component"]): str(record["runtime_version"])
            for record in profile["components"]
        }
        if profile["python_version"] == python_version and profile_versions == actual_versions:
            matching_profiles.append(profile)
    if len(matching_profiles) != 1:
        raise RuntimeError("Bundled native libraries do not select one complete reviewed profile")
    selected = matching_profiles[0]
    if required_profile is not None and (
        selected["id"] != required_profile or selected["release_eligible"] is not True
    ):
        raise RuntimeError("Bundled native libraries do not match the required release profile")
    return selected


def distribution_native_paths(distribution_name: str) -> set[str]:
    distribution = metadata.distribution(distribution_name)
    paths: set[str] = set()
    for entry in distribution.files or ():
        relative = portable_relative(entry)
        if relative is None:
            continue
        if relative.name.endswith((".so", ".dylib")):
            paths.add(relative.as_posix())
    return paths


def cpython_native_paths() -> set[str]:
    dynamic_root_value = sysconfig.get_config_var("DESTSHARED")
    if not isinstance(dynamic_root_value, str) or not dynamic_root_value:
        raise RuntimeError("CPython dynamic-extension inventory is unavailable")
    dynamic_root = Path(dynamic_root_value)
    if not dynamic_root.is_dir() or dynamic_root.is_symlink():
        raise RuntimeError("CPython dynamic-extension root is unavailable")
    python_major_minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    paths: set[str] = set()
    for path in dynamic_root.iterdir():
        if path.is_file() and not path.is_symlink() and path.name.endswith(".so"):
            paths.add(f"python{python_major_minor}/lib-dynload/{path.name}")
    if not paths:
        raise RuntimeError("CPython dynamic-extension inventory is empty")
    paths.add(f"Python.framework/Versions/{python_major_minor}/Python")
    return paths


def assert_disjoint_artifact_owners(
    catalog: dict[str, dict[str, object]],
    component_ids: set[str],
) -> None:
    artifact_owners: dict[str, str] = {}
    for component_id in sorted(component_ids):
        raw_artifact_paths = catalog[component_id].get("artifact_paths")
        if not isinstance(raw_artifact_paths, set):
            raise RuntimeError("Native artifact ownership inventory is malformed")
        for artifact_path in sorted(raw_artifact_paths):
            previous_owner = artifact_owners.get(artifact_path)
            if previous_owner is not None:
                raise RuntimeError(
                    "Native artifact path has overlapping component owners: "
                    f"{previous_owner} and {component_id}"
                )
            artifact_owners[artifact_path] = component_id


def file_record_map(files: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    mapped: dict[str, dict[str, object]] = {}
    for record in files:
        if not isinstance(record, dict):
            raise RuntimeError("License file inventory has an invalid record")
        path = record.get("path")
        file_hash = record.get("sha256")
        size = record.get("size")
        if (
            not isinstance(path, str)
            or portable_relative(path) is None
            or not isinstance(file_hash, str)
            or SHA256_PATTERN.fullmatch(file_hash) is None
            or not isinstance(size, int)
            or size < 0
            or path in mapped
        ):
            raise RuntimeError("License file inventory has an invalid record")
        mapped[path] = record
    return mapped


def license_references(
    paths: list[str],
    files: dict[str, dict[str, object]],
) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    if not paths:
        raise RuntimeError("A mapped component has no complete license text")
    for path in sorted(paths):
        record = files.get(path)
        if record is None:
            raise RuntimeError("A mapped component license is absent from the file inventory")
        references.append({"path": path, "sha256": str(record["sha256"])})
    return references


def validate_distribution_records(
    raw_records: object,
    files: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    if not isinstance(raw_records, list) or not raw_records:
        raise RuntimeError("License manifest has no distribution records")
    records: dict[str, dict[str, object]] = {}
    referenced_third_party_paths: set[str] = set()
    all_third_party_paths = {path for path in files if path.startswith("third-party/")}
    for raw_record in raw_records:
        if not isinstance(raw_record, dict) or set(raw_record) != {
            "name",
            "version",
            "license_files",
        }:
            raise RuntimeError("A distribution license record has an invalid shape")
        name = raw_record.get("name")
        version = raw_record.get("version")
        raw_license_files = raw_record.get("license_files")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or not isinstance(raw_license_files, list)
            or not raw_license_files
            or not all(isinstance(path, str) for path in raw_license_files)
        ):
            raise RuntimeError("A distribution license record is incomplete")
        normalized = normalized_name(name)
        if normalized in records:
            raise RuntimeError("A distribution license record is duplicated")
        installed = metadata.distribution(normalized)
        if installed.version != version:
            raise RuntimeError("A distribution version does not match the build environment")
        license_paths = sorted(raw_license_files)
        if len(set(license_paths)) != len(license_paths):
            raise RuntimeError("A distribution license record repeats a file")
        expected_prefix = f"third-party/{normalized}-{version}/"
        exact_owned_paths = sorted(
            path for path in all_third_party_paths if path.startswith(expected_prefix)
        )
        if license_paths != exact_owned_paths:
            raise RuntimeError(
                "A distribution license record does not own its exact collected file set"
            )
        if referenced_third_party_paths.intersection(license_paths):
            raise RuntimeError("A third-party license file is attributed more than once")
        referenced_third_party_paths.update(license_paths)
        license_references(license_paths, files)
        records[normalized] = {
            "id": normalized,
            "name": name,
            "version": version,
            "license_files": license_references(license_paths, files),
        }
    if referenced_third_party_paths != all_third_party_paths:
        raise RuntimeError("Third-party license files are missing an exact distribution owner")
    return records


def component_catalog(
    *,
    app: Path,
    python_version: str,
    python_license: dict[str, object],
    distribution_records: object,
    native_components: list[dict[str, object]],
    files: list[dict[str, object]],
) -> dict[str, dict[str, object]]:
    expected_python_version = ".".join(str(value) for value in sys.version_info[:3])
    if python_version != expected_python_version:
        raise RuntimeError("CPython version does not match the license manifest")
    mapped_files = file_record_map(files)
    distributions = validate_distribution_records(distribution_records, mapped_files)
    required_distributions = {
        "charset-normalizer",
        "pillow",
        "pycryptodome",
        "pyinstaller",
        "reportlab",
    }
    if not required_distributions.issubset(distributions):
        raise RuntimeError("The native-binary map lacks a required distribution component")
    for distribution_name in required_distributions:
        distributions[distribution_name]["artifact_paths"] = distribution_native_paths(
            distribution_name
        )

    catalog = dict(distributions)
    catalog["tvtime-backup-extractor"] = {
        "id": "tvtime-backup-extractor",
        "name": "TV Time Backup Extractor",
        "version": app_project_version(app),
        "license_files": license_references(["PROJECT-LICENSE.txt"], mapped_files),
    }
    raw_python_license_files = python_license.get("license_files")
    if not isinstance(raw_python_license_files, list) or not raw_python_license_files:
        raise RuntimeError("CPython lacks exact license references")
    python_license_paths: list[str] = []
    for raw_license in raw_python_license_files:
        if not isinstance(raw_license, dict) or set(raw_license) != {"path", "sha256"}:
            raise RuntimeError("CPython license reference is malformed")
        path = raw_license.get("path")
        expected_hash = raw_license.get("sha256")
        if not isinstance(path, str) or not isinstance(expected_hash, str):
            raise RuntimeError("CPython license reference is malformed")
        actual = mapped_files.get(path)
        if actual is None or actual["sha256"] != expected_hash:
            raise RuntimeError("CPython license text does not match provenance")
        python_license_paths.append(path)
    static_native_paths = static_native_component_artifact_paths(app)
    catalog["cpython"] = {
        "id": "cpython",
        "name": "CPython",
        "version": python_version,
        "license_files": license_references(python_license_paths, mapped_files),
        "artifact_paths": cpython_native_paths(),
    }

    for native_component in native_components:
        component = str(native_component["component"])
        runtime_version = str(native_component["runtime_version"])
        raw_license_files = native_component.get("license_files")
        if not isinstance(raw_license_files, list):
            raise RuntimeError("Native component lacks license references")
        paths: list[str] = []
        for raw_license in raw_license_files:
            if not isinstance(raw_license, dict) or set(raw_license) != {"path", "sha256"}:
                raise RuntimeError("Native component license reference is malformed")
            path = raw_license.get("path")
            expected_hash = raw_license.get("sha256")
            if not isinstance(path, str) or not isinstance(expected_hash, str):
                raise RuntimeError("Native component license reference is malformed")
            actual = mapped_files.get(path)
            if actual is None or actual["sha256"] != expected_hash:
                raise RuntimeError("Native component license text does not match provenance")
            paths.append(path)
        catalog[component] = {
            "id": component,
            "name": str(native_component["display_name"]),
            "version": runtime_version,
            "license_files": license_references(paths, mapped_files),
            "artifact_paths": set(),
            "embedded_artifact_paths": static_native_paths[component],
        }
    assert_disjoint_artifact_owners(
        catalog,
        required_distributions | {"cpython"} | REQUIRED_NATIVE_COMPONENTS,
    )
    return catalog


def app_regular_files(app: Path) -> Iterator[Path]:
    if not app.is_dir() or app.is_symlink():
        raise RuntimeError("Native-binary inventory root is not a regular app directory")
    resolved_root = app.resolve(strict=True)
    for current, directory_names, file_names in os.walk(
        app,
        topdown=True,
        followlinks=False,
        onerror=_walk_error,
    ):
        directory_names.sort()
        file_names.sort()
        current_path = Path(current)
        retained_directories: list[str] = []
        for directory_name in directory_names:
            directory = current_path / directory_name
            mode = directory.lstat().st_mode
            if stat.S_ISLNK(mode):
                try:
                    directory.resolve(strict=True).relative_to(resolved_root)
                except (OSError, ValueError) as error:
                    raise RuntimeError(
                        "App bundle contains an escaping directory symlink"
                    ) from error
                continue
            if not stat.S_ISDIR(mode):
                raise RuntimeError("App bundle contains an unsafe directory entry")
            retained_directories.append(directory_name)
        directory_names[:] = retained_directories

        for file_name in file_names:
            path = current_path / file_name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                try:
                    path.resolve(strict=True).relative_to(resolved_root)
                except (OSError, ValueError) as error:
                    raise RuntimeError("App bundle contains an escaping file symlink") from error
                continue
            if not stat.S_ISREG(mode):
                raise RuntimeError("App bundle contains a non-regular file")
            yield path


def parse_macho(
    data: bytes,
    *,
    require_terminal_signature: bool,
) -> str | None:
    if len(data) < 4:
        return None
    magic = data[:4]
    if magic in UNSUPPORTED_MACHO_MAGICS:
        raise RuntimeError("Native-binary inventory requires thin 64-bit per-architecture Mach-O")
    endian = MACHO_64_MAGICS.get(magic)
    if endian is None:
        return None
    if len(data) < 32:
        raise RuntimeError("Mach-O header is truncated")

    try:
        (
            _magic,
            cpu_type,
            _cpu_subtype,
            _file_type,
            command_count,
            command_size,
            _flags,
            _reserved,
        ) = struct.unpack_from(f"{endian}8I", data, 0)
    except struct.error as error:
        raise RuntimeError("Mach-O header is malformed") from error
    architecture = CPU_ARCHITECTURES.get(cpu_type)
    if architecture is None:
        raise RuntimeError("Mach-O has an unsupported CPU architecture")
    commands_end = 32 + command_size
    if command_count == 0 or commands_end > len(data):
        raise RuntimeError("Mach-O load-command table is malformed")

    offset = 32
    signature_command_offset: int | None = None
    signature_offset: int | None = None
    signature_size: int | None = None
    for _ in range(command_count):
        if offset + 8 > commands_end:
            raise RuntimeError("Mach-O load command is out of bounds")
        command, size = struct.unpack_from(f"{endian}2I", data, offset)
        if size < 8 or size % 8 != 0 or offset + size > commands_end:
            raise RuntimeError("Mach-O load commands overlap or are malformed")
        if command == LC_CODE_SIGNATURE:
            if signature_command_offset is not None:
                raise RuntimeError("Mach-O repeats LC_CODE_SIGNATURE")
            if size != 16:
                raise RuntimeError("Mach-O LC_CODE_SIGNATURE has an invalid command size")
            signature_command_offset = offset
            signature_offset, signature_size = struct.unpack_from(f"{endian}2I", data, offset + 8)
        offset += size
    if offset != commands_end:
        raise RuntimeError("Mach-O load-command size does not match its header")
    if require_terminal_signature:
        if (
            signature_command_offset is None
            or signature_offset is None
            or signature_size is None
            or signature_size == 0
            or signature_offset < commands_end
            or signature_offset + signature_size != len(data)
        ):
            raise RuntimeError(
                "Mach-O must have exactly one valid terminal LC_CODE_SIGNATURE before inventory"
            )
    elif signature_command_offset is not None:
        raise RuntimeError("Canonical Mach-O copy still contains LC_CODE_SIGNATURE")
    return architecture


def macho_dylib_load_paths(data: bytes) -> set[bytes]:
    """Return exact dylib names from load commands in a canonical thin Mach-O."""

    parse_macho(data, require_terminal_signature=False)
    endian = MACHO_64_MAGICS.get(data[:4])
    if endian is None:
        raise RuntimeError("Canonical Mach-O dependency table is malformed")
    try:
        command_count, command_size = struct.unpack_from(f"{endian}2I", data, 16)
    except struct.error as error:
        raise RuntimeError("Canonical Mach-O dependency table is malformed") from error
    commands_end = 32 + command_size
    dependencies: set[bytes] = set()
    offset = 32
    for _ in range(command_count):
        try:
            command, size = struct.unpack_from(f"{endian}2I", data, offset)
        except struct.error as error:
            raise RuntimeError("Canonical Mach-O dependency command is malformed") from error
        if size < 8 or size % 8 != 0 or offset + size > commands_end:
            raise RuntimeError("Canonical Mach-O dependency commands are malformed")
        if command in DYLIB_LOAD_COMMANDS:
            if size < 24:
                raise RuntimeError("Canonical Mach-O dylib command is truncated")
            name_offset = struct.unpack_from(f"{endian}I", data, offset + 8)[0]
            if name_offset < 24 or name_offset >= size:
                raise RuntimeError("Canonical Mach-O dylib name offset is invalid")
            name_start = offset + name_offset
            name_end = data.find(b"\0", name_start, offset + size)
            if name_end == -1 or name_end == name_start:
                raise RuntimeError("Canonical Mach-O dylib name is malformed")
            dependencies.add(data[name_start:name_end])
        offset += size
    if offset != commands_end:
        raise RuntimeError("Canonical Mach-O dependency table size is invalid")
    return dependencies


def _stat_identity(source_stat: os.stat_result) -> tuple[object, ...]:
    return (
        source_stat.st_dev,
        source_stat.st_ino,
        source_stat.st_mode,
        source_stat.st_size,
        source_stat.st_mtime_ns,
        source_stat.st_ctime_ns,
    )


def normalize_signature_dependent_linkedit_extent(data: bytes) -> bytes:
    """Normalize the signed-size-dependent ``__LINKEDIT`` virtual extent.

    ``codesign --remove-signature`` restores the terminal file size and removes
    ``LC_CODE_SIGNATURE``, but it deliberately leaves the signed image's
    page-rounded ``__LINKEDIT`` ``vmsize`` behind. A larger replacement signature
    can therefore change one load-command field even when every code byte is
    identical. Bind the canonical hash to the exact unsigned ``filesize`` instead.
    """

    endian = MACHO_64_MAGICS.get(data[:4])
    if endian is None or len(data) < 32:
        raise RuntimeError("Canonical Mach-O data is malformed")
    try:
        command_count, command_size = struct.unpack_from(f"{endian}2I", data, 16)
    except struct.error as error:
        raise RuntimeError("Canonical Mach-O header is malformed") from error
    commands_end = 32 + command_size
    if command_count == 0 or commands_end > len(data):
        raise RuntimeError("Canonical Mach-O load-command table is malformed")

    normalized = bytearray(data)
    linkedit_offset: int | None = None
    offset = 32
    for _ in range(command_count):
        try:
            command, size = struct.unpack_from(f"{endian}2I", data, offset)
        except struct.error as error:
            raise RuntimeError("Canonical Mach-O load command is malformed") from error
        if size < 8 or size % 8 != 0 or offset + size > commands_end:
            raise RuntimeError("Canonical Mach-O load commands overlap or are malformed")
        if command == 0x19:  # LC_SEGMENT_64
            if size < 72:
                raise RuntimeError("Canonical Mach-O segment command is truncated")
            segment_name = data[offset + 8 : offset + 24].split(b"\0", 1)[0]
            if segment_name == b"__LINKEDIT":
                if linkedit_offset is not None:
                    raise RuntimeError("Canonical Mach-O repeats the __LINKEDIT segment")
                linkedit_offset = offset
        offset += size
    if offset != commands_end or linkedit_offset is None:
        raise RuntimeError("Canonical Mach-O lacks one valid __LINKEDIT segment")

    try:
        virtual_size = struct.unpack_from(f"{endian}Q", data, linkedit_offset + 32)[0]
        file_offset = struct.unpack_from(f"{endian}Q", data, linkedit_offset + 40)[0]
        file_size = struct.unpack_from(f"{endian}Q", data, linkedit_offset + 48)[0]
    except struct.error as error:
        raise RuntimeError("Canonical Mach-O __LINKEDIT segment is malformed") from error
    if (
        file_size == 0
        or virtual_size < file_size
        or file_offset < commands_end
        or file_offset + file_size != len(data)
    ):
        raise RuntimeError("Canonical Mach-O __LINKEDIT extent is invalid")
    struct.pack_into(f"{endian}Q", normalized, linkedit_offset + 32, file_size)
    return bytes(normalized)


def canonical_macho_snapshot(path: Path) -> tuple[str, bytes] | None:
    initial_stat = path.lstat()
    if stat.S_ISLNK(initial_stat.st_mode) or not stat.S_ISREG(initial_stat.st_mode):
        raise RuntimeError("Native-binary hashing source is not a regular file")
    source_data = path.read_bytes()
    after_read_stat = path.lstat()
    if _stat_identity(after_read_stat) != _stat_identity(initial_stat):
        raise RuntimeError("Native-binary source changed while it was read")
    architecture = parse_macho(source_data, require_terminal_signature=True)
    if architecture is None:
        return None
    source_identity = (_stat_identity(initial_stat), hashlib.sha256(source_data).hexdigest())
    if not Path("/usr/bin/codesign").is_file():
        raise RuntimeError("Native-binary hashing requires /usr/bin/codesign")

    with tempfile.TemporaryDirectory(prefix="tvtime-macho-license-") as temporary:
        canonical_path = Path(temporary) / "signed-code"
        canonical_path.write_bytes(source_data)
        completed = subprocess.run(
            ["/usr/bin/codesign", "--remove-signature", str(canonical_path)],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": temporary},
        )
        if completed.returncode != 0:
            raise RuntimeError("Could not remove a Mach-O signature in the private hash copy")
        canonical_data = canonical_path.read_bytes()
        canonical_architecture = parse_macho(
            canonical_data,
            require_terminal_signature=False,
        )
        if canonical_architecture != architecture:
            raise RuntimeError("Signature removal changed the Mach-O architecture")
        canonical_data = normalize_signature_dependent_linkedit_extent(canonical_data)

    unchanged_data = path.read_bytes()
    unchanged_identity = (
        _stat_identity(path.lstat()),
        hashlib.sha256(unchanged_data).hexdigest(),
    )
    if unchanged_identity != source_identity:
        raise RuntimeError("Native-binary hashing changed its source Mach-O")
    return architecture, canonical_data


def macho_code_identity(path: Path) -> tuple[str, str] | None:
    snapshot = canonical_macho_snapshot(path)
    if snapshot is None:
        return None
    architecture, canonical_data = snapshot
    return architecture, hashlib.sha256(canonical_data).hexdigest()


def classify_native_binary(
    relative_path: str,
    catalog: dict[str, dict[str, object]],
) -> str:
    main_executable = "Contents/MacOS/TVTimeRecoveryApp"
    helper_root = "Contents/Helpers/TVTimeHelper.bundle/Contents"
    helper_executable = f"{helper_root}/MacOS/tvtime-helper"
    internal_prefix = f"{helper_root}/Resources/_internal/"
    if relative_path == main_executable:
        return "tvtime-backup-extractor"
    if relative_path == helper_executable:
        return "pyinstaller"
    if not relative_path.startswith(internal_prefix):
        raise RuntimeError(f"Unmapped Mach-O path in app bundle: {relative_path}")

    internal_path = relative_path[len(internal_prefix) :]
    name = PurePosixPath(internal_path).name
    for component_id in (
        "pycryptodome",
        "pillow",
        "charset-normalizer",
        "reportlab",
        "openssl",
        "mpdecimal",
        "sqlite",
        "cpython",
    ):
        raw_paths = catalog.get(component_id, {}).get("artifact_paths")
        if isinstance(raw_paths, set) and internal_path in raw_paths:
            return component_id
    if OPENSSL_LIBRARY_PATTERN.fullmatch(name) and "/" not in internal_path:
        return "openssl"
    if MPDECIMAL_LIBRARY_PATTERN.fullmatch(name) and "/" not in internal_path:
        return "mpdecimal"
    if SQLITE_LIBRARY_PATTERN.fullmatch(name) and "/" not in internal_path:
        return "sqlite"
    raise RuntimeError(f"Unmapped Mach-O path in frozen helper: {internal_path}")


def native_binary_inventory(
    app: Path,
    catalog: dict[str, dict[str, object]],
) -> tuple[str, list[dict[str, object]]]:
    records: list[dict[str, object]] = []
    architectures: set[str] = set()
    for path in app_regular_files(app):
        identity = macho_code_identity(path)
        if identity is None:
            continue
        architecture, digest = identity
        architectures.add(architecture)
        relative_path = path.relative_to(app).as_posix()
        component_id = classify_native_binary(relative_path, catalog)
        component = catalog.get(component_id)
        if component is None:
            raise RuntimeError(f"Mach-O component has no license mapping: {component_id}")
        component_ids = [component_id]
        helper_internal_prefix = (
            "Contents/Helpers/TVTimeHelper.bundle/Contents/Resources/_internal/"
        )
        if relative_path.startswith(helper_internal_prefix):
            internal_path = relative_path[len(helper_internal_prefix) :]
            for embedded_id in sorted(REQUIRED_NATIVE_COMPONENTS):
                raw_embedded_paths = catalog.get(embedded_id, {}).get("embedded_artifact_paths")
                if isinstance(raw_embedded_paths, set) and internal_path in raw_embedded_paths:
                    component_ids.append(embedded_id)
        components: list[dict[str, object]] = []
        for mapped_id in component_ids:
            mapped_component = catalog.get(mapped_id)
            if mapped_component is None:
                raise RuntimeError("Composite Mach-O component has no license mapping")
            components.append(
                {
                    key: value
                    for key, value in mapped_component.items()
                    if key not in {"artifact_paths", "embedded_artifact_paths"}
                }
            )
        records.append(
            {
                "path": relative_path,
                "architecture": architecture,
                "sha256": digest,
                "sha256_scope": MACHO_HASH_SCOPE,
                "components": components,
            }
        )
    if not records:
        raise RuntimeError("App bundle contains no inventoried Mach-O files")
    if len(architectures) != 1:
        raise RuntimeError("A per-architecture app contains mixed Mach-O architectures")
    used_components = {
        str(component["id"])
        for record in records
        for component in record["components"]
        if isinstance(component, dict)
    }
    if not REQUIRED_NATIVE_COMPONENTS.issubset(used_components):
        raise RuntimeError("A required native-license component is not used by any Mach-O")
    native_counts = {
        component: sum(
            1
            for record in records
            if any(
                isinstance(mapped_component, dict) and mapped_component.get("id") == component
                for mapped_component in record["components"]
            )
        )
        for component in REQUIRED_NATIVE_COMPONENTS
    }
    if native_counts != REQUIRED_NATIVE_BINARY_COUNTS:
        raise RuntimeError("Required native-library Mach-O counts are incomplete or unexpected")
    return next(iter(architectures)), sorted(records, key=lambda record: str(record["path"]))


def ensure_license_output_belongs_to_app(output: Path, app: Path) -> None:
    expected = app / "Contents" / "Resources" / "Licenses"
    try:
        output_parent = output.parent.resolve(strict=True)
        expected_parent = expected.parent.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("License output or app resource parent is unavailable") from error
    if output_parent != expected_parent or output.name != expected.name:
        raise RuntimeError("License inventory is not attached to the app being verified")


def verify_license_manifest(
    output: Path,
    bundled_licenses: list[Path],
    app: Path,
    *,
    required_profile: str | None = None,
) -> None:
    ensure_license_output_belongs_to_app(output, app)
    if not output.is_dir() or output.is_symlink():
        raise RuntimeError("License verification root is not a regular directory")
    manifest_path = output / "LICENSES.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise RuntimeError("License manifest is unavailable")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("License manifest is unreadable") from error
    if not isinstance(manifest, dict) or manifest.get("schema") != LICENSE_SCHEMA:
        raise RuntimeError("License manifest schema is unsupported")
    expected_keys = {
        "schema",
        "project_version",
        "python_version",
        "distributions",
        "bundled_license_reconciliation",
        "native_components",
        "native_profile",
        "native_architecture",
        "native_binary_hash_scheme",
        "native_binaries",
        "files",
    }
    if set(manifest) != expected_keys:
        raise RuntimeError("License manifest has unexpected or missing top-level fields")

    actual_files = license_file_records(output)
    if manifest.get("files") != actual_files:
        raise RuntimeError("License inventory file hashes or sizes do not match the manifest")
    reconciliation = manifest.get("bundled_license_reconciliation")
    if not isinstance(reconciliation, list):
        raise RuntimeError("License manifest lacks bundled-resource reconciliation")
    actual_reconciliation = reconcile_bundled_licenses(bundled_licenses, actual_files)
    if reconciliation != actual_reconciliation:
        raise RuntimeError("Bundled-resource license reconciliation does not match the manifest")

    reviewed_native_profiles = validate_native_provenance(
        output / "native-components",
        output_prefix="native-components",
    )
    native_profile = manifest.get("native_profile")
    if not isinstance(native_profile, dict):
        raise RuntimeError("License manifest has no selected native profile")
    selected_profile = select_native_profile(
        app,
        reviewed_native_profiles,
        required_profile=required_profile,
    )
    if native_profile_summary(selected_profile) != native_profile:
        raise RuntimeError("Selected native profile does not match the manifest")
    native_components = selected_profile["components"]
    if manifest.get("native_components") != native_components:
        raise RuntimeError("Native-component provenance does not match the manifest")
    project_version = app_project_version(app)
    if manifest.get("project_version") != project_version:
        raise RuntimeError("Project version does not match the assembled app")
    python_version = manifest.get("python_version")
    if not isinstance(python_version, str):
        raise RuntimeError("License manifest has no valid CPython version")
    catalog = component_catalog(
        app=app,
        python_version=python_version,
        python_license=selected_profile["python_license"],
        distribution_records=manifest.get("distributions"),
        native_components=native_components,
        files=actual_files,
    )
    architecture, native_binaries = native_binary_inventory(app, catalog)
    if manifest.get("native_binary_hash_scheme") != MACHO_HASH_SCOPE:
        raise RuntimeError("Native-binary hash scheme is unsupported")
    if manifest.get("native_architecture") != architecture:
        raise RuntimeError("Native-binary architecture does not match the manifest")
    if manifest.get("native_binaries") != native_binaries:
        raise RuntimeError("Native-binary path, hash, component, or license mapping changed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-output", type=Path)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--requirements", type=Path, action="append", default=[])
    parser.add_argument("--project-license", type=Path)
    parser.add_argument("--third-party-notice", type=Path)
    parser.add_argument("--native-license-root", type=Path)
    parser.add_argument("--required-native-profile")
    parser.add_argument("--bundled-license", type=Path, action="append", default=[])
    arguments = parser.parse_args()

    if (arguments.output is None) == (arguments.verify_output is None):
        parser.error("choose exactly one of --output or --verify-output")
    if not arguments.bundled_license:
        parser.error("at least one --bundled-license is required")
    if arguments.verify_output is not None:
        if (
            arguments.requirements
            or arguments.project_license
            or arguments.third_party_notice
            or arguments.native_license_root
        ):
            parser.error(
                "verification mode accepts only --verify-output, --app, "
                "--required-native-profile, and --bundled-license"
            )
        verify_license_manifest(
            arguments.verify_output,
            arguments.bundled_license,
            arguments.app,
            required_profile=arguments.required_native_profile,
        )
        print("License inventory and complete native-binary mapping passed.")
        return 0
    if not arguments.requirements or arguments.project_license is None:
        parser.error("generation mode requires --requirements and --project-license")
    if arguments.third_party_notice is None:
        parser.error("generation mode requires --third-party-notice")
    if arguments.native_license_root is None:
        parser.error("generation mode requires --native-license-root")

    output = arguments.output
    assert output is not None
    ensure_license_output_belongs_to_app(output, arguments.app)
    if output.exists() or output.is_symlink():
        raise RuntimeError("License output must be a fresh path")
    if not arguments.project_license.is_file() or arguments.project_license.is_symlink():
        raise RuntimeError("Project license is unavailable")
    if not arguments.third_party_notice.is_file() or arguments.third_party_notice.is_symlink():
        raise RuntimeError("Third-party notice is unavailable")

    requirements = pinned_requirements(arguments.requirements)
    pip_distribution = metadata.distribution("pip")
    requirements.setdefault("pip", pip_distribution.version)
    output.mkdir(parents=True, mode=0o755)

    project_target = output / "PROJECT-LICENSE.txt"
    notice_target = output / "THIRD-PARTY-NOTICES.md"
    shutil.copyfile(arguments.project_license, project_target)
    shutil.copyfile(arguments.third_party_notice, notice_target)
    distributions = copy_distribution_licenses(output, requirements)
    selected_native_profile = copy_native_license_material(
        arguments.native_license_root,
        output,
        arguments.app,
        required_profile=arguments.required_native_profile,
    )
    native_components = selected_native_profile["components"]

    files = license_file_records(output)
    bundled_license_reconciliation = reconcile_bundled_licenses(
        arguments.bundled_license,
        files,
    )
    python_version = ".".join(str(value) for value in sys.version_info[:3])
    catalog = component_catalog(
        app=arguments.app,
        python_version=python_version,
        python_license=selected_native_profile["python_license"],
        distribution_records=distributions,
        native_components=native_components,
        files=files,
    )
    native_architecture, native_binaries = native_binary_inventory(
        arguments.app,
        catalog,
    )
    manifest = {
        "schema": LICENSE_SCHEMA,
        "project_version": app_project_version(arguments.app),
        "python_version": python_version,
        "distributions": distributions,
        "bundled_license_reconciliation": bundled_license_reconciliation,
        "native_components": native_components,
        "native_profile": native_profile_summary(selected_native_profile),
        "native_architecture": native_architecture,
        "native_binary_hash_scheme": MACHO_HASH_SCOPE,
        "native_binaries": native_binaries,
        "files": files,
    }
    (output / "LICENSES.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    verify_license_manifest(
        output,
        arguments.bundled_license,
        arguments.app,
        required_profile=arguments.required_native_profile,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
