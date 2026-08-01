from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
THUMBPRINT_PATTERN = re.compile(r"^[0-9A-F]{40}$")
MAXIMUM_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024
MAXIMUM_PACKAGE_BYTES = 1024 * 1024 * 1024
MAXIMUM_TEXT_BYTES = 8 * 1024 * 1024
MAXIMUM_CERTIFICATE_BYTES = 64 * 1024
MAXIMUM_MANIFEST_BYTES = 1024 * 1024
MAXIMUM_MEMBERS = 32
MAXIMUM_MSIX_MEMBERS = 4096
MAXIMUM_MSIX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
ARTIFACT_LIMITS = {
    "package": MAXIMUM_PACKAGE_BYTES,
    "certificate": MAXIMUM_CERTIFICATE_BYTES,
    "installer": MAXIMUM_TEXT_BYTES,
    "uninstaller": MAXIMUM_TEXT_BYTES,
    "trust_helper": MAXIMUM_TEXT_BYTES,
    "readme": MAXIMUM_TEXT_BYTES,
    "license": MAXIMUM_TEXT_BYTES,
    "third_party_notices": MAXIMUM_TEXT_BYTES,
}
DEPENDENCY_LOCK_PATHS = (
    "global.json",
    "requirements-windows-build.lock",
    "windows/TVTimeRecovery.Windows/packages.lock.json",
)
EXPECTED_KNOWN_LIMITS = [
    "final-msix-binary-to-component-inventory",
    "self-signed-certificate-requires-explicit-local-trust",
    "physical-device-and-ui-coverage-remains-tester-dependent",
    "windows-build-is-prerelease-only",
]
FORBIDDEN_MSIX_NAME_TOKENS = (
    "anthropic",
    "directml",
    "machinelearning",
    "onnx",
    "openai",
    "tensorflow",
    "torch",
    "webview2",
    "windows.ai",
    "windowsappsdk.ai",
    "windowsappsdk.ml",
)


def is_notice_member(name: PurePosixPath) -> bool:
    return (
        len(name.parts) >= 2
        and name.parts[0].casefold() == "notices"
        and (
            name.suffix.casefold() == ".txt"
            or name.as_posix().casefold() == "notices/manifest.json"
        )
    )


def safe_member(info: zipfile.ZipInfo) -> str:
    if info.is_dir():
        raise RuntimeError("The Windows release bundle contained a directory entry.")
    relative = PurePosixPath(info.filename.replace("\\", "/"))
    if (
        relative.is_absolute()
        or len(relative.parts) != 1
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise RuntimeError("The Windows release bundle contained an unsafe path.")
    mode = (info.external_attr >> 16) & 0o170000
    if mode and mode != stat.S_IFREG:
        raise RuntimeError("The Windows release bundle contained a linked or special member.")
    if info.file_size <= 0 or info.file_size > MAXIMUM_PACKAGE_BYTES:
        raise RuntimeError("A Windows release member had an unsafe byte size.")
    return relative.name


def read_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    limit: int,
    label: str,
) -> bytes:
    if info.file_size > limit:
        raise RuntimeError(f"The {label} exceeded its byte limit.")
    with archive.open(info, "r") as handle:
        payload = handle.read(limit + 1)
    if len(payload) != info.file_size or len(payload) > limit:
        raise RuntimeError(f"The {label} changed while it was read.")
    return payload


def hash_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    byte_count = 0
    with archive.open(info, "r") as handle:
        while chunk := handle.read(1024 * 1024):
            byte_count += len(chunk)
            if byte_count > info.file_size:
                raise RuntimeError("A Windows release member exceeded its recorded size.")
            digest.update(chunk)
    if byte_count != info.file_size:
        raise RuntimeError("A Windows release member changed while it was read.")
    return digest.hexdigest()


def load_json_bytes(payload: bytes, label: str) -> dict[str, object]:
    try:
        decoded = payload.decode("utf-8")
        value = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"The {label} was not valid bounded JSON.") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"The {label} had an unsupported shape.")
    return value


def dependency_lock_records(source_root: Path) -> list[dict[str, str]]:
    resolved_root = source_root.resolve(strict=True)
    if not resolved_root.is_dir() or resolved_root.is_symlink():
        raise RuntimeError("The Windows release source root was unsafe.")
    records: list[dict[str, str]] = []
    for relative in DEPENDENCY_LOCK_PATHS:
        path = (resolved_root / relative).resolve(strict=True)
        metadata = path.lstat()
        if (
            resolved_root not in path.parents
            or not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_size <= 0
            or metadata.st_size > MAXIMUM_TEXT_BYTES
        ):
            raise RuntimeError("A Windows release dependency lock was unsafe.")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        records.append({"path": relative, "sha256": digest.hexdigest()})
    return records


def verify_msix(handle: BinaryIO, release_version: str) -> None:
    required = {
        "appxmanifest.xml",
        "appxblockmap.xml",
        "appxsignature.p7x",
    }
    observed: set[str] = set()
    appx_manifest: bytes | None = None
    expanded_bytes = 0
    try:
        with zipfile.ZipFile(handle) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAXIMUM_MSIX_MEMBERS:
                raise RuntimeError("The Windows MSIX had unsafe membership.")
            for info in infos:
                if info.is_dir():
                    continue
                name = PurePosixPath(info.filename.replace("\\", "/"))
                if name.is_absolute() or any(part in {"", ".", ".."} for part in name.parts):
                    raise RuntimeError("The Windows MSIX contained an unsafe path.")
                mode = (info.external_attr >> 16) & 0o170000
                if mode and mode != stat.S_IFREG:
                    raise RuntimeError("The Windows MSIX contained a linked or special member.")
                if info.file_size < 0:
                    raise RuntimeError("The Windows MSIX contained an invalid member size.")
                expanded_bytes += info.file_size
                if expanded_bytes > MAXIMUM_MSIX_EXPANDED_BYTES:
                    raise RuntimeError("The Windows MSIX exceeded its expanded byte limit.")
                normalized = name.as_posix().casefold()
                if normalized in observed:
                    raise RuntimeError("The Windows MSIX contained an ambiguous path.")
                observed.add(normalized)
                if not is_notice_member(name) and any(
                    token in normalized for token in FORBIDDEN_MSIX_NAME_TOKENS
                ):
                    raise RuntimeError("The Windows MSIX contained an AI or WebView payload.")
                if normalized == "appxmanifest.xml":
                    with archive.open(info, "r") as handle:
                        appx_manifest = handle.read(1024 * 1024 + 1)
    except (OSError, zipfile.BadZipFile) as exc:
        raise RuntimeError("The Windows MSIX could not be inspected.") from exc
    if not required.issubset(observed):
        raise RuntimeError("The signed Windows MSIX was incomplete.")
    if appx_manifest is None or len(appx_manifest) > 1024 * 1024:
        raise RuntimeError("The Windows MSIX manifest was unavailable.")
    try:
        root = ET.fromstring(appx_manifest)
    except ET.ParseError as exc:
        raise RuntimeError("The Windows MSIX manifest was malformed.") from exc
    identities = [node for node in root if node.tag.rsplit("}", 1)[-1] == "Identity"]
    if len(identities) != 1:
        raise RuntimeError("The Windows MSIX identity was ambiguous.")
    identity = identities[0]
    expected_numeric = release_version.removesuffix("-alpha.1") + ".1"
    expected_identity = {
        "Name": "AmirBrooks.TVTimeBackupExtractor.Alpha",
        "Publisher": "CN=TV Time Backup Extractor Alpha",
        "Version": expected_numeric,
    }
    allowed_identities = (
        expected_identity,
        {**expected_identity, "ProcessorArchitecture": "x64"},
    )
    if identity.attrib not in allowed_identities:
        raise RuntimeError("The Windows MSIX identity did not match the alpha release.")
    capabilities = [
        node.attrib.get("Name")
        for node in root.iter()
        if node.tag.rsplit("}", 1)[-1] == "Capability"
    ]
    if capabilities != ["runFullTrust"]:
        raise RuntimeError("The Windows MSIX declared an unexpected capability.")


def extract_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    destination: Path,
    limit: int,
    label: str,
) -> None:
    if info.file_size <= 0 or info.file_size > limit:
        raise RuntimeError(f"The {label} exceeded its byte limit.")
    byte_count = 0
    with archive.open(info, "r") as source, destination.open("xb") as output:
        while chunk := source.read(1024 * 1024):
            byte_count += len(chunk)
            if byte_count > info.file_size or byte_count > limit:
                raise RuntimeError(f"The {label} exceeded its recorded size.")
            output.write(chunk)
    if byte_count != info.file_size:
        raise RuntimeError(f"The {label} changed while it was extracted.")


def windows_powershell() -> Path:
    windows_root = os.environ.get("WINDIR")
    if not windows_root:
        raise RuntimeError("Windows PowerShell was unavailable for signature verification.")
    executable = (
        Path(windows_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    ).resolve(strict=True)
    metadata = executable.lstat()
    if not stat.S_ISREG(metadata.st_mode) or executable.is_symlink():
        raise RuntimeError("Windows PowerShell had an unsafe file shape.")
    return executable


def verify_windows_signature(package: Path, certificate: Path, thumbprint: str) -> None:
    if sys.platform != "win32":
        raise RuntimeError("Cryptographic Windows signature verification requires Windows.")
    verifier = Path(__file__).with_name("verify_windows_signature.ps1").resolve(strict=True)
    metadata = verifier.lstat()
    if not stat.S_ISREG(metadata.st_mode) or verifier.is_symlink():
        raise RuntimeError("The Windows signature verifier had an unsafe file shape.")
    completed = subprocess.run(
        [
            str(windows_powershell()),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(verifier),
            "-Package",
            str(package),
            "-Certificate",
            str(certificate),
            "-ExpectedThumbprint",
            thumbprint,
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "The Windows MSIX signature was not cryptographically valid "
            "for its bundled certificate."
        )


def verify(arguments: argparse.Namespace) -> None:
    if GIT_OBJECT_PATTERN.fullmatch(arguments.source_commit) is None:
        raise RuntimeError("The expected Windows release commit was invalid.")
    if GIT_OBJECT_PATTERN.fullmatch(arguments.source_tree) is None:
        raise RuntimeError("The expected Windows release tree was invalid.")
    bundle = arguments.bundle.resolve(strict=True)
    metadata = bundle.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or bundle.is_symlink()
        or metadata.st_size <= 0
        or metadata.st_size > MAXIMUM_BUNDLE_BYTES
    ):
        raise RuntimeError("The Windows release bundle was unsafe or unavailable.")

    records: dict[str, zipfile.ZipInfo] = {}
    with zipfile.ZipFile(bundle) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAXIMUM_MEMBERS:
            raise RuntimeError("The Windows release bundle had unsafe membership.")
        for info in infos:
            name = safe_member(info)
            key = name.casefold()
            if key in records:
                raise RuntimeError("The Windows release bundle contained ambiguous names.")
            records[key] = info

        manifest_entry = records.get("windows-release-manifest.json")
        if manifest_entry is None:
            raise RuntimeError("The Windows release manifest was missing.")
        manifest = load_json_bytes(
            read_member(
                archive,
                manifest_entry,
                MAXIMUM_MANIFEST_BYTES,
                "Windows release manifest",
            ),
            "Windows release manifest",
        )
        if set(manifest) != {
            "artifacts",
            "build_environment",
            "dependency_locks",
            "integrity",
            "known_limits",
            "release",
            "schema",
            "signing",
            "source",
        }:
            raise RuntimeError("The Windows release manifest contained unknown fields.")
        if manifest.get("schema") != "tvtime-windows-alpha-release-v1":
            raise RuntimeError("The Windows release manifest schema was unsupported.")
        release = manifest.get("release")
        source = manifest.get("source")
        signing = manifest.get("signing")
        artifacts = manifest.get("artifacts")
        build_environment = manifest.get("build_environment")
        integrity = manifest.get("integrity")
        if not all(
            isinstance(value, dict)
            for value in (
                release,
                source,
                signing,
                artifacts,
                build_environment,
                integrity,
            )
        ):
            raise RuntimeError("The Windows release manifest was incomplete.")
        if release != {
            "version": arguments.release_version,
            "channel": "experimental-alpha",
            "architecture": "x64",
            "package_identity": "AmirBrooks.TVTimeBackupExtractor.Alpha",
        }:
            raise RuntimeError("The Windows release scope was invalid.")
        if manifest.get("known_limits") != EXPECTED_KNOWN_LIMITS:
            raise RuntimeError("The Windows release limitations were not recorded exactly.")
        if source != {
            "git_commit": arguments.source_commit,
            "git_tree": arguments.source_tree,
            "stage": "verified-git-archive",
        }:
            raise RuntimeError("The Windows release did not match the reviewed source stage.")
        if set(signing) != {"kind", "certificate_thumbprint", "private_key_included"}:
            raise RuntimeError("The Windows release signing record was malformed.")
        if signing.get("kind") != "ephemeral-self-signed-alpha":
            raise RuntimeError("The Windows release signing mode was invalid.")
        if signing.get("private_key_included") is not False:
            raise RuntimeError("The Windows alpha bundle could expose a private signing key.")
        thumbprint = signing.get("certificate_thumbprint")
        if not isinstance(thumbprint, str) or THUMBPRINT_PATTERN.fullmatch(thumbprint) is None:
            raise RuntimeError("The Windows alpha certificate binding was invalid.")
        if build_environment != {"python": "3.13.12", "dotnet_sdk": "8.0.423"}:
            raise RuntimeError("The Windows release build environment was not reviewed.")
        source_root = getattr(arguments, "source_root", Path(__file__).parents[1])
        if manifest.get("dependency_locks") != dependency_lock_records(source_root):
            raise RuntimeError("The Windows release dependency locks did not match the source.")
        if set(integrity) != {"unsigned_package_sha256", "signed_block_map_sha256"} or any(
            not isinstance(integrity.get(name), str)
            or SHA256_PATTERN.fullmatch(integrity[name]) is None
            for name in ("unsigned_package_sha256", "signed_block_map_sha256")
        ):
            raise RuntimeError("The Windows package integrity binding was invalid.")
        if set(artifacts) != set(ARTIFACT_LIMITS):
            raise RuntimeError("The Windows release artifact set was incomplete.")

        expected_names = {"windows-release-manifest.json"}
        package_entry: zipfile.ZipInfo | None = None
        certificate_entry: zipfile.ZipInfo | None = None
        for label, record in artifacts.items():
            if not isinstance(record, dict) or set(record) != {"name", "sha256", "size"}:
                raise RuntimeError("A Windows release artifact record was malformed.")
            name = record.get("name")
            expected_hash = record.get("sha256")
            expected_size = record.get("size")
            limit = ARTIFACT_LIMITS[label]
            if (
                not isinstance(name, str)
                or PurePosixPath(name).name != name
                or not isinstance(expected_hash, str)
                or SHA256_PATTERN.fullmatch(expected_hash) is None
                or not isinstance(expected_size, int)
                or isinstance(expected_size, bool)
                or expected_size <= 0
                or expected_size > limit
            ):
                raise RuntimeError("A Windows release artifact binding was invalid.")
            entry = records.get(name.casefold())
            if entry is None or entry.file_size != expected_size:
                raise RuntimeError("A bound Windows release artifact was missing or changed.")
            if hash_member(archive, entry) != expected_hash:
                raise RuntimeError("A Windows release artifact did not match its manifest.")
            expected_names.add(name.casefold())
            if label == "package":
                package_entry = entry
            elif label == "certificate":
                certificate_entry = entry
            if name.casefold().endswith((".pfx", ".p12", ".pem", ".key")):
                raise RuntimeError("The Windows alpha bundle contained private key material.")
        if set(records) != expected_names:
            raise RuntimeError("The Windows release bundle contained unexpected files.")
        if package_entry is None:
            raise RuntimeError("The Windows release bundle did not bind its MSIX.")
        with archive.open(package_entry, "r") as package_handle:
            verify_msix(package_handle, arguments.release_version)
        if not getattr(arguments, "structural_only", False):
            if certificate_entry is None:
                raise RuntimeError("The Windows release bundle did not bind its certificate.")
            with tempfile.TemporaryDirectory(prefix="tvtime-windows-signature-") as temporary:
                temporary_root = Path(temporary)
                package = temporary_root / "candidate.msix"
                certificate = temporary_root / "candidate.cer"
                extract_member(
                    archive,
                    package_entry,
                    package,
                    MAXIMUM_PACKAGE_BYTES,
                    "Windows MSIX",
                )
                extract_member(
                    archive,
                    certificate_entry,
                    certificate,
                    MAXIMUM_CERTIFICATE_BYTES,
                    "Windows certificate",
                )
                verify_windows_signature(package, certificate, thumbprint)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--bundle", type=Path, required=True)
    result.add_argument("--release-version", required=True)
    result.add_argument("--source-commit", required=True)
    result.add_argument("--source-tree", required=True)
    return result


if __name__ == "__main__":
    verify(parser().parse_args())
