from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from script import build_visual_report_fixture, collect_macos_licenses, scan_macos_release
from script.build_python_distributions import (
    capture_source_identity,
    reject_python_environment_overrides,
    write_release_manifest,
)
from script.git_source_stage import (
    make_source_removable,
    prepare_source_stage,
    verify_source_stage,
)
from script.sdist_metadata import normalize_sdist_metadata, verify_sdist_metadata
from script.verify_python_release import verify_release_set

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENT_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)(?:\s*;\s*.+)?\s*\\$")
HASH_PATTERN = re.compile(r"^\s+--hash=sha256:([0-9a-f]{64})(?:\s*\\)?$")


def normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.casefold())


def canonical_macho_fixture(
    *,
    dependencies: tuple[bytes, ...] = (),
    payload: bytes = b"",
) -> bytes:
    commands: list[bytes] = []
    for dependency in dependencies:
        raw_size = 24 + len(dependency) + 1
        command_size = (raw_size + 7) & ~7
        command = struct.pack("<6I", 0xC, command_size, 24, 0, 0, 0)
        command += dependency + b"\0"
        command += b"\0" * (command_size - len(command))
        commands.append(command)
    if not commands:
        commands.append(struct.pack("<2I", 0x1B, 24) + b"\0" * 16)
    command_data = b"".join(commands)
    header = struct.pack(
        "<8I",
        0xFEEDFACF,
        0x0100000C,
        0,
        6,
        len(commands),
        len(command_data),
        0,
        0,
    )
    return header + command_data + payload


def simple_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s;]+)", line)
        if match is None:
            raise AssertionError(f"not an exact source pin: {path.name}")
        name, version = match.groups()
        pins[normalized_name(name)] = version
    return pins


def hashed_lock_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    current_name: str | None = None
    current_hashes = 0
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        requirement = REQUIREMENT_PATTERN.fullmatch(raw_line)
        if requirement is not None:
            if current_name is not None and current_hashes == 0:
                raise AssertionError(f"missing hashes for {current_name} in {path.name}")
            name, version = requirement.groups()
            current_name = normalized_name(name)
            current_hashes = 0
            if current_name in pins:
                raise AssertionError(f"duplicate lock requirement: {current_name}")
            pins[current_name] = version
            continue
        artifact_hash = HASH_PATTERN.fullmatch(raw_line)
        if artifact_hash is None or current_name is None:
            raise AssertionError(f"unsupported lock line in {path.name}: {raw_line}")
        current_hashes += 1
    if current_name is None or current_hashes == 0:
        raise AssertionError(f"empty or incomplete requirement lock: {path.name}")
    return pins


def synthetic_signed_macho(
    *,
    signature_commands: int = 1,
    command_size: int = 16,
    signature_offset: int | None = None,
    trailing: bytes = b"",
) -> bytes:
    signature = b"synthetic-signature"
    code = b"synthetic-code"
    commands_size = signature_commands * command_size
    default_signature_offset = 32 + commands_size + len(code)
    data_offset = default_signature_offset if signature_offset is None else signature_offset
    commands = b"".join(
        struct.pack(
            "<4I",
            collect_macos_licenses.LC_CODE_SIGNATURE,
            command_size,
            data_offset,
            len(signature),
        )
        + b"\0" * (command_size - 16)
        for _ in range(signature_commands)
    )
    header = struct.pack(
        "<8I",
        0xFEEDFACF,
        0x0100000C,
        0,
        2,
        signature_commands,
        len(commands),
        0,
        0,
    )
    return header + commands + code + signature + trailing


class NativeLicenseCompletenessTests(unittest.TestCase):
    def test_checked_in_profiles_are_exact_complete_and_unique(self) -> None:
        profiles = collect_macos_licenses.validate_native_provenance(
            ROOT / "macos" / "Bundle" / "NativeLicenses",
            output_prefix="native-components",
        )

        expected_python_license = {
            "license_files": [
                {
                    "path": "native-components/CPython-3.13.12-LICENSE.txt",
                    "sha256": ("78b12c3a81360b357002334f0e70ea0e92eebf7a9b358805c03c48484945f3bb"),
                }
            ],
            "upstream_archive_sha256": (
                "12e7cb170ad2d1a69aee96a1cc7fc8de5b1e97a2bdac51683a3db016ec9a2996"
            ),
            "upstream_archive_url": (
                "https://www.python.org/ftp/python/3.13.12/Python-3.13.12.tgz"
            ),
            "upstream_license_extraction": "byte-exact-whole-file",
            "upstream_license_path": "LICENSE",
            "upstream_release": "Python-3.13.12",
            "upstream_source": "Python.org CPython 3.13.12 source release",
        }
        self.assertEqual(
            {profile["id"] for profile in profiles},
            {
                "homebrew-python-3.13.12",
                "official-cpython-3.13.12-universal2",
            },
        )
        self.assertEqual(sum(profile["release_eligible"] is True for profile in profiles), 1)
        for profile in profiles:
            self.assertEqual(profile["python_version"], "3.13.12")
            self.assertEqual(profile["python_license"], expected_python_license)
            self.assertEqual(
                collect_macos_licenses.native_profile_summary(profile)["python_license"],
                expected_python_license,
            )
            self.assertEqual(
                {component["component"] for component in profile["components"]},
                collect_macos_licenses.REQUIRED_NATIVE_COMPONENTS,
            )
            self.assertEqual(
                {
                    component["component"]: component["upstream_license_extraction"]
                    for component in profile["components"]
                },
                collect_macos_licenses.REQUIRED_LICENSE_EXTRACTIONS,
            )

    def test_cpython_license_is_byte_exact_and_tamper_evident(self) -> None:
        native_license_root = ROOT / "macos" / "Bundle" / "NativeLicenses"
        cpython_license = native_license_root / "CPython-3.13.12-LICENSE.txt"
        license_bytes = cpython_license.read_bytes()
        self.assertEqual(len(license_bytes), 13_809)
        self.assertEqual(
            hashlib.sha256(license_bytes).hexdigest(),
            "78b12c3a81360b357002334f0e70ea0e92eebf7a9b358805c03c48484945f3bb",
        )

        with tempfile.TemporaryDirectory() as temporary:
            copied_root = Path(temporary) / "NativeLicenses"
            shutil.copytree(native_license_root, copied_root)
            copied_license = copied_root / cpython_license.name
            copied_license.write_bytes(license_bytes + b"tamper")
            with self.assertRaisesRegex(RuntimeError, "CPython license hash"):
                collect_macos_licenses.validate_native_provenance(
                    copied_root,
                    output_prefix="native-components",
                )

    def test_sqlite_license_excerpts_have_reproducible_byte_contract(self) -> None:
        expected = (
            b"The author disclaims copyright to this source code.  In place of\n"
            b"a legal notice, here is a blessing:\n"
            b"\n"
            b"   May you do good and not evil.\n"
            b"   May you find forgiveness for yourself and forgive others.\n"
            b"   May you share freely, never taking more than you give.\n"
        )
        expected_hash = "06545a6ec25fbbff6c62f205f94a35be49e38f33bea827a8cfb07d7b82e4b083"
        self.assertEqual(hashlib.sha256(expected).hexdigest(), expected_hash)
        self.assertTrue(expected.endswith(b"\n"))
        self.assertFalse(expected.endswith(b"\n\n"))

        for version in ("3.50.4", "3.51.2"):
            with self.subTest(version=version):
                path = (
                    ROOT
                    / "macos"
                    / "Bundle"
                    / "NativeLicenses"
                    / f"SQLite-{version}-PUBLIC-DOMAIN.txt"
                )
                self.assertEqual(path.read_bytes(), expected)

    def test_macho_parser_requires_one_exact_terminal_signature_command(self) -> None:
        valid = synthetic_signed_macho()
        self.assertEqual(
            collect_macos_licenses.parse_macho(
                valid,
                require_terminal_signature=True,
            ),
            "arm64",
        )
        with self.assertRaisesRegex(RuntimeError, "repeats LC_CODE_SIGNATURE"):
            collect_macos_licenses.parse_macho(
                synthetic_signed_macho(signature_commands=2),
                require_terminal_signature=True,
            )
        with self.assertRaisesRegex(RuntimeError, "invalid command size"):
            collect_macos_licenses.parse_macho(
                synthetic_signed_macho(command_size=24),
                require_terminal_signature=True,
            )
        with self.assertRaisesRegex(RuntimeError, "valid terminal"):
            collect_macos_licenses.parse_macho(
                synthetic_signed_macho(trailing=b"unexpected"),
                require_terminal_signature=True,
            )
        with self.assertRaisesRegex(RuntimeError, "valid terminal"):
            collect_macos_licenses.parse_macho(
                synthetic_signed_macho(signature_offset=2**31),
                require_terminal_signature=True,
            )
        overlapping = bytearray(valid)
        struct.pack_into("<I", overlapping, 36, 32)
        with self.assertRaisesRegex(RuntimeError, "overlap"):
            collect_macos_licenses.parse_macho(
                bytes(overlapping),
                require_terminal_signature=True,
            )

    @unittest.skipUnless(sys.platform == "darwin", "codesign identity is macOS-only")
    def test_canonical_macho_hash_is_signing_stable_and_source_immutable(self) -> None:
        clang_lookup = subprocess.run(
            ["/usr/bin/xcrun", "--find", "clang"],
            check=False,
            capture_output=True,
            text=True,
        )
        if clang_lookup.returncode != 0:
            self.skipTest("clang is unavailable")
        clang = clang_lookup.stdout.strip()
        sdk_lookup = subprocess.run(
            ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
            check=False,
            capture_output=True,
            text=True,
        )
        if sdk_lookup.returncode != 0:
            self.skipTest("macOS SDK is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "synthetic.c"
            executable = root / "synthetic"
            entitlements = root / "entitlements.plist"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            signature_padding = "x" * (32 * 1024)
            entitlements.write_text(
                f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.example.tvtime.signature-padding</key><string>{signature_padding}</string>
</dict></plist>
""",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    clang,
                    "-isysroot",
                    sdk_lookup.stdout.strip(),
                    str(source),
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "/usr/bin/codesign",
                    "--force",
                    "--sign",
                    "-",
                    "--options",
                    "runtime",
                    "--timestamp=none",
                    str(executable),
                ],
                check=True,
                capture_output=True,
            )
            source_bytes = executable.read_bytes()
            source_stat = executable.stat()
            first_identity = collect_macos_licenses.macho_code_identity(executable)
            self.assertEqual(executable.read_bytes(), source_bytes)
            self.assertEqual(executable.stat().st_mtime_ns, source_stat.st_mtime_ns)

            subprocess.run(
                [
                    "/usr/bin/codesign",
                    "--force",
                    "--sign",
                    "-",
                    "--options",
                    "runtime",
                    "--timestamp=none",
                    "--entitlements",
                    str(entitlements),
                    str(executable),
                ],
                check=True,
                capture_output=True,
            )
            self.assertGreater(abs(executable.stat().st_size - len(source_bytes)), 16 * 1024)
            self.assertEqual(
                collect_macos_licenses.macho_code_identity(executable),
                first_identity,
            )

    def test_classifier_rejects_unowned_package_and_mypyc_lookalikes(self) -> None:
        prefix = "Contents/Helpers/TVTimeHelper.bundle/Contents/Resources/_internal/"
        catalog = {
            "pillow": {"artifact_paths": {"PIL/approved.dylib"}},
            "pycryptodome": {"artifact_paths": set()},
            "charset-normalizer": {"artifact_paths": {"approved__mypyc.cpython-313-darwin.so"}},
            "reportlab": {"artifact_paths": set()},
            "cpython": {"artifact_paths": set()},
        }
        self.assertEqual(
            collect_macos_licenses.classify_native_binary(f"{prefix}PIL/approved.dylib", catalog),
            "pillow",
        )
        for path in (
            "PIL/evil.dylib",
            "0123456789abcdefabcd__mypyc.cpython-313-darwin.so",
        ):
            with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, "Unmapped"):
                collect_macos_licenses.classify_native_binary(f"{prefix}{path}", catalog)

    def test_overlapping_artifact_owners_fail_closed(self) -> None:
        catalog = {
            "one": {"artifact_paths": {"shared/native.so"}},
            "two": {"artifact_paths": {"shared/native.so"}},
        }
        with self.assertRaisesRegex(RuntimeError, "overlapping component owners"):
            collect_macos_licenses.assert_disjoint_artifact_owners(
                catalog,
                {"one", "two"},
            )

    def test_native_profile_rejects_missing_or_non_macho_root_library(self) -> None:
        reviewed_versions = {
            "openssl": {"3.6.1"},
            "mpdecimal": {"4.0.1"},
            "sqlite": {"3.51.2"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / "Synthetic.app"
            internal = (
                app
                / "Contents"
                / "Helpers"
                / "TVTimeHelper.bundle"
                / "Contents"
                / "Resources"
                / "_internal"
            )
            internal.mkdir(parents=True)
            dynamic = internal / "python3.13" / "lib-dynload"
            dynamic.mkdir(parents=True)
            (internal / "libcrypto.3.dylib").write_bytes(b"OpenSSL 3.6.1 synthetic")
            (internal / "libssl.3.dylib").write_bytes(
                canonical_macho_fixture(dependencies=(b"@rpath/libcrypto.3.dylib",))
            )
            (internal / "libmpdec.4.dylib").write_bytes(b"\0" + b"4.0.1\0")
            (dynamic / "_decimal.cpython-313-darwin.so").write_bytes(
                canonical_macho_fixture(dependencies=(b"@rpath/libmpdec.4.dylib",))
            )
            with self.assertRaisesRegex(RuntimeError, "incomplete or ambiguous"):
                collect_macos_licenses.bundled_native_versions(app, reviewed_versions)

            (internal / "libsqlite3.dylib").write_bytes(b"3.51.2\0")
            (dynamic / "_sqlite3.cpython-313-darwin.so").write_bytes(
                canonical_macho_fixture(dependencies=(b"@rpath/libsqlite3.dylib",))
            )

            def snapshots(path: Path):
                if path.name == "libssl.3.dylib":
                    return None
                return "arm64", path.read_bytes()

            with (
                mock.patch.object(
                    collect_macos_licenses,
                    "canonical_macho_snapshot",
                    side_effect=snapshots,
                ),
                self.assertRaisesRegex(RuntimeError, "not a signed Mach-O"),
            ):
                collect_macos_licenses.bundled_native_versions(app, reviewed_versions)

    def test_native_profile_rejects_stale_unbound_dynamic_library(self) -> None:
        reviewed_versions = {
            "openssl": {"3.6.1"},
            "mpdecimal": {"4.0.1"},
            "sqlite": {"3.51.2"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / "Synthetic.app"
            internal = (
                app
                / "Contents"
                / "Helpers"
                / "TVTimeHelper.bundle"
                / "Contents"
                / "Resources"
                / "_internal"
            )
            dynamic = internal / "python3.13" / "lib-dynload"
            dynamic.mkdir(parents=True)
            fixtures = {
                internal / "libcrypto.3.dylib": b"OpenSSL 3.6.1 synthetic",
                internal / "libssl.3.dylib": canonical_macho_fixture(
                    dependencies=(b"@rpath/libcrypto.3.dylib",)
                ),
                internal / "libmpdec.4.dylib": b"\0" + b"4.0.1\0",
                internal / "libsqlite3.dylib": b"3.51.2\0",
                dynamic / "_decimal.cpython-313-darwin.so": canonical_macho_fixture(
                    payload=b"ordinary string @rpath/libmpdec.4.dylib\0 4.0.1\0"
                ),
                dynamic / "_sqlite3.cpython-313-darwin.so": canonical_macho_fixture(
                    dependencies=(b"@rpath/libsqlite3.dylib",)
                ),
            }
            for path, data in fixtures.items():
                path.write_bytes(data)
            with (
                mock.patch.object(
                    collect_macos_licenses,
                    "canonical_macho_snapshot",
                    side_effect=lambda path: ("arm64", path.read_bytes()),
                ),
                self.assertRaisesRegex(RuntimeError, "not bound to its selected library"),
            ):
                collect_macos_licenses.bundled_native_versions(app, reviewed_versions)

    def test_native_profile_rejects_unbound_libssl_payload_string(self) -> None:
        reviewed_versions = {
            "openssl": {"3.6.1"},
            "mpdecimal": {"4.0.1"},
            "sqlite": {"3.51.2"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / "Synthetic.app"
            internal = (
                app
                / "Contents"
                / "Helpers"
                / "TVTimeHelper.bundle"
                / "Contents"
                / "Resources"
                / "_internal"
            )
            dynamic = internal / "python3.13" / "lib-dynload"
            dynamic.mkdir(parents=True)
            fixtures = {
                internal / "libcrypto.3.dylib": b"OpenSSL 3.6.1 synthetic",
                internal / "libssl.3.dylib": canonical_macho_fixture(
                    payload=b"ordinary string @rpath/libcrypto.3.dylib\0"
                ),
                internal / "libmpdec.4.dylib": b"\0" + b"4.0.1\0",
                internal / "libsqlite3.dylib": b"3.51.2\0",
                dynamic / "_decimal.cpython-313-darwin.so": canonical_macho_fixture(
                    dependencies=(b"@rpath/libmpdec.4.dylib",)
                ),
                dynamic / "_sqlite3.cpython-313-darwin.so": canonical_macho_fixture(
                    dependencies=(b"@rpath/libsqlite3.dylib",)
                ),
            }
            for path, data in fixtures.items():
                path.write_bytes(data)
            with (
                mock.patch.object(
                    collect_macos_licenses,
                    "canonical_macho_snapshot",
                    side_effect=lambda path: ("arm64", path.read_bytes()),
                ),
                self.assertRaisesRegex(RuntimeError, "libssl is not bound"),
            ):
                collect_macos_licenses.bundled_native_versions(app, reviewed_versions)

    def test_native_profile_accepts_reviewed_static_python_components(self) -> None:
        reviewed_versions = {
            "openssl": {"3.0.18"},
            "mpdecimal": {"4.0.0"},
            "sqlite": {"3.50.4"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / "Synthetic.app"
            internal = (
                app
                / "Contents"
                / "Helpers"
                / "TVTimeHelper.bundle"
                / "Contents"
                / "Resources"
                / "_internal"
            )
            dynamic = internal / "python3.13" / "lib-dynload"
            dynamic.mkdir(parents=True)
            (internal / "libcrypto.3.dylib").write_bytes(b"OpenSSL 3.0.18 synthetic")
            (internal / "libssl.3.dylib").write_bytes(
                canonical_macho_fixture(dependencies=(b"@rpath/libcrypto.3.dylib",))
            )
            decimal = dynamic / "_decimal.cpython-313-darwin.so"
            sqlite = dynamic / "_sqlite3.cpython-313-darwin.so"
            decimal.write_bytes(canonical_macho_fixture(payload=b"synthetic\0" + b"4.0.0\0"))
            sqlite.write_bytes(canonical_macho_fixture(payload=b"synthetic 3.50.4\0"))

            with mock.patch.object(
                collect_macos_licenses,
                "canonical_macho_snapshot",
                side_effect=lambda path: ("arm64", path.read_bytes()),
            ):
                self.assertEqual(
                    collect_macos_licenses.bundled_native_versions(
                        app,
                        reviewed_versions,
                    ),
                    {
                        "openssl": "3.0.18",
                        "mpdecimal": "4.0.0",
                        "sqlite": "3.50.4",
                    },
                )

            static_paths = collect_macos_licenses.static_native_component_artifact_paths(app)
            self.assertEqual(
                static_paths,
                {
                    "openssl": set(),
                    "mpdecimal": {"python3.13/lib-dynload/_decimal.cpython-313-darwin.so"},
                    "sqlite": {"python3.13/lib-dynload/_sqlite3.cpython-313-darwin.so"},
                },
            )
            prefix = "Contents/Helpers/TVTimeHelper.bundle/Contents/Resources/_internal/"
            catalog = {
                component: {
                    "id": component,
                    "name": component,
                    "version": "1.0",
                    "license_files": [{"path": component, "sha256": "a" * 64}],
                    "artifact_paths": set(),
                    "embedded_artifact_paths": paths,
                }
                for component, paths in static_paths.items()
            }
            catalog.update(
                {
                    "pycryptodome": {"artifact_paths": set()},
                    "pillow": {"artifact_paths": set()},
                    "charset-normalizer": {"artifact_paths": set()},
                    "reportlab": {"artifact_paths": set()},
                    "cpython": {
                        "id": "cpython",
                        "name": "CPython",
                        "version": "3.13.12",
                        "license_files": [{"path": "cpython", "sha256": "b" * 64}],
                        "artifact_paths": {
                            "python3.13/lib-dynload/_decimal.cpython-313-darwin.so",
                            "python3.13/lib-dynload/_sqlite3.cpython-313-darwin.so",
                        },
                    },
                }
            )
            self.assertEqual(
                collect_macos_licenses.classify_native_binary(
                    f"{prefix}python3.13/lib-dynload/_decimal.cpython-313-darwin.so",
                    catalog,
                ),
                "cpython",
            )
            self.assertEqual(
                collect_macos_licenses.classify_native_binary(
                    f"{prefix}python3.13/lib-dynload/_sqlite3.cpython-313-darwin.so",
                    catalog,
                ),
                "cpython",
            )
            inventory_files = [
                internal / "libcrypto.3.dylib",
                internal / "libssl.3.dylib",
                decimal,
                sqlite,
            ]
            with (
                mock.patch.object(
                    collect_macos_licenses,
                    "app_regular_files",
                    return_value=iter(inventory_files),
                ),
                mock.patch.object(
                    collect_macos_licenses,
                    "macho_code_identity",
                    return_value=("arm64", "c" * 64),
                ),
            ):
                _, inventory = collect_macos_licenses.native_binary_inventory(app, catalog)
            by_name = {Path(str(record["path"])).name: record for record in inventory}
            self.assertEqual(
                [component["id"] for component in by_name[decimal.name]["components"]],
                ["cpython", "mpdecimal"],
            )
            self.assertEqual(
                [component["id"] for component in by_name[sqlite.name]["components"]],
                ["cpython", "sqlite"],
            )

    def test_distribution_cannot_claim_another_distribution_license(self) -> None:
        class Distribution:
            version = "1.0"

        files = {
            "third-party/pillow-1.0/LICENSE": {
                "path": "third-party/pillow-1.0/LICENSE",
                "sha256": "a" * 64,
                "size": 1,
            },
            "third-party/pycryptodome-1.0/LICENSE": {
                "path": "third-party/pycryptodome-1.0/LICENSE",
                "sha256": "b" * 64,
                "size": 1,
            },
        }
        records = [
            {
                "name": "pillow",
                "version": "1.0",
                "license_files": ["third-party/pycryptodome-1.0/LICENSE"],
            }
        ]
        with (
            mock.patch.object(
                collect_macos_licenses.metadata,
                "distribution",
                return_value=Distribution(),
            ),
            self.assertRaisesRegex(RuntimeError, "exact collected file set"),
        ):
            collect_macos_licenses.validate_distribution_records(records, files)

    def test_required_release_profile_rejects_non_release_profile(self) -> None:
        current_python = ".".join(str(value) for value in sys.version_info[:3])
        components = [
            {"component": component, "runtime_version": f"1.0.{index}"}
            for index, component in enumerate(
                sorted(collect_macos_licenses.REQUIRED_NATIVE_COMPONENTS)
            )
        ]
        profile = {
            "id": "synthetic-local-profile",
            "python_version": current_python,
            "release_eligible": False,
            "source": "synthetic public fixture",
            "components": components,
        }
        versions = {
            component["component"]: component["runtime_version"] for component in components
        }
        with (
            mock.patch.object(
                collect_macos_licenses,
                "bundled_native_versions",
                return_value=versions,
            ),
            self.assertRaisesRegex(RuntimeError, "required release profile"),
        ):
            collect_macos_licenses.select_native_profile(
                Path("synthetic.app"),
                [profile],
                required_profile="synthetic-local-profile",
            )

    def test_native_inventory_requires_every_explicit_native_component(self) -> None:
        app = Path("synthetic.app")
        executable = app / "Contents" / "MacOS" / "TVTimeRecoveryApp"
        catalog = {
            "tvtime-backup-extractor": {
                "id": "tvtime-backup-extractor",
                "name": "Synthetic Project",
                "version": "1.0",
                "license_files": [{"path": "LICENSE", "sha256": "a" * 64}],
            }
        }
        with (
            mock.patch.object(
                collect_macos_licenses,
                "app_regular_files",
                return_value=iter([executable]),
            ),
            mock.patch.object(
                collect_macos_licenses,
                "macho_code_identity",
                return_value=("arm64", "b" * 64),
            ),
            self.assertRaisesRegex(RuntimeError, "not used by any Mach-O"),
        ):
            collect_macos_licenses.native_binary_inventory(app, catalog)

    def test_native_inventory_requires_exact_native_library_counts(self) -> None:
        app = Path("synthetic.app")
        root = (
            app
            / "Contents"
            / "Helpers"
            / "TVTimeHelper.bundle"
            / "Contents"
            / "Resources"
            / "_internal"
        )
        files = [
            root / "libcrypto.3.dylib",
            root / "libmpdec.4.dylib",
            root / "libsqlite3.dylib",
        ]
        catalog = {
            component: {
                "id": component,
                "name": component,
                "version": "1.0",
                "license_files": [{"path": component, "sha256": "a" * 64}],
            }
            for component in collect_macos_licenses.REQUIRED_NATIVE_COMPONENTS
        }
        with (
            mock.patch.object(
                collect_macos_licenses,
                "app_regular_files",
                return_value=iter(files),
            ),
            mock.patch.object(
                collect_macos_licenses,
                "macho_code_identity",
                return_value=("arm64", "b" * 64),
            ),
            self.assertRaisesRegex(RuntimeError, "counts are incomplete"),
        ):
            collect_macos_licenses.native_binary_inventory(app, catalog)

    def test_packaging_verifies_native_inventory_after_signing_and_from_dmg(self) -> None:
        local_contents = (ROOT / "script" / "build_local_app.sh").read_text(encoding="utf-8")
        collector_contents = (ROOT / "script" / "collect_macos_licenses.py").read_text(
            encoding="utf-8"
        )
        for contents in (local_contents, collector_contents):
            self.assertNotIn("TVTIME_PYTHON_LICENSE_PATH", contents)
            self.assertNotIn("--python-license", contents)
        local_collectors = [
            match.start()
            for match in re.finditer(
                re.escape('"$ROOT_DIR/script/collect_macos_licenses.py"'),
                local_contents,
            )
        ]
        self.assertEqual(len(local_collectors), 2)
        local_signing = local_contents.index("sign_macos_app_inside_out")
        self.assertLess(local_collectors[0], local_signing)
        self.assertLess(local_signing, local_collectors[1])
        self.assertIn(
            '--verify-output "$APP_RESOURCES/Licenses"',
            local_contents[local_collectors[1] :],
        )

        release_contents = (ROOT / "script" / "build_release_app.sh").read_text(encoding="utf-8")
        self.assertNotIn("TVTIME_PYTHON_LICENSE_PATH", release_contents)
        self.assertNotIn("--python-license", release_contents)
        function_start = release_contents.index("build_release_for_architecture()")
        function_contents = release_contents[function_start:]
        release_collectors = [
            match.start()
            for match in re.finditer(
                re.escape('"$ROOT_DIR/script/collect_macos_licenses.py"'),
                function_contents,
            )
        ]
        self.assertEqual(len(release_collectors), 3)
        release_signing = function_contents.index("sign_macos_app_inside_out")
        self.assertLess(release_collectors[0], release_signing)
        self.assertLess(release_signing, release_collectors[1])
        self.assertLess(release_collectors[1], release_collectors[2])
        self.assertEqual(
            function_contents.count(
                '--required-native-profile "official-cpython-3.13.12-universal2"'
            ),
            3,
        )
        mounted_verification = function_contents[release_collectors[2] :]
        self.assertIn(
            '--verify-output "$embedded_app/Contents/Resources/Licenses"',
            mounted_verification,
        )


class MacRunScriptContractTests(unittest.TestCase):
    def test_telemetry_stream_is_narrow_and_attaches_before_launch(self) -> None:
        contents = (ROOT / "script" / "build_and_run.sh").read_text(encoding="utf-8")
        telemetry = contents[
            contents.index("--telemetry|telemetry)") : contents.index("--verify|verify)")
        ]
        predicate = 'subsystem == \\"$BUNDLE_ID\\" AND category == \\"RecoveryDiagnostics\\"'
        self.assertIn(predicate, telemetry)
        stream_index = telemetry.index("/usr/bin/log stream")
        launch_index = telemetry.index("open_app")
        self.assertLess(stream_index, launch_index)
        self.assertIn('/bin/kill -0 "$telemetry_pid"', telemetry[stream_index:launch_index])


class RequirementLockTests(unittest.TestCase):
    def test_python_and_native_packaging_ranges_are_bounded_consistently(self) -> None:
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(project, r'(?m)^requires-python = ">=3\.10,<3\.14"$')

        version_guard = "sys.version_info[:3] == (3, 13, 12)"
        for relative_path in (
            "script/build_macos_helper.sh",
            "script/build_release_app.sh",
        ):
            contents = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn(version_guard, contents)
            self.assertNotIn("(3, 10) <= sys.version_info < (3, 14)", contents)

    def test_locks_pin_and_hash_every_distribution(self) -> None:
        runtime = hashed_lock_pins(ROOT / "requirements.lock")
        development = hashed_lock_pins(ROOT / "requirements-dev.lock")
        macos_build = hashed_lock_pins(ROOT / "requirements-macos-build.lock")
        source_build = hashed_lock_pins(ROOT / "requirements-source-build.lock")

        self.assertEqual(runtime, simple_pins(ROOT / "requirements.txt"))
        for name, version in simple_pins(ROOT / "requirements-dev.txt").items():
            self.assertEqual(development.get(name), version)
        combined_sources = {
            **simple_pins(ROOT / "requirements.txt"),
            **simple_pins(ROOT / "requirements-macos-build.txt"),
        }
        for name, version in combined_sources.items():
            self.assertEqual(macos_build.get(name), version)
        self.assertEqual(source_build, simple_pins(ROOT / "requirements-source-build.txt"))

    def test_locks_contain_no_index_or_local_path_configuration(self) -> None:
        forbidden_fragments = (
            "--extra-index-url",
            "--find-links",
            "--index-url",
            "/Users/",
            "/home/",
            "/private/",
            "\\Users\\",
            "file://",
            "http://",
            "https://",
        )
        for filename in (
            "requirements.lock",
            "requirements-dev.lock",
            "requirements-macos-build.lock",
            "requirements-source-build.lock",
        ):
            with self.subTest(filename=filename):
                contents = (ROOT / filename).read_text(encoding="utf-8")
                for fragment in forbidden_fragments:
                    self.assertNotIn(fragment, contents)
                self.assertNotIn(str(ROOT), contents)
                self.assertNotIn(str(Path.home()), contents)


class SourceArchivePrivacyTests(unittest.TestCase):
    def test_normalizer_produces_reproducible_private_tar_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "package.tar.gz"
            second_archive = Path(temporary) / "second-package.tar.gz"
            payload = b"safe synthetic content\n"

            def build_synthetic_archive(
                path: Path, *, reverse: bool, owner: tuple[int, int], timestamp: int
            ) -> None:
                entries = [
                    ("package-1.0", tarfile.DIRTYPE, 0o700, b""),
                    ("package-1.0/README.md", tarfile.REGTYPE, 0o640, payload),
                    ("package-1.0/tool", tarfile.REGTYPE, 0o750, b"#!/bin/sh\n"),
                ]
                if reverse:
                    entries.reverse()
                with tarfile.open(path, "w:gz") as target:
                    for name, entry_type, mode, contents in entries:
                        member = tarfile.TarInfo(name)
                        member.type = entry_type
                        member.size = len(contents)
                        member.mode = mode
                        member.uid, member.gid = owner
                        member.uname = "local-user"
                        member.gname = "staff"
                        member.mtime = timestamp
                        member.pax_headers = {"atime": str(timestamp + 1)}
                        target.addfile(member, io.BytesIO(contents) if contents else None)

            build_synthetic_archive(
                archive,
                reverse=True,
                owner=(501, 20),
                timestamp=1_700_000_000,
            )
            build_synthetic_archive(
                second_archive,
                reverse=False,
                owner=(502, 21),
                timestamp=1_800_000_000,
            )

            with self.assertRaises(RuntimeError):
                verify_sdist_metadata(archive)
            normalize_sdist_metadata(archive)
            normalize_sdist_metadata(second_archive)
            verify_sdist_metadata(archive)
            verify_sdist_metadata(second_archive)
            self.assertEqual(archive.read_bytes(), second_archive.read_bytes())
            with tarfile.open(archive, "r:gz") as source:
                self.assertEqual(source.extractfile("package-1.0/README.md").read(), payload)
                self.assertEqual(
                    [member.name for member in source.getmembers()],
                    ["package-1.0", "package-1.0/README.md", "package-1.0/tool"],
                )
                for member in source.getmembers():
                    self.assertEqual((member.uid, member.gid), (0, 0))
                    self.assertEqual((member.uname, member.gname), ("", ""))
                    self.assertEqual(member.mtime, 0)
                    self.assertEqual(member.pax_headers, {})
                self.assertEqual(source.getmember("package-1.0").mode, 0o755)
                self.assertEqual(source.getmember("package-1.0/README.md").mode, 0o644)
                self.assertEqual(source.getmember("package-1.0/tool").mode, 0o755)


class PythonDistributionProvenanceTests(unittest.TestCase):
    def test_source_identity_requires_the_exact_clean_commit(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.skipTest("git is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()

            def run_git(*arguments: str) -> str:
                completed = subprocess.run(
                    [git, "-C", str(repository), *arguments],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return completed.stdout.strip()

            run_git("init", "--quiet")
            run_git("config", "user.name", "Synthetic Test")
            run_git("config", "user.email", "synthetic@example.invalid")
            tracked = repository / "tracked.txt"
            tracked.write_text("reviewed synthetic source\n", encoding="utf-8")
            run_git("add", "tracked.txt")
            run_git("commit", "--quiet", "-m", "synthetic source")
            commit = run_git("rev-parse", "HEAD")
            tree = run_git("rev-parse", "HEAD^{tree}")

            captured_tree, timestamp = capture_source_identity(repository, commit)
            self.assertEqual(captured_tree, tree)
            self.assertGreaterEqual(timestamp, 0)

            build_root = repository / ".dist.build-synthetic"
            build_root.mkdir()
            (build_root / "controlled-artifact.whl").write_bytes(b"synthetic")
            captured_tree, timestamp = capture_source_identity(
                repository,
                commit,
                controlled_build_root=build_root,
            )
            self.assertEqual(captured_tree, tree)
            self.assertGreaterEqual(timestamp, 0)

            (repository / "unrelated-untracked.txt").write_text(
                "must remain visible\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "completely clean"):
                capture_source_identity(
                    repository,
                    commit,
                    controlled_build_root=build_root,
                )
            (repository / "unrelated-untracked.txt").unlink()
            shutil.rmtree(build_root)

            with self.assertRaisesRegex(RuntimeError, "does not match"):
                capture_source_identity(repository, "0" * 40)

            tracked.write_text("unreviewed synthetic change\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "completely clean"):
                capture_source_identity(repository, commit)
            tracked.write_text("reviewed synthetic source\n", encoding="utf-8")
            (repository / "untracked.txt").write_text("synthetic\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "completely clean"):
                capture_source_identity(repository, commit)

    def test_release_manifest_binds_exact_artifacts_and_detects_tampering(self) -> None:
        source_commit = "a" * 40
        source_tree = "b" * 40
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary) / "release"
            release.mkdir()
            source_archive = release / "synthetic-package-1.0.tar.gz"
            wheel = release / "synthetic_package-1.0-py3-none-any.whl"

            with tarfile.open(source_archive, "w:gz") as target:
                contents = b"safe synthetic source\n"
                member = tarfile.TarInfo("synthetic-package-1.0/README.txt")
                member.size = len(contents)
                member.mode = 0o640
                target.addfile(member, io.BytesIO(contents))
            normalize_sdist_metadata(source_archive)
            with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as target:
                target.writestr("synthetic_package/__init__.py", "VALUE = 'synthetic'\n")

            write_release_manifest(
                release,
                source_commit=source_commit,
                source_tree=source_tree,
            )
            verify_release_set(
                release,
                source_commit=source_commit,
                source_tree=source_tree,
                forbidden_values=[],
            )

            unexpected = release / "unexpected.txt"
            unexpected.write_text("synthetic\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unmanifested artifact"):
                verify_release_set(
                    release,
                    source_commit=source_commit,
                    source_tree=source_tree,
                    forbidden_values=[],
                )
            unexpected.unlink()
            wheel.write_bytes(wheel.read_bytes() + b"tamper")
            with self.assertRaisesRegex(RuntimeError, "does not match its manifest"):
                verify_release_set(
                    release,
                    source_commit=source_commit,
                    source_tree=source_tree,
                    forbidden_values=[],
                )

    def test_release_builder_rejects_python_environment_shadowing(self) -> None:
        with (
            mock.patch.dict(os.environ, {"PYTHONPATH": "synthetic-shadow"}, clear=False),
            self.assertRaisesRegex(RuntimeError, "PYTHONPATH must be unset"),
        ):
            reject_python_environment_overrides()


@unittest.skipUnless(Path("/usr/bin/git").is_file(), "macOS release staging needs /usr/bin/git")
class MacReleaseSourceProvenanceTests(unittest.TestCase):
    def test_release_builder_reexecutes_and_reverifies_the_committed_source_stage(self) -> None:
        contents = (ROOT / "script" / "build_release_app.sh").read_text(encoding="utf-8")
        self.assertIn(
            'show "$TVTIME_RELEASE_COMMIT:script/git_source_stage.py"',
            contents,
        )
        self.assertIn(
            'exec "$PREPARED_RELEASE_STAGE/source/script/build_release_app.sh"',
            contents,
        )
        self.assertGreaterEqual(contents.count('"$ROOT_DIR/script/git_source_stage.py"'), 2)
        self.assertIn('--package-path "$ROOT_DIR/macos"', contents)
        self.assertNotIn('--package-path "$CHECKOUT_ROOT/macos"', contents)

    def test_release_stage_ignores_worktree_change_restore_race_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()

            def run_git(*arguments: str) -> str:
                completed = subprocess.run(
                    ["/usr/bin/git", "-C", str(repository), *arguments],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return completed.stdout.strip()

            run_git("init", "--quiet")
            run_git("config", "user.name", "Synthetic Test")
            run_git("config", "user.email", "synthetic@example.invalid")
            (repository / ".gitignore").write_text("dist/\n", encoding="utf-8")
            tracked = repository / "reviewed-source.txt"
            tracked.write_text("reviewed synthetic source\n", encoding="utf-8")
            run_git("add", ".gitignore", "reviewed-source.txt")
            run_git("commit", "--quiet", "-m", "synthetic reviewed source")
            commit = run_git("rev-parse", "HEAD")

            release_stage = prepare_source_stage(repository, commit)
            source = release_stage / "source"
            staged_file = source / "reviewed-source.txt"
            try:
                self.assertEqual(
                    staged_file.read_text(encoding="utf-8"), "reviewed synthetic source\n"
                )
                self.assertEqual(stat.S_IMODE(staged_file.stat().st_mode), 0o444)

                tracked.write_text("temporary unreviewed race content\n", encoding="utf-8")
                verify_source_stage(repository, commit, source)
                self.assertEqual(
                    staged_file.read_text(encoding="utf-8"),
                    "reviewed synthetic source\n",
                )
                tracked.write_text("reviewed synthetic source\n", encoding="utf-8")

                staged_file.chmod(0o644)
                staged_file.write_text("tampered staged source\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "does not exactly match"):
                    verify_source_stage(repository, commit, source)
            finally:
                make_source_removable(source)


class RepositoryPrivacyIgnoreContractTests(unittest.TestCase):
    def test_tracked_binary_media_is_exact_reviewed_allowlist(self) -> None:
        completed = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
        media_suffixes = {
            ".gif",
            ".heic",
            ".icns",
            ".jpeg",
            ".jpg",
            ".m4v",
            ".mov",
            ".mp4",
            ".pdf",
            ".png",
            ".tif",
            ".tiff",
            ".webp",
            ".zip",
        }
        tracked_media = {
            path
            for path in completed.stdout.decode("utf-8").split("\0")
            if path and Path(path).suffix.casefold() in media_suffixes
        }
        self.assertEqual(
            tracked_media,
            {
                "macos/Bundle/AppIcon-1024.png",
                "macos/Bundle/AppIcon.icns",
            },
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name) / "synthetic-repository"
        self.repository.mkdir()
        shutil.copyfile(ROOT / ".gitignore", self.repository / ".gitignore")
        subprocess.run(
            ["git", "init", "--quiet", str(self.repository)],
            check=True,
            capture_output=True,
            text=True,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _is_ignored(self, relative_path: str) -> bool:
        completed = subprocess.run(
            [
                "git",
                "-c",
                "core.excludesFile=/dev/null",
                "-C",
                str(self.repository),
                "check-ignore",
                "--no-index",
                "--quiet",
                "--",
                relative_path,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode not in (0, 1):
            raise AssertionError(f"git check-ignore failed safely: {completed.stderr.strip()}")
        return completed.returncode == 0

    def test_private_recovery_artifact_shapes_are_ignored(self) -> None:
        synthetic_payload = "a" * 40
        ignored_paths = (
            f"SyntheticBackup/ab/{synthetic_payload}",
            "TVTime-Recovered-Data.pdf",
            "TVTime-Recovered-Data.html",
            "TVTime-Recovery-SYNTHETIC-DEMO.zip",
            "nested/TVTime-Recovered-Data.md",
            "nested/TVTime-Recovered-Data.csv",
            "nested/TVTime-Recovery-SYNTHETIC-DEMO.zip",
            "synthetic/SYNTHETIC-QA-FIXTURE-NOT-RECOVERED-USER-DATA.pdf",
            "synthetic/Screenshot 2099-01-01 at 1.00.00 pm.png",
            "synthetic/Screen Shot 2099-01-01 at 1.00.00 PM.png",
            "synthetic/Screen Recording 2099-01-01 at 1.00.00 PM.mov",
            "docs/screenshot.png",
            "docs/step-1.png",
            "docs/guide.pdf",
            "nested/capture.jpg",
            "nested/recording.mp4",
            "nested/unreviewed.zip",
            "TV-Time-Backup-Extractor.dmg",
        )
        for relative_path in ignored_paths:
            with self.subTest(relative_path=relative_path):
                self.assertTrue(self._is_ignored(relative_path))

    def test_ignore_contract_preserves_source_assets_and_near_misses(self) -> None:
        visible_paths = (
            "macos/Bundle/AppIcon-1024.png",
            "macos/Bundle/AppIcon.icns",
            "release/source.tar.gz",
            f"SyntheticBackup/not-a-shard/{'a' * 40}",
            f"SyntheticBackup/ab/{'a' * 39}",
            f"SyntheticBackup/ab/{'a' * 41}",
            f"SyntheticBackup/ab/{'a' * 39}z",
        )
        for relative_path in visible_paths:
            with self.subTest(relative_path=relative_path):
                self.assertFalse(self._is_ignored(relative_path))


class SyntheticVisualFixtureContractTests(unittest.TestCase):
    def test_fixture_outputs_have_unmistakable_non_recovery_filenames(self) -> None:
        filenames = (
            build_visual_report_fixture.SYNTHETIC_HTML_FILENAME,
            build_visual_report_fixture.SYNTHETIC_PDF_FILENAME,
        )
        for filename in filenames:
            with self.subTest(filename=filename):
                self.assertTrue(filename.startswith("SYNTHETIC-QA-FIXTURE-"))
                self.assertIn("NOT-RECOVERED-USER-DATA", filename)
                self.assertNotIn("TVTime-Recovered-Data", filename)


class ReleaseScannerTests(unittest.TestCase):
    def test_entry_stat_and_file_read_errors_fail_closed(self) -> None:
        synthetic_path = Path("synthetic-release-entry")
        with (
            mock.patch.object(Path, "lstat", side_effect=PermissionError("synthetic stat denial")),
            self.assertRaisesRegex(RuntimeError, "metadata could not be read"),
        ):
            scan_macos_release.entry_mode(synthetic_path)
        with (
            mock.patch.object(Path, "open", side_effect=PermissionError("synthetic read denial")),
            self.assertRaisesRegex(RuntimeError, "unreadable regular file"),
        ):
            scan_macos_release.contains_value(synthetic_path, (b"synthetic",))

    def test_walk_errors_are_never_silently_skipped(self) -> None:
        def inaccessible_walk(_root, *, followlinks, onerror):
            self.assertFalse(followlinks)
            onerror(PermissionError("synthetic unreadable directory"))
            return iter(())

        with (
            mock.patch.object(scan_macos_release.os, "walk", side_effect=inaccessible_walk),
            self.assertRaisesRegex(RuntimeError, "could not be traversed safely"),
        ):
            list(scan_macos_release.walk_release_tree(Path("synthetic-release-tree")))

    @unittest.skipIf(os.name == "nt", "Windows chmod does not enforce POSIX traversal permissions")
    def test_unreadable_posix_subtree_with_forbidden_content_fails_closed(self) -> None:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root can traverse chmod-000 directories")

        scanner = ROOT / "script" / "scan_macos_release.py"
        with tempfile.TemporaryDirectory() as temporary:
            release_tree = Path(temporary) / "release"
            blocked = release_tree / "blocked"
            blocked.mkdir(parents=True)
            (blocked / "Manifest.plist").write_bytes(b"synthetic forbidden content")
            blocked.chmod(0)
            try:
                try:
                    with os.scandir(blocked):
                        pass
                except PermissionError:
                    pass
                else:
                    self.skipTest("filesystem does not enforce chmod-000 traversal denial")

                completed = subprocess.run(
                    [sys.executable, str(scanner), "--root", str(release_tree)],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            finally:
                blocked.chmod(0o700)

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("could not be traversed safely", completed.stdout)

    def test_backup_control_plists_are_denied_from_release_trees(self) -> None:
        scanner = ROOT / "script" / "scan_macos_release.py"
        for forbidden_name in ("Manifest.plist", "Status.plist"):
            with (
                self.subTest(forbidden_name=forbidden_name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                release_tree = Path(temporary)
                (release_tree / forbidden_name).write_bytes(b"synthetic")
                completed = subprocess.run(
                    [sys.executable, str(scanner), "--root", str(release_tree)],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("forbidden private-output file", completed.stdout)


@unittest.skipIf(os.name == "nt", "macOS packaging helpers require a POSIX shell")
class MacPackagingIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bash = shutil.which("bash")
        if self.bash is None:
            self.skipTest("bash is unavailable")

    def test_python_shadow_environment_is_rejected_before_helper_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            shadow_root = Path(temporary)
            shadow_package = shadow_root / "charset_normalizer"
            shadow_package.mkdir()
            marker = shadow_root / "shadow-loaded"
            (shadow_package / "__init__.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('loaded')\n",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(shadow_root)
            completed = subprocess.run(
                [self.bash, str(ROOT / "script" / "build_macos_helper.sh")],
                check=False,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("PYTHONPATH must be unset", completed.stdout)
            self.assertFalse(marker.exists())

    def test_helper_lifecycle_lock_blocks_concurrent_cache_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            synthetic_root = Path(temporary).resolve() / "repository"
            cache = synthetic_root / ".build-tools" / "helper-venv-arm64" / "sentinel"
            cache.parent.mkdir(parents=True)
            cache.write_text("original", encoding="utf-8")
            script = """
set -euo pipefail
ROOT_DIR="$1"
LIBRARY="$2"
CACHE="$3"
source "$LIBRARY"
owner_token="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
contender_token="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
acquire_helper_lifecycle_lock arm64 "$owner_token"
(
  if acquire_helper_lifecycle_lock arm64 "$contender_token"; then
    printf '%s\n' replaced >"$CACHE"
    release_helper_lifecycle_lock arm64 "$contender_token"
    exit 9
  fi
)
if [[ "$(<"$CACHE")" != original ]]; then
  exit 10
fi
release_helper_lifecycle_lock arm64 "$owner_token"
"""
            completed = subprocess.run(
                [
                    self.bash,
                    "-c",
                    script,
                    "synthetic-lock-test",
                    str(synthetic_root),
                    str(ROOT / "script" / "macos_packaging_lib.sh"),
                    str(cache),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertEqual(cache.read_text(encoding="utf-8"), "original")

    def test_release_stage_can_use_checkout_dist_without_broadening_other_generated_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            synthetic_root = Path(temporary).resolve() / "immutable-source"
            checkout_root = Path(temporary).resolve() / "checkout"
            (synthetic_root / "dist").mkdir(parents=True)
            (checkout_root / "dist").mkdir(parents=True)
            script = """
set -euo pipefail
ROOT_DIR="$1"
PACKAGING_GENERATED_ROOT_DIR="$2"
source "$3"
assert_generated_path "$2/dist/.macos-release.synthetic"
if assert_generated_path "$2/private/unsafe"; then
  exit 9
fi
"""
            completed = subprocess.run(
                [
                    self.bash,
                    "-c",
                    script,
                    "synthetic-generated-root-test",
                    str(synthetic_root),
                    str(checkout_root),
                    str(ROOT / "script" / "macos_packaging_lib.sh"),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("outside generated build/dist roots", completed.stdout)


if __name__ == "__main__":
    unittest.main()
