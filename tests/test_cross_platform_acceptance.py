from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from script.run_cross_platform_synthetic_acceptance import (
    AcceptanceFailure,
    readiness_gates,
    scrub_synthetic_tree,
)
from tvtime_extractor.safety import secure_directory, secure_file

ROOT = Path(__file__).resolve().parent.parent


class CrossPlatformSyntheticAcceptanceTests(unittest.TestCase):
    def test_end_to_end_runner_emits_only_bounded_gate_results(self) -> None:
        result = subprocess.run(
            [sys.executable, "-I", "script/run_cross_platform_synthetic_acceptance.py"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stderr, "")
        lines = result.stdout.splitlines()
        self.assertEqual(lines[-1], "RESULT PASS")
        self.assertTrue(all(line.startswith(("GATE ", "RESULT ")) for line in lines))
        self.assertNotIn(os.fspath(Path.home()), result.stdout)
        self.assertNotIn(os.fspath(ROOT), result.stdout)
        for required in (
            "android_archive",
            "android_snapshot",
            "official_export",
            "unsupported_android_rejected",
            "privacy_scrub",
        ):
            self.assertIn(f"GATE {required} PASS", lines)

    def test_scrub_rejects_host_specific_content_without_exposing_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = secure_directory(Path(temporary))
            private = root / "synthetic.txt"
            private.write_text(os.fspath(Path.home()), encoding="utf-8")
            secure_file(private)
            with self.assertRaises(AcceptanceFailure) as context:
                scrub_synthetic_tree(root)
            self.assertNotIn(os.fspath(Path.home()), str(context.exception))

    def test_readiness_gates_do_not_enumerate_devices(self) -> None:
        requested: list[str] = []

        def which(name: str) -> str | None:
            requested.append(name)
            return "/synthetic/tool" if name == "adb" else None

        gates = readiness_gates(which=which, platform_name="darwin")
        self.assertEqual(gates[0].status, "PASS")
        self.assertEqual(gates[1].status, "SKIP")
        self.assertEqual(gates[2].status, "SKIP")
        self.assertNotIn("devices", requested)

    def test_required_missing_tool_changes_skip_to_failure(self) -> None:
        gates = readiness_gates(
            which=lambda _name: None,
            platform_name="darwin",
            require_adb=True,
            require_android_emulator=True,
            require_windows_toolchain=True,
        )
        self.assertTrue(all(gate.status == "FAIL" for gate in gates))

    def test_windows_readiness_accepts_msbuild_discovered_by_vswhere(self) -> None:
        def which(name: str) -> str | None:
            return "/synthetic/tool" if name in {"dotnet", "pwsh"} else None

        gates = readiness_gates(
            which=which,
            platform_name="win32",
            msbuild_probe=lambda: True,
        )
        self.assertEqual(gates[-1].status, "PASS")


if __name__ == "__main__":
    unittest.main()
