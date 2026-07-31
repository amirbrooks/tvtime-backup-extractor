# Private cross-platform synthetic checks

Use the synthetic acceptance runner to verify source acquisition, analysis, reporting, output
validation, privacy scrubbing, and host-tool readiness without reading a real backup or querying a
connected device.

```bash
python -I script/run_cross_platform_synthetic_acceptance.py
```

The runner creates a fresh owner-only temporary tree containing only deterministic synthetic data.
It exercises:

- a compatible compressed Android backup container;
- a preserved Android database snapshot with an empty optional SQLite sidecar;
- an official export ZIP;
- rejection of unsupported Android backup encryption;
- the complete recovery-output validator; and
- a bounded scrub for links, unsafe permissions, oversized artifacts, and host-specific paths.

It always deletes the temporary tree and prints only fixed `GATE` and `RESULT` lines. It never runs
`adb devices`, lists a serial number, captures from a phone, opens a real backup, or prints a source,
output, account, or host path.

Readiness checks are informational by default. Missing optional tools produce `SKIP`, allowing the
same command to run on macOS, Linux, and Windows. Tighten the expected host contract explicitly:

```bash
python -I script/run_cross_platform_synthetic_acceptance.py --require-adb
python -I script/run_cross_platform_synthetic_acceptance.py \
  --require-adb --require-android-emulator
python -I script/run_cross_platform_synthetic_acceptance.py --require-windows-toolchain
```

Every required gate and the final result must say `PASS`. On Windows, the toolchain gate requires
.NET, PowerShell, and MSBuild. It is only a readiness check: the private MSIX must still be built,
installed, launched, exercised with the same synthetic sources, and removed on a disposable
encrypted Windows host before Windows runtime support is considered verified.

The Android emulator gate proves only that an emulator command is available. A separate disposable
legacy-compatible virtual device and a locally generated synthetic backup-enabled application are
needed to exercise the ADB transport. Neither an emulator nor synthetic fixture proves that a real
TV Time release or a modern device permits backup.

This runner checks private generated recovery trees. It does not replace the source/wheel release
privacy scan, native signing and entitlement checks, or authorized private real-backup validation.
Never add generated fixtures, recovered output, screenshots, paths, device identifiers, or gate
logs containing non-synthetic data to the repository or a support request.
