from __future__ import annotations

import runpy
from pathlib import Path

if __name__ == "__main__":
    namespace = runpy.run_path(
        str(Path(__file__).with_name("collect_windows_licenses.py")),
        run_name="tvtime_windows_license_verifier",
    )
    verify = namespace.get("verify_python_installation")
    if not callable(verify):
        raise RuntimeError("The Windows Python environment verifier was unavailable.")
    verify()
