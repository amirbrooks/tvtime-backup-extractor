#!/usr/bin/env python3
"""Compatibility wrapper for ``tvtime-extractor analyze``."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tvtime_extractor.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["analyze", *sys.argv[1:]]))
