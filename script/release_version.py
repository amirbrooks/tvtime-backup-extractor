#!/usr/bin/env python3
"""Translate the public release identifier into platform-safe versions."""

from __future__ import annotations

import argparse
import re

RELEASE_VERSION_PATTERN = re.compile(
    r"^(?P<base>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))"
    r"(?:-(?P<channel>alpha|beta|rc)\.(?P<number>[1-9]\d*))?$"
)
PEP_440_CHANNELS = {
    "alpha": "a",
    "beta": "b",
    "rc": "rc",
}


def parse_release_version(value: str) -> re.Match[str]:
    match = RELEASE_VERSION_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError("release version must be SemVer or an alpha, beta, or rc prerelease")
    return match


def marketing_version(value: str) -> str:
    """Return the numeric version required by Apple bundle metadata."""
    return parse_release_version(value).group("base")


def python_version(value: str) -> str:
    """Return the equivalent PEP 440 project version."""
    match = parse_release_version(value)
    channel = match.group("channel")
    if channel is None:
        return match.group("base")
    return f"{match.group('base')}{PEP_440_CHANNELS[channel]}{match.group('number')}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release_version")
    parser.add_argument("--format", choices=("marketing", "python"), required=True)
    arguments = parser.parse_args()
    try:
        if arguments.format == "marketing":
            value = marketing_version(arguments.release_version)
        else:
            value = python_version(arguments.release_version)
    except ValueError as error:
        parser.error(str(error))
    print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
