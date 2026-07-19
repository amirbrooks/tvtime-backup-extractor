#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=script/macos_packaging_lib.sh
source "$ROOT_DIR/script/macos_packaging_lib.sh"
reject_python_environment_overrides

TOOLS_DIR="$ROOT_DIR/.build-tools"
TARGET_ARCH="${TVTIME_TARGET_ARCH:-$(/usr/bin/uname -m)}"
VENV_DIR="$TOOLS_DIR/helper-venv-$TARGET_ARCH"
PYINSTALLER_DIR="$TOOLS_DIR/pyinstaller-$TARGET_ARCH"
HELPER_DIR="$PYINSTALLER_DIR/dist/tvtime-helper"
HELPER_BINARY="$HELPER_DIR/tvtime-helper"
REQUIREMENT_LOCK="$ROOT_DIR/requirements-macos-build.lock"
REQUIRE_FRESH_HELPER="${TVTIME_REQUIRE_FRESH_HELPER:-0}"
HELPER_LOCK_HELD="${TVTIME_HELPER_LOCK_HELD:-0}"
HELPER_LOCK_TOKEN="${TVTIME_HELPER_LOCK_TOKEN:-}"
REPORTLAB_FONT_RESOURCE_NAMES=(
  Vera.ttf
  VeraBd.ttf
  VeraIt.ttf
  VeraBI.ttf
  bitstream-vera-license.txt
)

case "$REQUIRE_FRESH_HELPER" in
  0|1) ;;
  *)
    echo "error: TVTIME_REQUIRE_FRESH_HELPER must be 0 or 1" >&2
    exit 2
    ;;
esac
case "$HELPER_LOCK_HELD" in
  0|1) ;;
  *)
    echo "error: TVTIME_HELPER_LOCK_HELD must be 0 or 1" >&2
    exit 2
    ;;
esac
if [[ ! -f "$REQUIREMENT_LOCK" ]] || [[ -L "$REQUIREMENT_LOCK" ]] \
  || [[ ! -s "$REQUIREMENT_LOCK" ]]
then
  echo "error: requirements-macos-build.lock must be a non-empty regular file" >&2
  exit 2
fi

case "$TARGET_ARCH" in
  arm64|x86_64) ;;
  universal2)
    echo "error: a single universal2 frozen helper is not supported" >&2
    echo "PyInstaller executables cannot be combined safely with lipo, and Pillow" >&2
    echo "ships separate arm64 and x86_64 wheels. Build both release packages instead." >&2
    exit 2
    ;;
  *)
    echo "error: TVTIME_TARGET_ARCH must be arm64 or x86_64" >&2
    exit 2
    ;;
esac

require_packaging_command /usr/bin/arch
require_packaging_command /usr/bin/file
require_packaging_command /usr/bin/lipo

find_supported_build_python() {
  local command_name candidate
  for command_name in python3.13 python3; do
    candidate="$(command -v "$command_name" 2>/dev/null || true)"
    if [[ -n "$candidate" ]] \
      && /usr/bin/arch "-$TARGET_ARCH" "$candidate" -I -c \
        'import sys; raise SystemExit(0 if sys.version_info[:3] == (3, 13, 12) else 1)' \
        >/dev/null 2>&1
    then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

if [[ -n "${TVTIME_BUILD_PYTHON:-}" ]]; then
  BUILD_PYTHON="$TVTIME_BUILD_PYTHON"
else
  BUILD_PYTHON="$(find_supported_build_python || true)"
fi
run_python_for_target() {
  local python_executable="$1"
  shift
  /usr/bin/arch "-$TARGET_ARCH" "$python_executable" -I "$@"
}

if [[ -z "$BUILD_PYTHON" ]] || ! run_python_for_target "$BUILD_PYTHON" -c \
  'import sys; raise SystemExit(0 if sys.version_info[:3] == (3, 13, 12) else 1)'
then
  echo "error: macOS helper builds require the reviewed Python 3.13.12 runtime" >&2
  echo "set TVTIME_BUILD_PYTHON to an exact reviewed interpreter and retry" >&2
  exit 2
fi
BUILD_PYTHON_EXECUTABLE="$(
  run_python_for_target "$BUILD_PYTHON" -c \
    'import pathlib, sys; print(pathlib.Path(sys.executable).resolve())'
)"
verify_macho_architectures "$BUILD_PYTHON_EXECUTABLE" "$TARGET_ARCH"

verify_pinned_requirements() {
  local python_executable="$1"
  run_python_for_target "$python_executable" - \
    "$REQUIREMENT_LOCK" <<'PY'
import sys
from importlib import metadata

from packaging.requirements import Requirement

requirements = []
for filename in sys.argv[1:]:
    with open(filename, encoding="utf-8") as handle:
        for raw_line in handle:
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            if raw_line[:1].isspace():
                continue
            line = raw_line.split("#", 1)[0].strip().removesuffix("\\").strip()
            requirement = Requirement(line)
            specifiers = list(requirement.specifier)
            if requirement.url is not None or len(specifiers) != 1:
                raise SystemExit(f"unsupported unpinned build requirement: {line}")
            specifier = specifiers[0]
            if specifier.operator != "==" or specifier.version.endswith(".*"):
                raise SystemExit(f"unsupported unpinned build requirement: {line}")
            if requirement.marker is not None and not requirement.marker.evaluate():
                continue
            requirements.append((requirement.name, specifier.version))

for name, expected in requirements:
    try:
        actual = metadata.version(name)
    except metadata.PackageNotFoundError:
        raise SystemExit(f"missing build requirement: {name}") from None
    if actual != expected:
        raise SystemExit(f"build requirement mismatch: {name}=={actual}, expected {expected}")
PY
}

verify_reportlab_font_resource() {
  local helper_root="$1"
  local font_name vera_font entry entry_count=0
  local font_root="$helper_root/_internal/reportlab/fonts"
  for font_name in "${REPORTLAB_FONT_RESOURCE_NAMES[@]}"; do
    vera_font="$helper_root/_internal/reportlab/fonts/$font_name"
    if [[ ! -f "$vera_font" ]] || [[ -L "$vera_font" ]]; then
      echo "error: frozen helper is missing a required ReportLab Vera resource" >&2
      return 1
    fi
  done
  while IFS= read -r -d '' entry; do
    entry_count=$((entry_count + 1))
    if [[ ! -f "$entry" ]] || [[ -L "$entry" ]]; then
      echo "error: frozen helper has a non-regular ReportLab font resource" >&2
      return 1
    fi
    case "$(/usr/bin/basename "$entry")" in
      Vera.ttf|VeraBd.ttf|VeraIt.ttf|VeraBI.ttf|bitstream-vera-license.txt) ;;
      *)
        echo "error: frozen helper contains an unapproved ReportLab font resource" >&2
        return 1
        ;;
    esac
  done < <(/usr/bin/find "$font_root" -mindepth 1 -maxdepth 1 -print0)
  if [[ $entry_count -ne ${#REPORTLAB_FONT_RESOURCE_NAMES[@]} ]]; then
    echo "error: frozen helper ReportLab font resource set is incomplete" >&2
    return 1
  fi
  if /usr/bin/find "$helper_root" -iname '*darkgarden*' -print -quit | /usr/bin/grep -q .; then
    echo "error: frozen helper contains unapproved DarkGarden assets" >&2
    return 1
  fi
}

HELPER_OWNS_LOCK=false
if [[ "$HELPER_LOCK_HELD" == 1 ]]; then
  verify_helper_lifecycle_lock "$TARGET_ARCH" "$HELPER_LOCK_TOKEN"
else
  HELPER_LOCK_TOKEN="$(new_helper_lifecycle_token)"
  acquire_helper_lifecycle_lock "$TARGET_ARCH" "$HELPER_LOCK_TOKEN"
  HELPER_OWNS_LOCK=true
fi
helper_exit() {
  local status=$?
  trap - EXIT
  if [[ "$HELPER_OWNS_LOCK" == true ]]; then
    if ! release_helper_lifecycle_lock "$TARGET_ARCH" "$HELPER_LOCK_TOKEN" \
      && [[ $status -eq 0 ]]
    then
      status=1
    fi
  fi
  exit "$status"
}
trap helper_exit EXIT

VENV_LOCK="$({
  /usr/bin/shasum -a 256 \
    "$ROOT_DIR/requirements.txt" \
    "$ROOT_DIR/requirements-macos-build.txt" \
    "$REQUIREMENT_LOCK"
  run_python_for_target "$BUILD_PYTHON" -VV
  run_python_for_target "$BUILD_PYTHON" - <<'PY'
import hashlib
import os
import sys
import sysconfig

paths = [os.path.realpath(sys.executable)]
library_name = sysconfig.get_config_var("LDLIBRARY")
library_directory = sysconfig.get_config_var("LIBDIR")
if library_name and library_directory:
    paths.append(os.path.join(library_directory, library_name))
for path in paths:
    if not os.path.isfile(path):
        continue
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    print(f"{os.path.realpath(path)} {digest.hexdigest()}")
PY
  printf '%s\n' "$BUILD_PYTHON_EXECUTABLE" "$TARGET_ARCH"
} | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"

installed_lock=""
if [[ -f "$VENV_DIR/.tvtime-build-lock" ]] && [[ ! -L "$VENV_DIR/.tvtime-build-lock" ]]; then
  installed_lock="$(<"$VENV_DIR/.tvtime-build-lock")"
fi
if [[ "$REQUIRE_FRESH_HELPER" == 1 ]] \
  || [[ ! -x "$VENV_DIR/bin/python" ]] \
  || [[ "$installed_lock" != "$VENV_LOCK" ]] \
  || ! verify_pinned_requirements "$VENV_DIR/bin/python"
then
  VENV_STAGE="$(/usr/bin/mktemp -d "$TOOLS_DIR/.helper-venv-$TARGET_ARCH.XXXXXX")"
  assert_generated_path "$VENV_STAGE"
  run_python_for_target "$BUILD_PYTHON" -m venv "$VENV_STAGE"
  run_python_for_target "$VENV_STAGE/bin/python" -m pip install \
    --disable-pip-version-check \
    --only-binary=:all: \
    --require-hashes \
    --requirement "$REQUIREMENT_LOCK" >&2
  run_python_for_target "$VENV_STAGE/bin/python" -m pip check >&2
  verify_pinned_requirements "$VENV_STAGE/bin/python"
  printf '%s\n' "$VENV_LOCK" >"$VENV_STAGE/.tvtime-build-lock"
  promote_generated_directory "$VENV_STAGE" "$VENV_DIR"
fi

REPORTLAB_FONT_ROOT="$(
  run_python_for_target "$VENV_DIR/bin/python" - <<'PY'
from pathlib import Path

import reportlab

print((Path(reportlab.__file__).resolve().parent / "fonts").resolve(strict=True))
PY
)"
case "$REPORTLAB_FONT_ROOT" in
  "$VENV_DIR"/*) ;;
  *)
    echo "error: ReportLab font resources resolved outside the locked helper environment" >&2
    exit 1
    ;;
esac
for font_name in "${REPORTLAB_FONT_RESOURCE_NAMES[@]}"; do
  font_path="$REPORTLAB_FONT_ROOT/$font_name"
  if [[ ! -f "$font_path" ]] || [[ -L "$font_path" ]]; then
    echo "error: the pinned ReportLab package is missing a required Vera resource" >&2
    exit 1
  fi
done

SOURCE_LOCK="$({
  /usr/bin/find \
    "$ROOT_DIR/tvtime_extractor" \
    -type f -name '*.py' -exec /usr/bin/shasum -a 256 {} \;
  /usr/bin/find \
    "$ROOT_DIR/scripts/macos_helper_entry.py" \
    "$ROOT_DIR/script/build_macos_helper.sh" \
    "$ROOT_DIR/script/macos_packaging_lib.sh" \
    "$ROOT_DIR/script/scan_macos_release.py" \
    "$ROOT_DIR/requirements.txt" \
    "$ROOT_DIR/requirements-macos-build.txt" \
    "$REQUIREMENT_LOCK" \
    "$ROOT_DIR/pyproject.toml" \
    -type f -exec /usr/bin/shasum -a 256 {} \;
  for font_name in "${REPORTLAB_FONT_RESOURCE_NAMES[@]}"; do
    /usr/bin/shasum -a 256 "$REPORTLAB_FONT_ROOT/$font_name"
  done
  printf '%s\n' "$VENV_LOCK" "$TARGET_ARCH"
} | LC_ALL=C /usr/bin/sort | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"

installed_source_lock=""
if [[ -f "$PYINSTALLER_DIR/.tvtime-source-lock" ]] \
  && [[ ! -L "$PYINSTALLER_DIR/.tvtime-source-lock" ]]
then
  installed_source_lock="$(<"$PYINSTALLER_DIR/.tvtime-source-lock")"
fi
if [[ "$REQUIRE_FRESH_HELPER" != 1 ]] \
  && [[ -x "$HELPER_BINARY" ]] \
  && [[ "$installed_source_lock" == "$SOURCE_LOCK" ]]
then
  verify_macho_tree_exact_architecture "$HELPER_DIR" "$TARGET_ARCH"
  verify_reportlab_font_resource "$HELPER_DIR"
  echo "$HELPER_DIR"
  exit 0
fi

PYINSTALLER_STAGE="$(/usr/bin/mktemp -d "$TOOLS_DIR/.pyinstaller-$TARGET_ARCH.XXXXXX")"
assert_generated_path "$PYINSTALLER_STAGE"
DIST_DIR="$PYINSTALLER_STAGE/dist"
WORK_DIR="$PYINSTALLER_STAGE/work"
SPEC_DIR="$PYINSTALLER_STAGE/spec"
/bin/mkdir -p "$DIST_DIR" "$WORK_DIR" "$SPEC_DIR"

reportlab_data_arguments=()
for font_name in "${REPORTLAB_FONT_RESOURCE_NAMES[@]}"; do
  reportlab_data_arguments+=(
    --add-data "$REPORTLAB_FONT_ROOT/$font_name:reportlab/fonts"
  )
done

run_python_for_target "$VENV_DIR/bin/python" -m PyInstaller \
  --clean \
  --noconfirm \
  --onedir \
  --console \
  --noupx \
  --name tvtime-helper \
  --contents-directory _internal \
  --target-arch "$TARGET_ARCH" \
  "${reportlab_data_arguments[@]}" \
  --paths "$ROOT_DIR" \
  --distpath "$DIST_DIR" \
  --workpath "$WORK_DIR" \
  --specpath "$SPEC_DIR" \
  "$ROOT_DIR/scripts/macos_helper_entry.py" >&2

STAGED_HELPER_DIR="$DIST_DIR/tvtime-helper"
STAGED_HELPER_BINARY="$STAGED_HELPER_DIR/tvtime-helper"
if [[ ! -x "$STAGED_HELPER_BINARY" ]]; then
  echo "error: PyInstaller did not create the expected helper" >&2
  echo "The incomplete generated stage was preserved at $PYINSTALLER_STAGE" >&2
  exit 1
fi

/usr/bin/file "$STAGED_HELPER_BINARY" >&2
verify_macho_tree_exact_architecture "$STAGED_HELPER_DIR" "$TARGET_ARCH"
verify_reportlab_font_resource "$STAGED_HELPER_DIR"
scan_arguments=(
  --root "$STAGED_HELPER_DIR"
  --forbidden-value "$ROOT_DIR"
)
if [[ -n "${HOME:-}" ]]; then
  scan_arguments+=(--forbidden-value "$HOME")
fi
run_python_for_target "$VENV_DIR/bin/python" "$ROOT_DIR/script/scan_macos_release.py" \
  "${scan_arguments[@]}" >&2
printf '%s\n' "$SOURCE_LOCK" >"$PYINSTALLER_STAGE/.tvtime-source-lock"

promote_generated_directory "$PYINSTALLER_STAGE" "$PYINSTALLER_DIR"
echo "$HELPER_DIR"
