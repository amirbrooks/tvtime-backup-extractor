#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ "${TVTIME_IMMUTABLE_RELEASE_SOURCE:-0}" != 1 ]]; then
  CHECKOUT_ROOT="$SCRIPT_ROOT"
  if [[ $# -ne 0 ]]; then
    echo "usage: TVTIME_RELEASE_COMMIT=... TVTIME_SIGNING_IDENTITY=... \\" >&2
    echo "       TVTIME_NOTARY_PROFILE=... \\" >&2
    echo "       TVTIME_BUILD_PYTHON=... $0" >&2
    exit 2
  fi
  for python_override in \
    PYTHONHOME PYTHONPATH PYTHONUSERBASE PYTHONSTARTUP PYTHONINSPECT \
    PYTHONCASEOK PYTHONEXECUTABLE PYTHONPLATLIBDIR __PYVENV_LAUNCHER__
  do
    if declare -p "$python_override" >/dev/null 2>&1; then
      echo "error: $python_override must be unset for isolated Python packaging" >&2
      exit 2
    fi
  done
  if [[ ! "${TVTIME_RELEASE_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "error: set TVTIME_RELEASE_COMMIT to the reviewed full Git commit" >&2
    exit 2
  fi
  if [[ -z "${TVTIME_BUILD_PYTHON:-}" ]] || [[ ! -x "$TVTIME_BUILD_PYTHON" ]]; then
    echo "error: set TVTIME_BUILD_PYTHON to the official universal2 Python 3.13.12 executable" >&2
    exit 2
  fi
  if [[ -z "${TVTIME_SIGNING_IDENTITY:-}" ]] \
    || [[ "$TVTIME_SIGNING_IDENTITY" != *"Developer ID Application:"* ]]
  then
    echo "error: set TVTIME_SIGNING_IDENTITY to a Developer ID Application identity" >&2
    exit 2
  fi
  if [[ -z "${TVTIME_NOTARY_PROFILE:-}" ]]; then
    echo "error: set TVTIME_NOTARY_PROFILE to a notarytool Keychain profile" >&2
    exit 2
  fi
  if ! "$TVTIME_BUILD_PYTHON" -I -c \
    'import sys; raise SystemExit(0 if sys.version_info[:3] == (3, 13, 12) else 1)'
  then
    echo "error: TVTIME_BUILD_PYTHON must be exact Python 3.13.12" >&2
    exit 2
  fi
  if [[ ! -x /usr/bin/git ]]; then
    echo "error: Git is required at /usr/bin/git" >&2
    exit 2
  fi
  PREPARED_RELEASE_STAGE="$(
    /usr/bin/git -C "$CHECKOUT_ROOT" \
      show "$TVTIME_RELEASE_COMMIT:script/git_source_stage.py" \
      | "$TVTIME_BUILD_PYTHON" -I - \
        --prepare \
        --repository "$CHECKOUT_ROOT" \
        --source-commit "$TVTIME_RELEASE_COMMIT"
  )"
  if [[ ! -d "$PREPARED_RELEASE_STAGE/source" ]] \
    || [[ -L "$PREPARED_RELEASE_STAGE" ]] \
    || [[ -L "$PREPARED_RELEASE_STAGE/source" ]]
  then
    echo "error: immutable release source staging did not produce a safe source tree" >&2
    exit 1
  fi
  TVTIME_IMMUTABLE_RELEASE_SOURCE=1 \
  TVTIME_RELEASE_CHECKOUT_ROOT="$CHECKOUT_ROOT" \
  TVTIME_PREPARED_RELEASE_STAGE="$PREPARED_RELEASE_STAGE" \
    exec "$PREPARED_RELEASE_STAGE/source/script/build_release_app.sh"
fi

ROOT_DIR="$SCRIPT_ROOT"
if [[ -z "${TVTIME_RELEASE_CHECKOUT_ROOT:-}" ]] \
  || [[ -z "${TVTIME_PREPARED_RELEASE_STAGE:-}" ]]
then
  echo "error: immutable release source context is incomplete" >&2
  exit 2
fi
CHECKOUT_ROOT="$(cd "$TVTIME_RELEASE_CHECKOUT_ROOT" && pwd -P)"
RELEASE_STAGE="$(cd "$TVTIME_PREPARED_RELEASE_STAGE" && pwd -P)"
if [[ "$ROOT_DIR" != "$RELEASE_STAGE/source" ]]; then
  echo "error: release builder is not running from its prepared Git source stage" >&2
  exit 2
fi
case "$RELEASE_STAGE" in
  "$CHECKOUT_ROOT/dist/.macos-release."*) ;;
  *)
    echo "error: immutable release source stage is outside the checkout distribution root" >&2
    exit 2
    ;;
esac
PACKAGING_GENERATED_ROOT_DIR="$CHECKOUT_ROOT"
# shellcheck source=script/macos_packaging_lib.sh
source "$ROOT_DIR/script/macos_packaging_lib.sh"
reject_python_environment_overrides
early_release_exit() {
  local status=$?
  trap - EXIT
  if [[ $status -ne 0 ]] && [[ -d "$RELEASE_STAGE" ]]; then
    echo "Release failed safely; the immutable diagnostic stage was preserved at:" >&2
    echo "$RELEASE_STAGE" >&2
  fi
  exit "$status"
}
trap early_release_exit EXIT

APP_NAME="TV Time Backup Extractor"
EXECUTABLE_NAME="TVTimeRecoveryApp"
APP_ENTITLEMENTS="$ROOT_DIR/macos/Bundle/TVTimeRecovery.entitlements"
HELPER_ENTITLEMENTS="$ROOT_DIR/macos/Bundle/TVTimeRecoveryHelper.entitlements"
INFO_PLIST="$ROOT_DIR/macos/Bundle/Info.plist"
HELPER_INFO_PLIST="$ROOT_DIR/macos/Bundle/TVTimeHelper-Info.plist"
DIST_ROOT="$CHECKOUT_ROOT/dist"

if [[ $# -ne 0 ]]; then
  echo "usage: TVTIME_RELEASE_COMMIT=... TVTIME_SIGNING_IDENTITY=... \\" >&2
  echo "       TVTIME_NOTARY_PROFILE=... \\" >&2
  echo "       TVTIME_BUILD_PYTHON=... $0" >&2
  exit 2
fi
if [[ -z "${TVTIME_RELEASE_COMMIT:-}" ]]; then
  echo "error: set TVTIME_RELEASE_COMMIT to the reviewed full Git commit" >&2
  exit 2
fi
if [[ -z "${TVTIME_SIGNING_IDENTITY:-}" ]]; then
  echo "error: set TVTIME_SIGNING_IDENTITY to the exact Developer ID Application identity" >&2
  exit 2
fi
if [[ "$TVTIME_SIGNING_IDENTITY" != *"Developer ID Application:"* ]]; then
  echo "error: TVTIME_SIGNING_IDENTITY must name a Developer ID Application identity" >&2
  exit 2
fi
if [[ -z "${TVTIME_NOTARY_PROFILE:-}" ]]; then
  echo "error: set TVTIME_NOTARY_PROFILE to a notarytool Keychain profile" >&2
  exit 2
fi
if [[ -z "${TVTIME_BUILD_PYTHON:-}" ]] || [[ ! -x "$TVTIME_BUILD_PYTHON" ]]; then
  echo "error: set TVTIME_BUILD_PYTHON to the official universal2 Python 3.13.12 executable" >&2
  exit 2
fi

require_packaging_command /usr/bin/xcodebuild "full Xcode"
require_packaging_command /usr/bin/xcrun
require_packaging_command /usr/bin/codesign
require_packaging_command /usr/bin/git
require_packaging_command /usr/bin/security
require_packaging_command /usr/bin/lipo
require_packaging_command /usr/bin/hdiutil
require_packaging_command /usr/bin/xattr
require_packaging_command /usr/bin/diff
require_packaging_command /usr/bin/strip
require_packaging_command /usr/bin/stat
require_packaging_command /usr/bin/cmp
require_packaging_command /usr/bin/sips
require_packaging_command /usr/sbin/spctl
SOURCE_IDENTITY="$(capture_release_source_identity "$TVTIME_RELEASE_COMMIT" "$CHECKOUT_ROOT")"
read -r SOURCE_COMMIT SOURCE_TREE <<<"$SOURCE_IDENTITY"
"$TVTIME_BUILD_PYTHON" -I "$ROOT_DIR/script/git_source_stage.py" \
  --verify \
  --repository "$CHECKOUT_ROOT" \
  --source-commit "$SOURCE_COMMIT" \
  --source "$ROOT_DIR"
SWIFT_LOCK_DIGEST="$(swift_package_lock_digest)"
DEVELOPER_DIRECTORY="$(/usr/bin/xcode-select -p 2>/dev/null || true)"
if [[ "$DEVELOPER_DIRECTORY" != */Contents/Developer ]] \
  || ! /usr/bin/xcodebuild -version >/dev/null 2>&1
then
  echo "error: select a full Xcode installation with xcode-select before release packaging" >&2
  exit 2
fi
for tool in notarytool stapler swift; do
  if ! /usr/bin/xcrun --find "$tool" >/dev/null 2>&1; then
    echo "error: full Xcode does not provide required tool: $tool" >&2
    exit 2
  fi
done
if ! /usr/bin/security find-identity -v -p codesigning \
  | /usr/bin/grep -F -- "$TVTIME_SIGNING_IDENTITY" >/dev/null
then
  echo "error: the requested Developer ID Application identity is not available" >&2
  exit 2
fi
if ! "$TVTIME_BUILD_PYTHON" -I -c \
  'import sys; raise SystemExit(0 if sys.version_info[:3] == (3, 13, 12) else 1)'
then
  echo "error: TVTIME_BUILD_PYTHON must be exact Python 3.13.12" >&2
  exit 2
fi
BUILD_PYTHON_EXECUTABLE="$(
  "$TVTIME_BUILD_PYTHON" -I -c \
    'import pathlib, sys; print(pathlib.Path(sys.executable).resolve())'
)"
verify_macho_architectures "$BUILD_PYTHON_EXECUTABLE" universal2
if [[ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null || true)" != 1 ]]; then
  echo "error: dual-architecture release packaging requires an Apple Silicon build Mac" >&2
  echo "Each architecture must be frozen and released as its own verified package." >&2
  exit 2
fi
for execution_architecture in arm64 x86_64; do
  if ! /usr/bin/arch "-$execution_architecture" "$BUILD_PYTHON_EXECUTABLE" -I -c \
    'import platform, sys; raise SystemExit(0 if platform.machine() == sys.argv[1] else 1)' \
    "$execution_architecture"
  then
    echo "error: TVTIME_BUILD_PYTHON cannot run as $execution_architecture" >&2
    if [[ "$execution_architecture" == x86_64 ]]; then
      echo "Install Rosetta 2, then retry the release build." >&2
    fi
    exit 2
  fi
done
/usr/bin/plutil -lint "$INFO_PLIST" "$HELPER_INFO_PLIST" \
  "$APP_ENTITLEMENTS" "$HELPER_ENTITLEMENTS"
refuse_running_recovery_processes

VERSION="$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$INFO_PLIST")"
HELPER_VERSION="$(
  /usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$HELPER_INFO_PLIST"
)"
PROJECT_VERSION="$(
  "$TVTIME_BUILD_PYTHON" -I -c \
    'import pathlib, re, sys; text = pathlib.Path(sys.argv[1]).read_text(); match = re.search(r"(?m)^version\s*=\s*\"([^\"]+)\"", text); print(match.group(1) if match else "")' \
    "$ROOT_DIR/pyproject.toml"
)"
PACKAGE_VERSION="$(
  "$TVTIME_BUILD_PYTHON" -I -c \
    'import pathlib, re, sys; text = pathlib.Path(sys.argv[1]).read_text(); match = re.search(r"(?m)^__version__\s*=\s*\"([^\"]+)\"", text); print(match.group(1) if match else "")' \
    "$ROOT_DIR/tvtime_extractor/__init__.py"
)"
if [[ -z "$VERSION" ]] \
  || [[ "$VERSION" != "$HELPER_VERSION" ]] \
  || [[ "$VERSION" != "$PROJECT_VERSION" ]] \
  || [[ "$VERSION" != "$PACKAGE_VERSION" ]]
then
  echo "error: release versions must match across both plists, pyproject.toml," >&2
  echo "and tvtime_extractor/__init__.py before packaging" >&2
  exit 2
fi
if [[ -n "${TVTIME_RELEASE_VERSION:-}" ]] && [[ "$TVTIME_RELEASE_VERSION" != "$VERSION" ]]; then
  echo "error: TVTIME_RELEASE_VERSION does not match the application Info.plist" >&2
  exit 2
fi
FINAL_DIR="$DIST_ROOT/release-$VERSION-macos"
assert_generated_path "$FINAL_DIR"
if [[ -e "$FINAL_DIR" ]] || [[ -L "$FINAL_DIR" ]]; then
  echo "error: release output already exists; existing artifacts were left unchanged" >&2
  exit 2
fi

/bin/mkdir -p "$DIST_ROOT"
RELEASE_LOCK="$DIST_ROOT/.release-build.lock"
acquire_generated_lock "$RELEASE_LOCK"
assert_generated_path "$RELEASE_STAGE"
HELPER_ARM64_LOCK_ACQUIRED=false
HELPER_X86_64_LOCK_ACQUIRED=false
HELPER_ARM64_LOCK_TOKEN=""
HELPER_X86_64_LOCK_TOKEN=""
release_exit() {
  local status=$?
  trap - EXIT
  if [[ $status -ne 0 ]] && [[ -n "${RELEASE_STAGE:-}" ]] && [[ -d "$RELEASE_STAGE" ]]; then
    echo "Release failed safely; the generated diagnostic stage was preserved at:" >&2
    echo "$RELEASE_STAGE" >&2
  fi
  if [[ "$HELPER_X86_64_LOCK_ACQUIRED" == true ]]; then
    if ! release_helper_lifecycle_lock x86_64 "$HELPER_X86_64_LOCK_TOKEN" \
      && [[ $status -eq 0 ]]
    then
      status=1
    fi
  fi
  if [[ "$HELPER_ARM64_LOCK_ACQUIRED" == true ]]; then
    if ! release_helper_lifecycle_lock arm64 "$HELPER_ARM64_LOCK_TOKEN" \
      && [[ $status -eq 0 ]]
    then
      status=1
    fi
  fi
  if ! release_generated_lock "$RELEASE_LOCK" && [[ $status -eq 0 ]]; then
    status=1
  fi
  exit "$status"
}
trap release_exit EXIT
HELPER_ARM64_LOCK_TOKEN="$(new_helper_lifecycle_token)"
acquire_helper_lifecycle_lock arm64 "$HELPER_ARM64_LOCK_TOKEN"
HELPER_ARM64_LOCK_ACQUIRED=true
HELPER_X86_64_LOCK_TOKEN="$(new_helper_lifecycle_token)"
acquire_helper_lifecycle_lock x86_64 "$HELPER_X86_64_LOCK_TOKEN"
HELPER_X86_64_LOCK_ACQUIRED=true

WORK_ROOT="$RELEASE_STAGE/work"
OUTPUT_STAGE="$RELEASE_STAGE/output"
/bin/mkdir -p "$WORK_ROOT" "$OUTPUT_STAGE"

SDK_PATH="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"
swift_binary_for_architecture() {
  local architecture="$1"
  local scratch="$WORK_ROOT/swift-$architecture"
  local triple="$architecture-apple-macosx14.0"
  local binary_directory

  /usr/bin/xcrun swift build \
    --package-path "$ROOT_DIR/macos" \
    --disable-automatic-resolution \
    --configuration release \
    --scratch-path "$scratch" \
    --triple "$triple" \
    --sdk "$SDK_PATH" \
    --product "$EXECUTABLE_NAME" >&2
  binary_directory="$(
    /usr/bin/xcrun swift build \
      --package-path "$ROOT_DIR/macos" \
      --disable-automatic-resolution \
      --configuration release \
      --scratch-path "$scratch" \
      --triple "$triple" \
      --sdk "$SDK_PATH" \
      --show-bin-path
  )"
  if [[ ! -x "$binary_directory/$EXECUTABLE_NAME" ]]; then
    echo "error: SwiftPM did not create the $architecture release executable" >&2
    return 1
  fi
  verify_macho_exact_architecture "$binary_directory/$EXECUTABLE_NAME" "$architecture"
  echo "$binary_directory/$EXECUTABLE_NAME"
}

echo "Building and validating both architecture payloads before notarization." >&2
SWIFT_ARM64="$(swift_binary_for_architecture arm64)"
SWIFT_X86_64="$(swift_binary_for_architecture x86_64)"
verify_swift_package_lock_unchanged "$SWIFT_LOCK_DIGEST"
HELPER_ARM64="$(
  TVTIME_TARGET_ARCH=arm64 \
  TVTIME_BUILD_PYTHON="$BUILD_PYTHON_EXECUTABLE" \
  TVTIME_REQUIRE_FRESH_HELPER=1 \
  TVTIME_HELPER_LOCK_HELD=1 \
  TVTIME_HELPER_LOCK_TOKEN="$HELPER_ARM64_LOCK_TOKEN" \
    "$ROOT_DIR/script/build_macos_helper.sh"
)"
HELPER_X86_64="$(
  TVTIME_TARGET_ARCH=x86_64 \
  TVTIME_BUILD_PYTHON="$BUILD_PYTHON_EXECUTABLE" \
  TVTIME_REQUIRE_FRESH_HELPER=1 \
  TVTIME_HELPER_LOCK_HELD=1 \
  TVTIME_HELPER_LOCK_TOKEN="$HELPER_X86_64_LOCK_TOKEN" \
    "$ROOT_DIR/script/build_macos_helper.sh"
)"

release_files=()
build_release_for_architecture() {
  local architecture="$1"
  local package_label="$2"
  local architecture_work="$WORK_ROOT/$architecture"
  local app_bundle="$architecture_work/$APP_NAME.app"
  local app_contents="$app_bundle/Contents"
  local app_macos="$app_contents/MacOS"
  local app_resources="$app_contents/Resources"
  local helper_bundle="$app_contents/Helpers/TVTimeHelper.bundle"
  local helper_contents="$helper_bundle/Contents"
  local helper_macos="$helper_contents/MacOS"
  local helper_resources="$helper_contents/Resources"
  local swift_binary helper_source helper_python app_notary_zip
  local dmg_root dmg_name dmg_path manifest_name manifest_path mount_point
  local embedded_app embedded_helper_resources applications_link top_level_entry_count
  local -a helper_python_command license_arguments privacy_arguments mounted_privacy_arguments

  /bin/mkdir -p "$app_macos" "$app_resources" "$helper_macos" "$helper_resources"
  case "$architecture" in
    arm64)
      swift_binary="$SWIFT_ARM64"
      helper_source="$HELPER_ARM64"
      ;;
    x86_64)
      swift_binary="$SWIFT_X86_64"
      helper_source="$HELPER_X86_64"
      ;;
    *)
      echo "error: unsupported release architecture: $architecture" >&2
      return 2
      ;;
  esac
  /bin/cp "$swift_binary" "$app_macos/$EXECUTABLE_NAME"
  /usr/bin/strip -S "$app_macos/$EXECUTABLE_NAME"
  /bin/chmod 755 "$app_macos/$EXECUTABLE_NAME"
  # Cross-compiled Swift executables are unsigned. Give both architectures the
  # same valid terminal ad-hoc signature so the pre-sign canonical license hash
  # can be compared with the later Developer ID-signed binary.
  /usr/bin/codesign --force --sign - "$app_macos/$EXECUTABLE_NAME"
  verify_macho_exact_architecture "$app_macos/$EXECUTABLE_NAME" "$architecture"

  helper_python="$ROOT_DIR/.build-tools/helper-venv-$architecture/bin/python"
  helper_python_command=(/usr/bin/arch "-$architecture" "$helper_python" -I)

  /bin/cp "$INFO_PLIST" "$app_contents/Info.plist"
  /bin/cp "$ROOT_DIR/macos/Bundle/AppIcon.icns" "$app_resources/AppIcon.icns"
  /bin/cp "$ROOT_DIR/macos/Bundle/THIRD_PARTY_NOTICES.md" "$app_resources/"
  /bin/cp "$ROOT_DIR/LICENSE" "$app_resources/PROJECT_LICENSE.txt"
  /bin/cp "$HELPER_INFO_PLIST" "$helper_contents/Info.plist"
  # Git release staging deliberately makes tracked inputs read-only. The copied
  # bundle resources must be owner-writable so xattr can remove staging metadata
  # before the bundle is signed.
  /bin/chmod u+w \
    "$app_contents/Info.plist" \
    "$app_resources/AppIcon.icns" \
    "$app_resources/THIRD_PARTY_NOTICES.md" \
    "$app_resources/PROJECT_LICENSE.txt" \
    "$helper_contents/Info.plist"
  /bin/cp "$helper_source/tvtime-helper" "$helper_macos/tvtime-helper"
  /bin/chmod 755 "$helper_macos/tvtime-helper"
  /usr/bin/ditto "$helper_source/_internal" "$helper_resources/_internal"
  /bin/ln -s ../Resources/_internal "$helper_macos/_internal"

  license_arguments=(
    --output "$app_resources/Licenses"
    --app "$app_bundle"
    --requirements "$ROOT_DIR/requirements.txt"
    --requirements "$ROOT_DIR/requirements-macos-build.txt"
    --project-license "$ROOT_DIR/LICENSE"
    --third-party-notice "$ROOT_DIR/macos/Bundle/THIRD_PARTY_NOTICES.md"
    --native-license-root "$ROOT_DIR/macos/Bundle/NativeLicenses"
    --required-native-profile "official-cpython-3.13.12-universal2"
    --bundled-license \
      "$helper_resources/_internal/reportlab/fonts/bitstream-vera-license.txt"
  )
  "${helper_python_command[@]}" \
    "$ROOT_DIR/script/collect_macos_licenses.py" "${license_arguments[@]}"

  /usr/bin/xattr -cr "$app_bundle"
  /usr/bin/plutil -lint "$app_contents/Info.plist" "$helper_contents/Info.plist"
  verify_macho_tree_exact_architecture "$app_bundle" "$architecture"
  verify_bundled_app_icon "$app_bundle" "$ROOT_DIR/macos/Bundle/AppIcon.icns"
  privacy_arguments=(
    --root "$app_bundle"
    --forbidden-value "$ROOT_DIR"
    --forbidden-value "$CHECKOUT_ROOT"
    --forbidden-value "$RELEASE_STAGE"
  )
  if [[ -n "${HOME:-}" ]]; then
    privacy_arguments+=(--forbidden-value "$HOME")
  fi
  "${helper_python_command[@]}" \
    "$ROOT_DIR/script/scan_macos_release.py" "${privacy_arguments[@]}"

  sign_macos_app_inside_out \
    "$app_bundle" \
    "$TVTIME_SIGNING_IDENTITY" \
    secure \
    "$APP_ENTITLEMENTS" \
    "$HELPER_ENTITLEMENTS"
  "${helper_python_command[@]}" \
    "$ROOT_DIR/script/collect_macos_licenses.py" \
    --verify-output "$app_resources/Licenses" \
    --app "$app_bundle" \
    --required-native-profile "official-cpython-3.13.12-universal2" \
    --bundled-license \
      "$helper_resources/_internal/reportlab/fonts/bitstream-vera-license.txt"
  verify_macos_app_signatures "$app_bundle"
  verify_hardened_runtime_signatures "$app_bundle"
  verify_expected_sandbox_entitlements "$app_bundle"
  verify_bundled_app_icon "$app_bundle" "$ROOT_DIR/macos/Bundle/AppIcon.icns"
  print_applied_entitlements "$app_bundle"
  "${helper_python_command[@]}" \
    "$ROOT_DIR/script/smoke_packaged_helper.py" \
    --helper "$helper_macos/tvtime-helper" \
    --developer-id-identity "$TVTIME_SIGNING_IDENTITY" \
    --architecture "$architecture"

  app_notary_zip="$architecture_work/notary-app-$architecture.zip"
  /usr/bin/ditto -c -k --sequesterRsrc --keepParent "$app_bundle" "$app_notary_zip"
  /usr/bin/xcrun notarytool submit "$app_notary_zip" \
    --keychain-profile "$TVTIME_NOTARY_PROFILE" \
    --wait
  /usr/bin/xcrun stapler staple "$app_bundle"
  /usr/bin/xcrun stapler validate "$app_bundle"
  verify_macos_app_signatures "$app_bundle"
  verify_hardened_runtime_signatures "$app_bundle"
  verify_macho_tree_exact_architecture "$app_bundle" "$architecture"
  verify_expected_sandbox_entitlements "$app_bundle"
  verify_bundled_app_icon "$app_bundle" "$ROOT_DIR/macos/Bundle/AppIcon.icns"
  /usr/sbin/spctl --assess --type execute --verbose=2 "$app_bundle"
  "${helper_python_command[@]}" \
    "$ROOT_DIR/script/scan_macos_release.py" "${privacy_arguments[@]}"

  dmg_root="$architecture_work/dmg-root"
  dmg_name="TV-Time-Backup-Extractor-$VERSION-macOS-$package_label.dmg"
  dmg_path="$OUTPUT_STAGE/$dmg_name"
  /bin/mkdir -p "$dmg_root"
  /usr/bin/ditto "$app_bundle" "$dmg_root/$APP_NAME.app"
  /bin/ln -s /Applications "$dmg_root/Applications"
  /usr/bin/hdiutil create \
    -volname "$APP_NAME" \
    -srcfolder "$dmg_root" \
    -format UDZO \
    "$dmg_path"
  /usr/bin/codesign --force --sign "$TVTIME_SIGNING_IDENTITY" --timestamp "$dmg_path"
  /usr/bin/codesign --verify --strict --verbose=2 "$dmg_path"
  /usr/bin/xcrun notarytool submit "$dmg_path" \
    --keychain-profile "$TVTIME_NOTARY_PROFILE" \
    --wait
  /usr/bin/xcrun stapler staple "$dmg_path"
  /usr/bin/xcrun stapler validate "$dmg_path"
  /usr/bin/codesign --verify --strict --verbose=2 "$dmg_path"
  /usr/sbin/spctl \
    --assess --type open --context context:primary-signature --verbose=2 "$dmg_path"

  manifest_name="release-manifest-$architecture.json"
  manifest_path="$OUTPUT_STAGE/$manifest_name"
  mount_point="$(/usr/bin/mktemp -d "$architecture_work/dmg-mount.XXXXXX")"
  assert_generated_path "$mount_point"
  (
    mounted=false
    cleanup_mounted_dmg() {
      local status=$?
      local detach_status=0
      local should_detach="$mounted"
      trap - EXIT
      if is_generated_disk_image_mounted "$mount_point"; then
        should_detach=true
      fi
      if [[ "$should_detach" == true ]]; then
        detach_generated_disk_image "$mount_point" || detach_status=$?
        if [[ $detach_status -ne 20 ]]; then
          safe_remove_generated "$mount_point" || status=1
        fi
        if [[ $detach_status -ne 0 ]]; then
          status=1
        fi
      else
        safe_remove_generated "$mount_point" || status=1
      fi
      exit "$status"
    }
    trap cleanup_mounted_dmg EXIT

    /usr/bin/hdiutil attach \
      -readonly \
      -nobrowse \
      -mountpoint "$mount_point" \
      "$dmg_path" >/dev/null
    mounted=true
    embedded_app="$mount_point/$APP_NAME.app"
    embedded_helper_resources="$embedded_app/Contents/Helpers/TVTimeHelper.bundle/Contents/Resources"
    applications_link="$mount_point/Applications"
    if [[ ! -d "$embedded_app" ]] || [[ -L "$embedded_app" ]]; then
      echo "error: mounted release DMG does not contain the expected regular app bundle" >&2
      exit 1
    fi
    if [[ ! -L "$applications_link" ]] \
      || [[ "$(/usr/bin/readlink "$applications_link")" != /Applications ]]
    then
      echo "error: mounted release DMG has an invalid Applications link" >&2
      exit 1
    fi
    top_level_entry_count="$(
      /usr/bin/find "$mount_point" -mindepth 1 -maxdepth 1 -print \
        | /usr/bin/wc -l \
        | /usr/bin/tr -d ' '
    )"
    if [[ "$top_level_entry_count" != 2 ]]; then
      echo "error: mounted release DMG contains unexpected top-level entries" >&2
      exit 1
    fi

    verify_macos_app_signatures "$embedded_app"
    verify_hardened_runtime_signatures "$embedded_app"
    /usr/bin/xcrun stapler validate "$embedded_app"
    /usr/sbin/spctl --assess --type execute --verbose=2 "$embedded_app"
    verify_macho_tree_exact_architecture "$embedded_app" "$architecture"
    verify_expected_sandbox_entitlements "$embedded_app"
    verify_bundled_app_icon "$embedded_app" "$ROOT_DIR/macos/Bundle/AppIcon.icns"
    "${helper_python_command[@]}" \
      "$ROOT_DIR/script/collect_macos_licenses.py" \
      --verify-output "$embedded_app/Contents/Resources/Licenses" \
      --app "$embedded_app" \
      --required-native-profile "official-cpython-3.13.12-universal2" \
      --bundled-license \
        "$embedded_helper_resources/_internal/reportlab/fonts/bitstream-vera-license.txt"
    mounted_privacy_arguments=(
      --root "$embedded_app"
      --forbidden-value "$ROOT_DIR"
      --forbidden-value "$CHECKOUT_ROOT"
      --forbidden-value "$RELEASE_STAGE"
    )
    if [[ -n "${HOME:-}" ]]; then
      mounted_privacy_arguments+=(--forbidden-value "$HOME")
    fi
    "${helper_python_command[@]}" \
      "$ROOT_DIR/script/scan_macos_release.py" \
      "${mounted_privacy_arguments[@]}"
    /usr/bin/diff -qr "$app_bundle" "$embedded_app"
    "${helper_python_command[@]}" \
      "$ROOT_DIR/script/generate_macos_release_manifest.py" \
      --architecture "$architecture" \
      --app "$embedded_app" \
      --artifact "$dmg_path" \
      --output "$manifest_path" \
      --source-commit "$SOURCE_COMMIT" \
      --source-tree "$SOURCE_TREE" \
      --swift-lockfile "$ROOT_DIR/macos/Package.resolved" \
      --dependency-lock "$ROOT_DIR/requirements-macos-build.lock" \
      --requirements "$ROOT_DIR/requirements.txt" \
      --requirements "$ROOT_DIR/requirements-macos-build.txt"
  )
  release_files+=("$dmg_name" "$manifest_name")
  echo "Completed signed and notarized $package_label release package." >&2
}

build_release_for_architecture arm64 Apple-Silicon-arm64
build_release_for_architecture x86_64 Intel-x86_64
verify_swift_package_lock_unchanged "$SWIFT_LOCK_DIGEST"
"$BUILD_PYTHON_EXECUTABLE" -I "$ROOT_DIR/script/git_source_stage.py" \
  --verify \
  --repository "$CHECKOUT_ROOT" \
  --source-commit "$SOURCE_COMMIT" \
  --source "$ROOT_DIR"
verify_release_source_identity "$SOURCE_COMMIT" "$SOURCE_TREE" "$CHECKOUT_ROOT"

output_privacy_arguments=(
  --root "$OUTPUT_STAGE"
  --forbidden-value "$ROOT_DIR"
  --forbidden-value "$CHECKOUT_ROOT"
  --forbidden-value "$RELEASE_STAGE"
)
if [[ -n "${HOME:-}" ]]; then
  output_privacy_arguments+=(--forbidden-value "$HOME")
fi
/usr/bin/arch -arm64 "$ROOT_DIR/.build-tools/helper-venv-arm64/bin/python" -I \
  "$ROOT_DIR/script/scan_macos_release.py" \
  "${output_privacy_arguments[@]}"
(
  cd "$OUTPUT_STAGE"
  /usr/bin/shasum -a 256 "${release_files[@]}" >SHA256SUMS
)

promote_generated_directory "$OUTPUT_STAGE" "$FINAL_DIR"
release_helper_lifecycle_lock x86_64 "$HELPER_X86_64_LOCK_TOKEN"
HELPER_X86_64_LOCK_ACQUIRED=false
release_helper_lifecycle_lock arm64 "$HELPER_ARM64_LOCK_TOKEN"
HELPER_ARM64_LOCK_ACQUIRED=false
"$BUILD_PYTHON_EXECUTABLE" -I "$ROOT_DIR/script/git_source_stage.py" \
  --unlock --source "$ROOT_DIR"
safe_remove_generated "$RELEASE_STAGE"
RELEASE_STAGE=""
release_generated_lock "$RELEASE_LOCK"
trap - EXIT

echo "Both architecture-specific packages passed signing, notarization, Gatekeeper," >&2
echo "exact-architecture, privacy, and manifest gates." >&2
echo "Users with Apple silicon select the arm64 DMG; users with Intel select x86_64." >&2
echo "No artifact was uploaded to GitHub or any other distribution service." >&2
echo "$FINAL_DIR"
