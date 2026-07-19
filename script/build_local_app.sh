#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=script/macos_packaging_lib.sh
source "$ROOT_DIR/script/macos_packaging_lib.sh"
reject_python_environment_overrides

APP_NAME="TV Time Backup Extractor"
EXECUTABLE_NAME="TVTimeRecoveryApp"
HOST_ARCH="$(/usr/bin/uname -m)"
DIST_ROOT="$ROOT_DIR/dist"
APP_BUNDLE="$DIST_ROOT/$APP_NAME.app"

case "$HOST_ARCH" in
  arm64|x86_64) ;;
  *)
    echo "error: unsupported local Mac architecture: $HOST_ARCH" >&2
    exit 2
    ;;
esac
require_packaging_command /usr/bin/xattr
require_packaging_command /usr/bin/strip
require_packaging_command /usr/bin/cmp
require_packaging_command /usr/bin/sips
if [[ -n "${TVTIME_TARGET_ARCH:-}" ]] && [[ "$TVTIME_TARGET_ARCH" != "$HOST_ARCH" ]]; then
  echo "error: local acceptance builds are host-architecture only ($HOST_ARCH)" >&2
  echo "Use script/build_release_app.sh for both distributable architectures." >&2
  exit 2
fi

refuse_running_recovery_processes
/bin/mkdir -p "$DIST_ROOT"
LOCAL_LOCK="$DIST_ROOT/.local-build.lock"
acquire_generated_lock "$LOCAL_LOCK"
LOCAL_STAGE=""
HELPER_LOCK_ACQUIRED=false
HELPER_LOCK_TOKEN=""
local_exit() {
  local status=$?
  trap - EXIT
  if [[ $status -ne 0 ]] && [[ -n "$LOCAL_STAGE" ]] && [[ -d "$LOCAL_STAGE" ]]; then
    echo "Local build failed safely; the previous app was unchanged." >&2
    echo "The generated diagnostic stage was preserved at $LOCAL_STAGE" >&2
  fi
  if [[ "$HELPER_LOCK_ACQUIRED" == true ]]; then
    if ! release_helper_lifecycle_lock "$HOST_ARCH" "$HELPER_LOCK_TOKEN" \
      && [[ $status -eq 0 ]]
    then
      status=1
    fi
  fi
  if ! release_generated_lock "$LOCAL_LOCK" && [[ $status -eq 0 ]]; then
    status=1
  fi
  exit "$status"
}
trap local_exit EXIT
HELPER_LOCK_TOKEN="$(new_helper_lifecycle_token)"
acquire_helper_lifecycle_lock "$HOST_ARCH" "$HELPER_LOCK_TOKEN"
HELPER_LOCK_ACQUIRED=true
LOCAL_STAGE="$(/usr/bin/mktemp -d "$DIST_ROOT/.local-app.XXXXXX")"
assert_generated_path "$LOCAL_STAGE"
STAGED_APP="$LOCAL_STAGE/$APP_NAME.app"
APP_CONTENTS="$STAGED_APP/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_HELPERS="$APP_CONTENTS/Helpers"
HELPER_BUNDLE="$APP_HELPERS/TVTimeHelper.bundle"
HELPER_CONTENTS="$HELPER_BUNDLE/Contents"
HELPER_MACOS="$HELPER_CONTENTS/MacOS"
HELPER_RESOURCES="$HELPER_CONTENTS/Resources"

HELPER_SOURCE="$(
  TVTIME_TARGET_ARCH="$HOST_ARCH" \
  TVTIME_HELPER_LOCK_HELD=1 \
  TVTIME_HELPER_LOCK_TOKEN="$HELPER_LOCK_TOKEN" \
    "$ROOT_DIR/script/build_macos_helper.sh"
)"
HELPER_PYTHON="$ROOT_DIR/.build-tools/helper-venv-$HOST_ARCH/bin/python"
HELPER_PYTHON_COMMAND=(/usr/bin/arch "-$HOST_ARCH" "$HELPER_PYTHON" -I)
SWIFT_LOCK_DIGEST="$(swift_package_lock_digest)"

/usr/bin/xcrun swift build \
  --package-path "$ROOT_DIR/macos" \
  --disable-automatic-resolution \
  --configuration release
SWIFT_BIN_DIR="$(
  /usr/bin/xcrun swift build \
    --package-path "$ROOT_DIR/macos" \
    --disable-automatic-resolution \
    --configuration release \
    --show-bin-path
)"
verify_swift_package_lock_unchanged "$SWIFT_LOCK_DIGEST"
SWIFT_BINARY="$SWIFT_BIN_DIR/$EXECUTABLE_NAME"
if [[ ! -x "$SWIFT_BINARY" ]]; then
  echo "error: SwiftPM did not create $EXECUTABLE_NAME" >&2
  echo "The previous local app, if any, was left unchanged." >&2
  exit 1
fi

/bin/mkdir -p "$APP_MACOS" "$APP_RESOURCES" "$HELPER_MACOS" "$HELPER_RESOURCES"
/bin/cp "$SWIFT_BINARY" "$APP_MACOS/$EXECUTABLE_NAME"
/usr/bin/strip -S "$APP_MACOS/$EXECUTABLE_NAME"
/bin/chmod 755 "$APP_MACOS/$EXECUTABLE_NAME"
/bin/cp "$ROOT_DIR/macos/Bundle/Info.plist" "$APP_CONTENTS/Info.plist"
/bin/cp "$ROOT_DIR/macos/Bundle/AppIcon.icns" "$APP_RESOURCES/AppIcon.icns"
/bin/cp "$ROOT_DIR/macos/Bundle/THIRD_PARTY_NOTICES.md" "$APP_RESOURCES/"
/bin/cp "$ROOT_DIR/LICENSE" "$APP_RESOURCES/PROJECT_LICENSE.txt"
/bin/cp "$ROOT_DIR/macos/Bundle/TVTimeHelper-Info.plist" "$HELPER_CONTENTS/Info.plist"
/bin/cp "$HELPER_SOURCE/tvtime-helper" "$HELPER_MACOS/tvtime-helper"
/bin/chmod 755 "$HELPER_MACOS/tvtime-helper"
/usr/bin/ditto "$HELPER_SOURCE/_internal" "$HELPER_RESOURCES/_internal"
/bin/ln -s ../Resources/_internal "$HELPER_MACOS/_internal"

license_arguments=(
  --output "$APP_RESOURCES/Licenses"
  --app "$STAGED_APP"
  --requirements "$ROOT_DIR/requirements.txt"
  --requirements "$ROOT_DIR/requirements-macos-build.txt"
  --project-license "$ROOT_DIR/LICENSE"
  --third-party-notice "$ROOT_DIR/macos/Bundle/THIRD_PARTY_NOTICES.md"
  --native-license-root "$ROOT_DIR/macos/Bundle/NativeLicenses"
  --bundled-license \
    "$HELPER_RESOURCES/_internal/reportlab/fonts/bitstream-vera-license.txt"
)
"${HELPER_PYTHON_COMMAND[@]}" \
  "$ROOT_DIR/script/collect_macos_licenses.py" "${license_arguments[@]}"

/usr/bin/xattr -cr "$STAGED_APP"
/usr/bin/plutil -lint "$APP_CONTENTS/Info.plist"
/usr/bin/plutil -lint "$HELPER_CONTENTS/Info.plist"
verify_macho_tree_exact_architecture "$STAGED_APP" "$HOST_ARCH"
verify_bundled_app_icon "$STAGED_APP" "$ROOT_DIR/macos/Bundle/AppIcon.icns"
privacy_arguments=(--root "$STAGED_APP" --forbidden-value "$ROOT_DIR")
if [[ -n "${HOME:-}" ]]; then
  privacy_arguments+=(--forbidden-value "$HOME")
fi
"${HELPER_PYTHON_COMMAND[@]}" \
  "$ROOT_DIR/script/scan_macos_release.py" "${privacy_arguments[@]}"
sign_macos_app_inside_out \
  "$STAGED_APP" \
  - \
  none \
  "$ROOT_DIR/macos/Bundle/TVTimeRecovery.entitlements" \
  "$ROOT_DIR/macos/Bundle/TVTimeRecoveryHelperLocal.entitlements"
"${HELPER_PYTHON_COMMAND[@]}" \
  "$ROOT_DIR/script/collect_macos_licenses.py" \
  --verify-output "$APP_RESOURCES/Licenses" \
  --app "$STAGED_APP" \
  --bundled-license \
    "$HELPER_RESOURCES/_internal/reportlab/fonts/bitstream-vera-license.txt"
verify_macos_app_signatures "$STAGED_APP"
verify_hardened_runtime_signatures "$STAGED_APP"
verify_local_adhoc_sandbox_entitlements "$STAGED_APP"
verify_bundled_app_icon "$STAGED_APP" "$ROOT_DIR/macos/Bundle/AppIcon.icns"
"${HELPER_PYTHON_COMMAND[@]}" \
  "$ROOT_DIR/script/scan_macos_release.py" "${privacy_arguments[@]}"
print_applied_entitlements "$STAGED_APP"

refuse_running_recovery_processes
promote_generated_directory "$STAGED_APP" "$APP_BUNDLE"
safe_remove_generated "$LOCAL_STAGE"
LOCAL_STAGE=""
release_helper_lifecycle_lock "$HOST_ARCH" "$HELPER_LOCK_TOKEN"
HELPER_LOCK_ACQUIRED=false
release_generated_lock "$LOCAL_LOCK"
trap - EXIT

echo "Local sandboxed acceptance build created for $HOST_ARCH." >&2
echo "It is ad-hoc signed, local-only, and is not a notarized or Gatekeeper-ready release." >&2
echo "$APP_BUNDLE"
