#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=script/macos_packaging_lib.sh
source "$ROOT_DIR/script/macos_packaging_lib.sh"
APP_NAME="TV Time Backup Extractor"
PROCESS_NAME="TVTimeRecoveryApp"
BUNDLE_ID="com.amirbrooks.tvtime-backup-extractor"
APP_BUNDLE="$ROOT_DIR/dist/$APP_NAME.app"
APP_BINARY="$APP_BUNDLE/Contents/MacOS/$PROCESS_NAME"

refuse_running_recovery_processes
"$ROOT_DIR/script/build_local_app.sh"

open_app() {
  /usr/bin/open -n "$APP_BUNDLE"
}

case "$MODE" in
  run)
    open_app
    ;;
  --debug|debug)
    /usr/bin/lldb -- "$APP_BINARY"
    ;;
  --logs|logs)
    open_app
    /usr/bin/log stream --info --style compact --predicate "process == \"$PROCESS_NAME\""
    ;;
  --telemetry|telemetry)
    /usr/bin/log stream --info --style compact \
      --predicate "subsystem == \"$BUNDLE_ID\" AND category == \"RecoveryDiagnostics\"" &
    telemetry_pid=$!
    trap '/bin/kill "$telemetry_pid" 2>/dev/null || true' EXIT INT TERM
    # Give the local stream time to attach so startup events are observable.
    /bin/sleep 1
    /bin/kill -0 "$telemetry_pid"
    open_app
    wait "$telemetry_pid"
    ;;
  --verify|verify)
    open_app
    /bin/sleep 2
    /usr/bin/pgrep -x "$PROCESS_NAME" >/dev/null
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac
