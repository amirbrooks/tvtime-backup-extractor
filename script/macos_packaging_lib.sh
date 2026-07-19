#!/usr/bin/env bash

# Shared, side-effect-conscious helpers for the macOS packaging scripts.
# Callers must set ROOT_DIR to the canonical repository root before use.

packaging_die() {
  echo "error: $*" >&2
  return 1
}

require_packaging_command() {
  local command_path="$1"
  local label="${2:-$1}"
  if [[ ! -x "$command_path" ]]; then
    packaging_die "$label is required at $command_path"
  fi
}

reject_python_environment_overrides() {
  local variable
  for variable in \
    PYTHONHOME \
    PYTHONPATH \
    PYTHONUSERBASE \
    PYTHONSTARTUP \
    PYTHONINSPECT \
    PYTHONCASEOK \
    PYTHONEXECUTABLE \
    PYTHONPLATLIBDIR \
    __PYVENV_LAUNCHER__
  do
    if declare -p "$variable" >/dev/null 2>&1; then
      packaging_die "$variable must be unset for isolated Python packaging"
      return 1
    fi
  done
}

swift_package_lock_digest() {
  local lockfile="$ROOT_DIR/macos/Package.resolved"

  if [[ ! -f "$lockfile" ]] || [[ -L "$lockfile" ]] || [[ ! -s "$lockfile" ]]; then
    packaging_die "macos/Package.resolved must be a non-empty regular file"
    return 1
  fi
  /usr/bin/shasum -a 256 "$lockfile" | /usr/bin/awk '{print $1}'
}

verify_swift_package_lock_unchanged() {
  local expected_digest="$1"
  local actual_digest

  if [[ ! "$expected_digest" =~ ^[0-9a-f]{64}$ ]]; then
    packaging_die "expected Swift package lock digest is invalid"
    return 1
  fi
  actual_digest="$(swift_package_lock_digest)" || return 1
  if [[ "$actual_digest" != "$expected_digest" ]]; then
    packaging_die "macos/Package.resolved changed during the build"
    return 1
  fi
}

capture_release_source_identity() {
  local expected_commit="$1"
  local repository_root="${2:-$ROOT_DIR}"
  local actual_commit source_tree dirty_state

  require_packaging_command /usr/bin/git || return 1
  if [[ ! "$expected_commit" =~ ^[0-9a-f]{40}$ ]]; then
    packaging_die "TVTIME_RELEASE_COMMIT must be a full lowercase 40-character Git commit"
    return 1
  fi
  actual_commit="$(/usr/bin/git -C "$repository_root" rev-parse --verify 'HEAD^{commit}')" \
    || return 1
  if [[ "$actual_commit" != "$expected_commit" ]]; then
    packaging_die "TVTIME_RELEASE_COMMIT does not match the checked-out HEAD"
    return 1
  fi
  if ! /usr/bin/git -C "$repository_root" ls-files --error-unmatch -- \
    macos/Package.resolved >/dev/null 2>&1
  then
    packaging_die "macos/Package.resolved must be committed before a release build"
    return 1
  fi
  dirty_state="$(
    /usr/bin/git -C "$repository_root" status --porcelain=v1 --untracked-files=all
  )"
  if [[ -n "$dirty_state" ]]; then
    packaging_die "release packaging requires a completely clean tracked and untracked worktree"
    return 1
  fi
  source_tree="$(/usr/bin/git -C "$repository_root" rev-parse --verify "$actual_commit^{tree}")" \
    || return 1
  if [[ ! "$source_tree" =~ ^[0-9a-f]{40}$ ]]; then
    packaging_die "the reviewed release commit did not resolve to a valid source tree"
    return 1
  fi
  printf '%s %s\n' "$actual_commit" "$source_tree"
}

verify_release_source_identity() {
  local expected_commit="$1"
  local expected_tree="$2"
  local repository_root="${3:-$ROOT_DIR}"
  local identity actual_commit actual_tree

  identity="$(capture_release_source_identity "$expected_commit" "$repository_root")" || return 1
  read -r actual_commit actual_tree <<<"$identity"
  if [[ "$actual_tree" != "$expected_tree" ]]; then
    packaging_die "the checked-out source tree changed during release packaging"
    return 1
  fi
}

assert_generated_path() {
  local target="${1:-}"
  local generated_root relative current component
  local additional_root="${PACKAGING_GENERATED_ROOT_DIR:-}"
  local components=()
  if [[ -z "${ROOT_DIR:-}" ]] || [[ "$ROOT_DIR" != /* ]]; then
    packaging_die "ROOT_DIR must be an absolute canonical path"
    return 1
  fi
  if [[ -z "$target" ]] || [[ "$target" != /* ]]; then
    packaging_die "generated paths must be absolute"
    return 1
  fi
  case "$target" in
    *'/../'*|*'/./'*|*'/..'|*'/.'|*'//'*)
      packaging_die "generated paths must not contain traversal or ambiguous components"
      return 1
      ;;
  esac
  case "$target" in
    "$ROOT_DIR/dist/"*) generated_root="$ROOT_DIR/dist" ;;
    "$ROOT_DIR/.build-tools/"*) generated_root="$ROOT_DIR/.build-tools" ;;
    "$additional_root/dist/"*)
      if [[ -z "$additional_root" ]] || [[ "$additional_root" != /* ]]; then
        packaging_die "PACKAGING_GENERATED_ROOT_DIR must be an absolute canonical path"
        return 1
      fi
      generated_root="$additional_root/dist"
      ;;
    *)
      packaging_die "refusing to modify a path outside generated build/dist roots"
      return 1
      ;;
  esac
  if [[ -L "$generated_root" ]]; then
    packaging_die "generated root must not be a symbolic link"
    return 1
  fi
  relative="${target#"$generated_root"/}"
  if [[ -z "$relative" ]]; then
    packaging_die "refusing to modify an entire generated root"
    return 1
  fi
  IFS='/' read -r -a components <<<"$relative"
  current="$generated_root"
  for component in "${components[@]}"; do
    current="$current/$component"
    if [[ -L "$current" ]]; then
      packaging_die "generated path must not traverse a symbolic link"
      return 1
    fi
  done
  return 0
}

safe_remove_generated() {
  local target="$1"
  assert_generated_path "$target" || return 1
  /bin/rm -rf -- "$target"
}

acquire_generated_lock() {
  local lock_directory="$1"
  assert_generated_path "$lock_directory" || return 1
  if ! /bin/mkdir "$lock_directory" 2>/dev/null; then
    echo "error: another packaging process may already be running." >&2
    echo "If no build is active, inspect and remove the stale generated lock manually:" >&2
    echo "$lock_directory" >&2
    return 1
  fi
}

release_generated_lock() {
  local lock_directory="$1"
  assert_generated_path "$lock_directory" || return 1
  /bin/rmdir "$lock_directory"
}

new_helper_lifecycle_token() {
  {
    printf '%s\n' "$$" "$RANDOM" "$RANDOM"
    /bin/date -u +%s
  } | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}'
}

helper_lifecycle_lock_path() {
  case "$1" in
    arm64|x86_64) printf '%s/.helper-%s.lock\n' "$ROOT_DIR/.build-tools" "$1" ;;
    *)
      packaging_die "unsupported helper lifecycle lock architecture"
      return 1
      ;;
  esac
}

acquire_helper_lifecycle_lock() {
  local architecture="$1"
  local token="$2"
  local lock_directory token_path

  if [[ ! "$token" =~ ^[0-9a-f]{64}$ ]]; then
    packaging_die "helper lifecycle lock token is invalid"
    return 1
  fi
  if [[ -L "$ROOT_DIR/.build-tools" ]]; then
    packaging_die "helper build root must not be a symbolic link"
    return 1
  fi
  /bin/mkdir -p "$ROOT_DIR/.build-tools"
  lock_directory="$(helper_lifecycle_lock_path "$architecture")" || return 1
  acquire_generated_lock "$lock_directory" || return 1
  token_path="$lock_directory/.owner-token"
  assert_generated_path "$token_path" || return 1
  if ! (umask 077; printf '%s\n' "$token" >"$token_path"); then
    release_generated_lock "$lock_directory" || true
    packaging_die "could not record helper lifecycle lock ownership"
    return 1
  fi
}

verify_helper_lifecycle_lock() {
  local architecture="$1"
  local token="$2"
  local lock_directory token_path recorded_token

  lock_directory="$(helper_lifecycle_lock_path "$architecture")" || return 1
  token_path="$lock_directory/.owner-token"
  if [[ ! -d "$lock_directory" ]] || [[ -L "$lock_directory" ]] \
    || [[ ! -f "$token_path" ]] || [[ -L "$token_path" ]]
  then
    packaging_die "helper lifecycle lock is unavailable or unsafe"
    return 1
  fi
  recorded_token="$(<"$token_path")"
  if [[ "$recorded_token" != "$token" ]]; then
    packaging_die "helper lifecycle lock ownership does not match"
    return 1
  fi
}

release_helper_lifecycle_lock() {
  local architecture="$1"
  local token="$2"
  local lock_directory token_path

  verify_helper_lifecycle_lock "$architecture" "$token" || return 1
  lock_directory="$(helper_lifecycle_lock_path "$architecture")" || return 1
  token_path="$lock_directory/.owner-token"
  assert_generated_path "$token_path" || return 1
  /bin/rm -f -- "$token_path" || return 1
  release_generated_lock "$lock_directory"
}

promote_generated_directory() {
  local staged="$1"
  local destination="$2"
  local previous="${destination}.previous.$$"
  local had_previous=false

  assert_generated_path "$staged" || return 1
  assert_generated_path "$destination" || return 1
  assert_generated_path "$previous" || return 1
  if [[ ! -d "$staged" ]] || [[ -L "$staged" ]]; then
    packaging_die "staged directory is unavailable or unsafe"
    return 1
  fi
  if [[ -e "$previous" ]] || [[ -L "$previous" ]]; then
    packaging_die "temporary promotion path already exists"
    return 1
  fi

  if [[ -e "$destination" ]] || [[ -L "$destination" ]]; then
    /bin/mv -- "$destination" "$previous"
    had_previous=true
  fi
  if /bin/mv -- "$staged" "$destination"; then
    if [[ "$had_previous" == true ]]; then
      safe_remove_generated "$previous"
    fi
    return 0
  fi

  if [[ "$had_previous" == true ]] && [[ ! -e "$destination" ]] && [[ ! -L "$destination" ]]; then
    /bin/mv -- "$previous" "$destination" || true
  fi
  packaging_die "could not promote the completed generated directory"
}

refuse_running_recovery_processes() {
  local process_name
  for process_name in TVTimeRecoveryApp tvtime-helper; do
    if /usr/bin/pgrep -x "$process_name" >/dev/null 2>&1; then
      echo "error: $process_name is already running; no process was terminated." >&2
      echo "Quit the existing recovery normally, wait for it to finish, then retry." >&2
      return 1
    fi
  done
}

is_macho_file() {
  local path="$1"
  [[ -f "$path" ]] && ! [[ -L "$path" ]] && /usr/bin/file -b "$path" | /usr/bin/grep -q "Mach-O"
}

required_architectures() {
  case "$1" in
    universal2) echo "arm64 x86_64" ;;
    arm64|x86_64) echo "$1" ;;
    *)
      packaging_die "unsupported architecture requirement: $1"
      return 1
      ;;
  esac
}

verify_macho_architectures() {
  local path="$1"
  local target="$2"
  local actual required architecture

  if ! is_macho_file "$path"; then
    packaging_die "expected a Mach-O file in the generated artifact"
    return 1
  fi
  actual="$(/usr/bin/lipo -archs "$path")"
  required="$(required_architectures "$target")"
  for architecture in $required; do
    case " $actual " in
      *" $architecture "*) ;;
      *)
        packaging_die "a generated Mach-O is missing the $architecture slice"
        return 1
        ;;
    esac
  done
}

verify_macho_tree_architectures() {
  local root="$1"
  local target="$2"
  local path
  local found=false

  while IFS= read -r -d '' path; do
    if is_macho_file "$path"; then
      found=true
      verify_macho_architectures "$path" "$target" || return 1
    fi
  done < <(/usr/bin/find "$root" -type f -print0)
  if [[ "$found" != true ]]; then
    packaging_die "the generated tree contained no Mach-O files"
  fi
}

verify_macho_exact_architecture() {
  local path="$1"
  local target="$2"
  local actual required architecture candidate
  local actual_count=0
  local required_count=0

  verify_macho_architectures "$path" "$target" || return 1
  actual="$(/usr/bin/lipo -archs "$path")"
  required="$(required_architectures "$target")"
  for architecture in $actual; do
    actual_count=$((actual_count + 1))
    case " $required " in
      *" $architecture "*) ;;
      *)
        packaging_die "a generated Mach-O contains an unexpected $architecture slice"
        return 1
        ;;
    esac
  done
  for candidate in $required; do
    required_count=$((required_count + 1))
  done
  if [[ $actual_count -ne $required_count ]]; then
    packaging_die "a generated Mach-O does not exactly match the required architecture set"
    return 1
  fi
}

verify_macho_tree_exact_architecture() {
  local root="$1"
  local target="$2"
  local path
  local found=false

  while IFS= read -r -d '' path; do
    if is_macho_file "$path"; then
      found=true
      verify_macho_exact_architecture "$path" "$target" || return 1
    fi
  done < <(/usr/bin/find "$root" -type f -print0)
  if [[ "$found" != true ]]; then
    packaging_die "the generated tree contained no Mach-O files"
  fi
}

codesign_generated_item() {
  local path="$1"
  local identity="$2"
  local timestamp_mode="$3"
  local entitlements="${4:-}"
  local arguments=(--force --sign "$identity")

  if [[ "$timestamp_mode" == none ]]; then
    arguments+=(--options runtime --timestamp=none)
  elif [[ "$timestamp_mode" == secure ]]; then
    arguments+=(--options runtime --timestamp)
  else
    packaging_die "unsupported code-signing timestamp mode"
    return 1
  fi
  if [[ -n "$entitlements" ]]; then
    arguments+=(--entitlements "$entitlements")
  fi
  /usr/bin/codesign "${arguments[@]}" "$path"
}

sign_macos_app_inside_out() {
  local app_bundle="$1"
  local identity="$2"
  local timestamp_mode="$3"
  local app_entitlements="$4"
  local helper_entitlements="$5"
  local helper_bundle="$app_bundle/Contents/Helpers/TVTimeHelper.bundle"
  local path nested

  while IFS= read -r -d '' path; do
    if is_macho_file "$path"; then
      codesign_generated_item "$path" "$identity" "$timestamp_mode" || return 1
    fi
  done < <(/usr/bin/find "$app_bundle" -type f -print0)

  while IFS= read -r -d '' nested; do
    if [[ "$nested" == "$app_bundle" ]]; then
      continue
    fi
    if [[ "$nested" == "$helper_bundle" ]]; then
      codesign_generated_item \
        "$nested" "$identity" "$timestamp_mode" "$helper_entitlements" || return 1
    else
      codesign_generated_item "$nested" "$identity" "$timestamp_mode" || return 1
    fi
  done < <(
    /usr/bin/find "$app_bundle" -depth -type d \
      \( -name '*.framework' -o -name '*.bundle' -o -name '*.xpc' -o -name '*.app' \) \
      -print0
  )

  codesign_generated_item \
    "$app_bundle" "$identity" "$timestamp_mode" "$app_entitlements" || return 1
}

verify_macos_app_signatures() {
  local app_bundle="$1"
  local path

  while IFS= read -r -d '' path; do
    if is_macho_file "$path"; then
      /usr/bin/codesign --verify --strict --verbose=2 "$path" || return 1
    fi
  done < <(/usr/bin/find "$app_bundle" -type f -print0)
  /usr/bin/codesign --verify --deep --strict --verbose=2 "$app_bundle" || return 1
}

verify_hardened_runtime_item() {
  local path="$1"
  local details

  if ! details="$(/usr/bin/codesign --display --verbose=4 "$path" 2>&1)"; then
    packaging_die "a release code object has no inspectable signature"
    return 1
  fi
  if ! /usr/bin/grep -Eq '^CodeDirectory .*flags=.*runtime' <<<"$details"; then
    packaging_die "a release code object is missing the hardened-runtime flag"
    return 1
  fi
}

verify_hardened_runtime_signatures() {
  local app_bundle="$1"
  local path nested
  local found=false

  while IFS= read -r -d '' path; do
    if is_macho_file "$path"; then
      found=true
      verify_hardened_runtime_item "$path" || return 1
    fi
  done < <(/usr/bin/find "$app_bundle" -type f -print0)
  if [[ "$found" != true ]]; then
    packaging_die "the signed release app contained no Mach-O code"
    return 1
  fi

  while IFS= read -r -d '' nested; do
    verify_hardened_runtime_item "$nested" || return 1
  done < <(
    /usr/bin/find "$app_bundle" -depth -type d \
      \( -name '*.framework' -o -name '*.bundle' -o -name '*.xpc' -o -name '*.app' \) \
      -print0
  )
  verify_hardened_runtime_item "$app_bundle"
}

verify_exact_entitlement_profile() {
  local bundle="$1"
  local required_key_one="$2"
  local required_key_two="$3"
  local required_key_three="${4:-}"
  local entitlements keys key value bundle_identifier team_identifier
  local has_application_identifier=false
  local has_team_identifier=false

  if ! entitlements="$(
    /usr/bin/codesign --display --entitlements - --xml "$bundle" 2>/dev/null
  )" || [[ -z "$entitlements" ]]; then
    packaging_die "the signed bundle has no parseable applied entitlements"
    return 1
  fi
  if ! printf '%s' "$entitlements" | /usr/bin/plutil -lint - >/dev/null; then
    packaging_die "the signed bundle returned malformed entitlement data"
    return 1
  fi
  keys="$(
    printf '%s' "$entitlements" \
      | /usr/bin/plutil -p - \
      | /usr/bin/sed -nE 's/^[[:space:]]*"([^"]+)"[[:space:]]*=>.*/\1/p' \
      | LC_ALL=C /usr/bin/sort
  )"
  if [[ -z "$keys" ]]; then
    packaging_die "the signed bundle has an empty entitlement dictionary"
    return 1
  fi
  while IFS= read -r key; do
    case "$key" in
      "$required_key_one"|"$required_key_two") ;;
      "$required_key_three")
        if [[ -z "$required_key_three" ]]; then
          packaging_die "the signed bundle contains an empty entitlement key"
          return 1
        fi
        ;;
      com.apple.application-identifier)
        has_application_identifier=true
        ;;
      com.apple.developer.team-identifier)
        has_team_identifier=true
        ;;
      *)
        packaging_die "the signed bundle contains an unapproved entitlement: $key"
        return 1
        ;;
    esac
  done <<<"$keys"

  for key in "$required_key_one" "$required_key_two"; do
    value="$(
      printf '%s' "$entitlements" \
        | /usr/libexec/PlistBuddy -c "Print :$key" /dev/stdin 2>/dev/null \
        || true
    )"
    if [[ "$value" != true ]]; then
      packaging_die "the signed bundle is missing required boolean entitlement $key"
      return 1
    fi
  done
  if [[ -n "$required_key_three" ]]; then
    value="$(
      printf '%s' "$entitlements" \
        | /usr/libexec/PlistBuddy -c "Print :$required_key_three" /dev/stdin 2>/dev/null \
        || true
    )"
    if [[ "$value" != true ]]; then
      packaging_die "the signed bundle is missing required boolean entitlement $required_key_three"
      return 1
    fi
  fi

  if [[ "$has_application_identifier" != "$has_team_identifier" ]]; then
    packaging_die "the signed bundle has an incomplete signing-identifier entitlement pair"
    return 1
  fi
  if [[ "$has_application_identifier" == true ]]; then
    team_identifier="$(
      /usr/bin/codesign --display --verbose=3 "$bundle" 2>&1 \
        | /usr/bin/awk -F= '$1 == "TeamIdentifier" {print $2; exit}'
    )"
    bundle_identifier="$(
      /usr/bin/plutil -extract CFBundleIdentifier raw -o - "$bundle/Contents/Info.plist"
    )"
    if [[ -z "$team_identifier" ]] || [[ "$team_identifier" == "not set" ]]; then
      packaging_die "signing-identifier entitlements require a real signing Team ID"
      return 1
    fi
    value="$(
      printf '%s' "$entitlements" \
        | /usr/libexec/PlistBuddy \
          -c 'Print :com.apple.developer.team-identifier' /dev/stdin 2>/dev/null \
        || true
    )"
    if [[ "$value" != "$team_identifier" ]]; then
      packaging_die "the applied developer Team ID entitlement does not match the signature"
      return 1
    fi
    value="$(
      printf '%s' "$entitlements" \
        | /usr/libexec/PlistBuddy \
          -c 'Print :com.apple.application-identifier' /dev/stdin 2>/dev/null \
        || true
    )"
    if [[ "$value" != "$team_identifier.$bundle_identifier" ]]; then
      packaging_die "the applied application identifier does not match the signed bundle"
      return 1
    fi
  fi
}

print_applied_entitlements() {
  local app_bundle="$1"
  local helper_bundle="$app_bundle/Contents/Helpers/TVTimeHelper.bundle"

  echo "Applied app entitlements:" >&2
  /usr/bin/codesign --display --entitlements - "$app_bundle" >&2
  echo "Applied helper entitlements:" >&2
  /usr/bin/codesign --display --entitlements - "$helper_bundle" >&2
}

verify_expected_sandbox_entitlements() {
  local app_bundle="$1"
  local helper_bundle="$app_bundle/Contents/Helpers/TVTimeHelper.bundle"

  verify_exact_entitlement_profile \
    "$app_bundle" \
    com.apple.security.app-sandbox \
    com.apple.security.files.user-selected.read-only || return 1
  verify_exact_entitlement_profile \
    "$helper_bundle" \
    com.apple.security.app-sandbox \
    com.apple.security.inherit || return 1
}

verify_local_adhoc_sandbox_entitlements() {
  local app_bundle="$1"
  local helper_bundle="$app_bundle/Contents/Helpers/TVTimeHelper.bundle"

  verify_exact_entitlement_profile \
    "$app_bundle" \
    com.apple.security.app-sandbox \
    com.apple.security.files.user-selected.read-only || return 1
  verify_exact_entitlement_profile \
    "$helper_bundle" \
    com.apple.security.app-sandbox \
    com.apple.security.inherit \
    com.apple.security.cs.disable-library-validation || return 1
}

verify_bundled_app_icon() {
  local app_bundle="$1"
  local expected_icon="${2:-}"
  local icon_name icon_path icon_properties

  icon_name="$(
    /usr/bin/plutil -extract CFBundleIconFile raw -o - "$app_bundle/Contents/Info.plist" \
      2>/dev/null || true
  )"
  if [[ "$icon_name" != AppIcon.icns ]]; then
    packaging_die "the app bundle does not declare the expected application icon"
    return 1
  fi
  icon_path="$app_bundle/Contents/Resources/$icon_name"
  if [[ ! -f "$icon_path" ]] || [[ -L "$icon_path" ]] || [[ ! -s "$icon_path" ]]; then
    packaging_die "the declared application icon is missing or unsafe"
    return 1
  fi
  if [[ -n "$expected_icon" ]]; then
    if [[ ! -f "$expected_icon" ]] || [[ -L "$expected_icon" ]] \
      || ! /usr/bin/cmp -s "$expected_icon" "$icon_path"
    then
      packaging_die "the bundled application icon does not match the reviewed source icon"
      return 1
    fi
  fi
  icon_properties="$(
    /usr/bin/sips -g format -g pixelWidth -g pixelHeight "$icon_path" 2>/dev/null
  )" || {
    packaging_die "the bundled application icon could not be decoded"
    return 1
  }
  if ! /usr/bin/grep -Eq '^[[:space:]]*format: icns$' <<<"$icon_properties" \
    || ! /usr/bin/grep -Eq '^[[:space:]]*pixelWidth: 1024$' <<<"$icon_properties" \
    || ! /usr/bin/grep -Eq '^[[:space:]]*pixelHeight: 1024$' <<<"$icon_properties"
  then
    packaging_die "the bundled application icon is not the expected 1024-pixel ICNS asset"
    return 1
  fi
}

is_generated_disk_image_mounted() {
  local mount_point="$1"
  local mount_device parent_device

  if [[ ! -d "$mount_point" ]] || [[ -L "$mount_point" ]]; then
    return 1
  fi
  mount_device="$(/usr/bin/stat -f %d "$mount_point" 2>/dev/null)" || return 1
  parent_device="$(/usr/bin/stat -f %d "$mount_point/.." 2>/dev/null)" || return 1
  [[ "$mount_device" != "$parent_device" ]]
}

detach_generated_disk_image() {
  local mount_point="$1"

  if /usr/bin/hdiutil detach "$mount_point"; then
    return 0
  fi
  echo "warning: normal disk-image detach failed; forcing generated read-only mount cleanup." >&2
  if /usr/bin/hdiutil detach -force "$mount_point"; then
    return 10
  fi
  echo "error: generated read-only disk image remains mounted at $mount_point" >&2
  return 20
}
