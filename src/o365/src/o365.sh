#!/usr/bin/env bash
# teams-for-linux: single-file wrapper that updates an AppImage (best-effort) then runs it.
# - If update detection fails for ANY reason, it just tries to run the currently cached AppImage.
# - On first run (no cached AppImage), it attempts a download; if that fails, you'll see an error.
# - With --profile=<slug>, map to teams-for-linux's supported flags:
#     --user-data-dir=<abs path> and --class=<name> so multiple apps can run at once.

set -Eeuo pipefail

########## configurable bits (edit in-place) ##########
GITHUB_REPO="IsmaelMartinez/teams-for-linux"
PINNED_VERSION=""
SYSTEM_INSTALL_DIR="/opt/teams-for-linux"
: "${TEAMSL_APP_DIR:=}"
: "${GITHUB_TOKEN:=}"
# export MSAL_USE_BROKER=1
#######################################################

APP_BASENAME="Teams-for-Linux"
CURL_BIN="${CURL_BIN:-curl}"
JQ_BIN="${JQ_BIN:-jq}"
SHA512SUM_BIN="${SHA512SUM_BIN:-sha512sum}"

log() { printf '[teams-wrapper] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

choose_dir() {
  if [[ -n "$TEAMSL_APP_DIR" ]]; then
    TARGET_DIR="$TEAMSL_APP_DIR"
  else
    if [[ -d "$SYSTEM_INSTALL_DIR" && -w "$SYSTEM_INSTALL_DIR" ]] || \
       [[ ! -e "$SYSTEM_INSTALL_DIR" && -w "$(dirname "$SYSTEM_INSTALL_DIR")" ]]; then
      TARGET_DIR="$SYSTEM_INSTALL_DIR"
    else
      local base="${XDG_DATA_HOME:-$HOME/.local/share}"
      TARGET_DIR="$base/teams-for-linux"
    fi
  fi
  mkdir -p "$TARGET_DIR"
  echo "$TARGET_DIR"
}

api_get() {
  local url="$1" ua="teams-appimage-wrapper/1.0"
  if [[ -n "$GITHUB_TOKEN" ]]; then
    "$CURL_BIN" -fsSL -H "Accept: application/vnd.github+json" -H "User-Agent: $ua" -H "Authorization: Bearer $GITHUB_TOKEN" "$url"
  else
    "$CURL_BIN" -fsSL -H "Accept: application/vnd.github+json" -H "User-Agent: $ua" "$url"
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

get_current_version() {
  local link="$TARGET_DIR/$APP_BASENAME.AppImage"
  if [[ -L "$link" ]]; then
    basename "$(readlink -f "$link")" | sed -n 's/.*-\([0-9][^-]*\)\.AppImage$/\1/p' || true
  else
    echo ""
  fi
}

fetch_release_info() {
  if ! have_cmd "$JQ_BIN"; then
    log "jq not found; skipping update detection."
    return 1
  fi
  local api_base="https://api.github.com/repos/${GITHUB_REPO}/releases" json
  if [[ -n "$PINNED_VERSION" ]]; then
    json="$(api_get "$api_base/tags/v${PINNED_VERSION}")" || return 1
  else
    json="$(api_get "$api_base/latest")" || return 1
  fi
  REMOTE_TAG="$(printf '%s' "$json" | "$JQ_BIN" -r '.tag_name // empty' | sed 's/^v//')"
  ASSET_URL="$(printf '%s' "$json" | "$JQ_BIN" -r \
    '.assets[]?.browser_download_url
     | select(endswith(".AppImage"))
     | select(test("arm|aarch|armv7|arm64"; "i")|not)' | head -n1)"
  YML_URL="$(printf '%s' "$json" | "$JQ_BIN" -r \
    '.assets[]?.browser_download_url | select(endswith("latest-linux.yml"))' | head -n1)"
  [[ -n "$ASSET_URL" && "$ASSET_URL" != "null" ]]
}

need_update() {
  local have="$1" remote="$2"
  if [[ ! -x "$TARGET_DIR/$APP_BASENAME.AppImage" ]]; then
    return 0
  fi
  [[ -z "$remote" ]] && return 1
  [[ "$have" != "$remote" ]]
}

download_and_switch() {
  local version="${REMOTE_TAG:-$(date -u +%Y%m%d%H%M%S)}"
  local target="$TARGET_DIR/${APP_BASENAME}-${version}.AppImage"
  local temp="${target}.part"

  log "Downloading $ASSET_URL"
  "$CURL_BIN" -fL --retry 3 --retry-delay 2 -o "$temp" "$ASSET_URL"
  chmod +x "$temp"

  # Optional sha512 verification if manifest is present (electron-builder uses base64)
  if [[ -n "$YML_URL" ]]; then
    log "Fetching checksum manifest (latest-linux.yml)"
    local yml sha_b64 file_b64
    yml="$("$CURL_BIN" -fsSL "$YML_URL" || true)"
    sha_b64="$(printf '%s\n' "$yml" | sed -n 's/^[[:space:]]*sha512:[[:space:]]*//p' | head -n1 | tr -d '\r"\' )"

    if [[ -n "$sha_b64" ]]; then
      if command -v openssl >/dev/null 2>&1; then
        # Compute base64 sha512 of the file and compare to manifest value
        file_b64="$(openssl dgst -sha512 -binary "$temp" | base64 -w0 2>/dev/null || openssl dgst -sha512 -binary "$temp" | base64)"
        if [[ "$file_b64" == "$sha_b64" ]]; then
          log "Checksum OK (base64 sha512)."
        else
          log "Checksum mismatch; discarding."
          rm -f "$temp"
          return 1
        fi
      else
        log "openssl not available; skipping checksum verification."
      fi
    else
      log "No sha512 found in manifest; skipping verification."
    fi
  fi

  mv -f "$temp" "$target"
  ln -sfn "$target" "$TARGET_DIR/$APP_BASENAME.AppImage"
  log "Updated to $APP_BASENAME-$version.AppImage"
}

# -------- profile handling (NEW) --------
PROFILE_SLUG=""
PASSTHRU=()
for arg in "$@"; do
  case "$arg" in
    --profile=*)
      PROFILE_SLUG="${arg#--profile=}"
      ;;
    *)
      PASSTHRU+=("$arg")
      ;;
  esac
done

make_profile_flags() {
  local slug="$1"
  [[ -z "$slug" ]] && return 0
  local dir="$HOME/.config/o365-profiles/$slug"
  mkdir -p "$dir"
  # Use the flags documented by teams-for-linux for multi-instance:
  #   --user-data-dir and --class (window manager grouping)
  printf -- "--user-data-dir=%s\n--class=%s\n" "$dir" "o365-$slug"
}

userns_clone_enabled() {
  # Returns 0 if kernel allows unprivileged user namespaces
  local f="/proc/sys/kernel/unprivileged_userns_clone"
  [[ -r "$f" && "$(cat "$f" 2>/dev/null)" == "1" ]]
}

apparmor_blocks_userns() {
  # Ubuntu 23.10+ exposes this switch; 1 means AppArmor blocks unprivileged user namespaces
  local f="/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
  [[ -r "$f" && "$(cat "$f" 2>/dev/null)" = "1" ]]
}

userns_clone_enabled() {
  local f="/proc/sys/kernel/unprivileged_userns_clone"
  [[ -r "$f" && "$(cat "$f" 2>/dev/null)" = "1" ]]
}

find_system_chrome_sandbox() {
  # Common locations for the setuid sandbox helper
  local candidates=(
    /usr/lib/chromium/chrome-sandbox
    /usr/lib64/chromium/chrome-sandbox
    /opt/google/chrome/chrome-sandbox
    /usr/lib/chrome-sandbox
  )
  for p in "${candidates[@]}"; do
    [[ -f "$p" ]] || continue
    # Needs to be root:root and 4755 to be valid
    local mode owner group
    mode=$(stat -c '%a' "$p" 2>/dev/null || echo "")
    owner=$(stat -c '%U' "$p" 2>/dev/null || echo "")
    group=$(stat -c '%G' "$p" 2>/dev/null || echo "")
    if [[ "$owner" = "root" && "$group" = "root" && "$mode" = 4755 ]]; then
      printf '%s' "$p"
      return 0
    fi
  done
  return 1
}

maybe_update_then_run() {
  local app="$TARGET_DIR/$APP_BASENAME.AppImage"

  (
    set -Eeuo pipefail
    exec 9>"$TARGET_DIR/.update.lock"
    flock -n 9 || exit 0
    if fetch_release_info; then
      local have_ver
      have_ver="$(get_current_version)"
      if need_update "$have_ver" "$REMOTE_TAG"; then
        download_and_switch || true
      fi
    fi
  ) || log "Update check failed; proceeding without updating."

  if [[ ! -e /dev/fuse || ! -r /dev/fuse ]]; then
    export APPIMAGE_EXTRACT_AND_RUN=1
  fi

  # Build extra flags (if any)
  EXTRA_ELECTRON_ARGS=()
  if [[ -n "$PROFILE_SLUG" ]]; then
    while IFS= read -r f; do
      [[ -n "$f" ]] && EXTRA_ELECTRON_ARGS+=( "$f" )
    done < <( make_profile_flags "$PROFILE_SLUG" )
  fi

  # Decide which Chromium sandbox to use
  if apparmor_blocks_userns; then
    # AppArmor blocks userns: try setuid sandbox helper; else no-sandbox
    if SANDBOX_BIN="$(find_system_chrome_sandbox)"; then
      export CHROME_DEVEL_SANDBOX="$SANDBOX_BIN"
      # No extra flags needed; Chromium will use setuid sandbox via CHROME_DEVEL_SANDBOX
      log "Using setuid sandbox helper at $SANDBOX_BIN"
    else
      log "AppArmor blocks userns and no setuid helper found; adding --no-sandbox (reduced security)."
      EXTRA_ELECTRON_ARGS+=( "--no-sandbox" )
    fi
  else
    # AppArmor not blocking: if userns allowed, prefer userns sandbox; else fallback to no-sandbox
    if userns_clone_enabled; then
      # Tell Chromium to NOT try setuid; use userns sandbox
      EXTRA_ELECTRON_ARGS+=( "--disable-setuid-sandbox" )
    else
      log "kernel.unprivileged_userns_clone=0; adding --no-sandbox (reduced security)."
      EXTRA_ELECTRON_ARGS+=( "--no-sandbox" )
    fi
  fi

  if [[ -x "$app" ]]; then
    exec "$app" --ssoInTuneEnabled=true "${EXTRA_ELECTRON_ARGS[@]}" "${PASSTHRU[@]}"
  else
    die "No cached AppImage found at $app and update attempt failed."
  fi
}

main() {
  for need in "$CURL_BIN"; do
    have_cmd "$need" || die "Required tool missing: $need"
  done
  choose_dir
  maybe_update_then_run
}

main
