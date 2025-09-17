#!/usr/bin/env bash
set -euo pipefail

# Minimal sub-profile picker for teams-for-linux based O365 wrapper
# Usage: o365-subprofile --profile=Word [other args...]
# It will pick Word-1, Word-2, ... (first free) and replace --profile accordingly.

O365_BIN=${O365_BIN:-/usr/bin/o365}
MAX=${O365_SUBPROFILES_MAX:-8}

# 1) get base profile from args
BASE=""
for a in "$@"; do
  case "$a" in
    --profile=*) BASE="${a#--profile=}" ;;
  esac
done
[[ -n "$BASE" ]] || { echo "o365-subprofile: need --profile=BASE" >&2; exit 2; }

# If already suffixed, just run as-is
if [[ "$BASE" =~ .+-[0-9]+$ ]]; then
  exec "$O365_BIN" "$@"
fi

# 2) collect used numbers by scanning running commands for teams-for-linux/AppImage
used_numbers() {
  if command -v pgrep >/dev/null 2>&1; then
    # -f to match full cmdline, -u to restrict to current user
    pgrep -af -u "$UID" 'teams-for-linux|Teams-for-Linux\.AppImage' 2>/dev/null \
      | grep -E -- "--class=o365-${BASE}-|--user-data-dir=.*/${BASE}-|--profile=${BASE}-" \
      | grep -oE "${BASE}-[0-9]+" \
      | sed -E 's/.*-([0-9]+)$/\1/' \
      | sort -n | uniq
  else
    ps -eo pid,args | grep -E 'teams-for-linux|Teams-for-Linux\.AppImage' | grep -v grep \
      | grep -E -- "--class=o365-${BASE}-|--user-data-dir=.*/${BASE}-|--profile=${BASE}-" \
      | grep -oE "${BASE}-[0-9]+" \
      | sed -E 's/.*-([0-9]+)$/\1/' \
      | sort -n | uniq
  fi
}

used="$(used_numbers || true)"
pick=1
for ((i=1; i<=MAX; i++)); do
  if ! grep -qx "$i" <<<"$used"; then pick="$i"; break; fi
done
[[ "$pick" -le "$MAX" ]] || { echo "o365-subprofile: all $MAX ${BASE} sub-profiles in use" >&2; exit 3; }

# 3) replace --profile with the chosen suffix and exec
newargs=()
for a in "$@"; do
  case "$a" in
    --profile=*) newargs+=("--profile=${BASE}-${pick}") ;;
    *)           newargs+=("$a") ;;
  esac
done

exec "$O365_BIN" "${newargs[@]}"
