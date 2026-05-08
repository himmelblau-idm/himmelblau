#!/usr/bin/env bash
set -Eeuo pipefail

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

  # Derive a class slug without a trailing "-<number>" (e.g., "Word-2" -> "Word")
  local class_slug="$slug"
  if [[ "$class_slug" =~ ^(.+)-([0-9]+)$ ]]; then
    class_slug="${BASH_REMATCH[1]}"
  fi

  printf -- "--user-data-dir=%s\n--class=%s\n" "$dir" "o365-$class_slug"
}

main() {
  # Build extra flags (if any)
  EXTRA_ELECTRON_ARGS=()
  if [[ -n "$PROFILE_SLUG" ]]; then
    while IFS= read -r f; do
      [[ -n "$f" ]] && EXTRA_ELECTRON_ARGS+=("$f")
    done < <(make_profile_flags "$PROFILE_SLUG")
  fi

  exec teams-for-linux --ssoInTuneEnabled=true "${EXTRA_ELECTRON_ARGS[@]}" "${PASSTHRU[@]}"
}

main
