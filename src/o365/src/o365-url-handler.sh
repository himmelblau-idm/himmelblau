#!/usr/bin/env bash
set -euo pipefail

# Accept %u/%U style invocations; take the first URL-like arg.
URL=""
for a in "$@"; do
  case "$a" in
    http://*|https://*) URL="$a"; break ;;
  esac
done
[[ -n "$URL" ]] || exit 0  # nothing to do

O365_LAUNCHER="/usr/bin/o365-multi"

urldecode() {
  # POSIX-safe URL decode
  local data="${1//+/ }"
  printf '%b' "${data//%/\\x}"
}

# Extract a query parameter (first match)
get_qs_param() {
  # $1=url, $2=key
  local q="${1#*\?}"; q="${q%%#*}"
  # split on '&', find key=
  awk -v RS='&' -v key="$2" '
    $0 ~ "^"key"=" {sub("^"key"=",""); print; exit}
  ' <<<"$q"
}

FILE_PARAM_RAW="$(get_qs_param "$URL" "file" || true)"
FILE_PARAM="$(urldecode "$FILE_PARAM_RAW" 2>/dev/null || true)"

# Grab lowercase extension from file param (if any)
EXT=""
if [[ -n "$FILE_PARAM" && "$FILE_PARAM" == *.* ]]; then
  EXT="${FILE_PARAM##*.}"
  EXT="${EXT,,}"
fi

# Map extensions -> app profile/icon/title
profile="" ; icon="" ; title=""
case "$EXT" in
  doc|docx|docm|dot|dotx|dotm)
    profile="Word"
    icon="/usr/share/icons/hicolor/256x256/apps/o365-word.png"
    title="Word"
    ;;
  xls|xlsx|xlsm|xlsb|xlt|xltx|xltm|csv)
    profile="Excel"
    icon="/usr/share/icons/hicolor/256x256/apps/o365-excel.png"
    title="Excel"
    ;;
  ppt|pptx|pptm|pps|ppsx|pot|potx|potm)
    profile="PowerPoint"
    icon="/usr/share/icons/hicolor/256x256/apps/o365-powerpoint.png"
    title="PowerPoint"
    ;;
esac

if [[ -n "$profile" ]]; then
  exec "$O365_LAUNCHER" \
    --url="$URL" \
    --profile="$profile" \
    --appIcon="$icon" \
    --appTitle="$title" \
    --closeAppOnCross=true \
    --trayIconEnabled=false
else
  # Unknown/extension-less (e.g., many OneNote links) -> let the browser handle it
  exec xdg-open "$URL"
fi
