#!/usr/bin/env bash
set -euo pipefail

# Accept %u/%U style invocations; take the first URL-like arg.
URL=""
for a in "$@"; do
  case "${a,,}" in
    http://*|https://*) URL="$a"; break ;;
  esac
done
[[ -n "$URL" ]] || exit 0  # nothing to do

O365_LAUNCHER="/usr/bin/o365-multi"

# The launcher hands --url to an Electron app whose window exposes Node's
# require() to page scripts, so loading an untrusted page there is remote code
# execution as the desktop user. Only origins on these lists may be opened that
# way; everything else goes to the browser. The file= query parameter below is
# attacker controlled and is used solely to pick an app profile -- it is never
# evidence that a URL is trusted.

# Hosts that must match exactly.
O365_ALLOWED_HOSTS=(
  outlook.office.com
  outlook.office365.com
  outlook.live.com
  teams.microsoft.com
  www.office.com
  m365.cloud.microsoft
  word.cloud.microsoft
  excel.cloud.microsoft
  powerpoint.cloud.microsoft
  onedrive.live.com
  # GCC High / DoD
  outlook.office365.us
  gov.teams.microsoft.us
  dod.teams.microsoft.us
  # 21Vianet (China)
  partner.outlook.cn
  teams.microsoft.cn
)

# Parent domains under which exactly one tenant label is accepted, e.g.
# contoso.sharepoint.com. Nested subdomains are not accepted.
O365_ALLOWED_TENANT_DOMAINS=(
  sharepoint.com
  officeapps.live.com
  # GCC High / DoD
  sharepoint.us
  sharepoint-mil.us
  # 21Vianet (China)
  sharepoint.cn
  # Germany
  sharepoint.de
)

# Echo the lowercase host of $1 when it is unambiguously an https origin,
# otherwise fail. Everything ambiguous is rejected rather than guessed at.
https_origin_host() {
  local url="$1" authority host

  # The scheme must be exactly https.
  case "${url,,}" in
    https://*) ;;
    *) return 1 ;;
  esac

  # The authority ends at the first '/', '?' or '#'.
  authority="${url:8}"
  authority="${authority%%[/?#]*}"

  # Reject userinfo (https://word.cloud.microsoft@evil.example/). Browsers also
  # normalize a backslash to '/', which would end the authority early; rather
  # than replicate that, the host pattern below rejects the backslash outright.
  if [[ "$authority" == *@* ]]; then
    return 1
  fi

  host="$authority"
  # An https origin has no port or port 443.
  if [[ "$host" == *:* ]]; then
    [[ "${host##*:}" == "443" ]] || return 1
    host="${host%:*}"
  fi

  host="${host,,}"
  host="${host%.}"  # trailing root label

  # A plain dotted DNS name and nothing else. This rejects percent-encoding,
  # IPv6 literals, embedded whitespace or control characters, and non-ASCII
  # homographs before any comparison happens.
  [[ "$host" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || return 1

  printf '%s' "$host"
}

host_is_allowed() {
  local host="$1" allowed tenant

  for allowed in "${O365_ALLOWED_HOSTS[@]}"; do
    if [[ "$host" == "$allowed" ]]; then
      return 0
    fi
  done

  for allowed in "${O365_ALLOWED_TENANT_DOMAINS[@]}"; do
    # The leading '.' anchors the match on a label boundary, so neither
    # evilsharepoint.com nor sharepoint.com.evil.example can match.
    if [[ "$host" != *".$allowed" ]]; then
      continue
    fi
    tenant="${host%".$allowed"}"
    # Exactly one tenant label.
    if [[ -n "$tenant" && "$tenant" != *.* ]]; then
      return 0
    fi
  done

  return 1
}

HOST="$(https_origin_host "$URL" || true)"
if [[ -z "$HOST" ]] || ! host_is_allowed "$HOST"; then
  exec xdg-open "$URL"
fi

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
