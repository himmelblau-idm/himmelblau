#!/bin/sh
# Functional test for the update-nss helper. No build or package required:
# it drives the helper against a fixture nsswitch.conf under DPKG_ROOT.
set -eu

helper="$(CDPATH='' cd "$(dirname "$0")/../src" && pwd)/update-nss"
work="$(mktemp -d "${TMPDIR:-.}/nss-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

conf="$work/etc/nsswitch.conf"
fail=0

fixture() { mkdir -p "$work/etc"; printf '%s\n' "$@" >"$conf"; }
dbline() { [ -f "$conf" ] && awk -v d="$1:" '$1==d' "$conf" || true; }
run() { DPKG_ROOT="$work" "$helper" "$1"; }
check() {
  if [ "$2" = "$3" ]; then
    printf 'ok   - %s\n' "$1"
  else
    printf 'FAIL - %s\n       expected: [%s]\n       actual:   [%s]\n' "$1" "$2" "$3"
    fail=1
  fi
}

fixture \
  "passwd:         files systemd" \
  "group:          files systemd" \
  "shadow:         files" \
  "gshadow:        files" \
  "hosts:          files dns" \
  "initgroups:     files"

run add
check "add appends to passwd"     "passwd:         files systemd himmelblau" "$(dbline passwd)"
check "add appends to group"      "group:          files systemd himmelblau" "$(dbline group)"
check "add appends to shadow"     "shadow:         files himmelblau"         "$(dbline shadow)"
check "add appends to initgroups" "initgroups:     files himmelblau"         "$(dbline initgroups)"
check "add leaves hosts alone"    "hosts:          files dns"                "$(dbline hosts)"
check "add leaves gshadow alone"  "gshadow:        files"                    "$(dbline gshadow)"

run add
check "add is idempotent" "passwd:         files systemd himmelblau" "$(dbline passwd)"

run remove
check "remove restores passwd"     "passwd:         files systemd" "$(dbline passwd)"
check "remove restores group"      "group:          files systemd" "$(dbline group)"
check "remove restores shadow"     "shadow:         files"         "$(dbline shadow)"
check "remove restores initgroups" "initgroups:     files"         "$(dbline initgroups)"

run remove
check "remove is idempotent" "passwd:         files systemd" "$(dbline passwd)"

fixture "passwd:         files himmelblau systemd himmelblau_extra"
run remove
check "remove takes only the exact service" "passwd:         files systemd himmelblau_extra" "$(dbline passwd)"
run add
check "add ignores a lookalike token" "passwd:         files systemd himmelblau_extra himmelblau" "$(dbline passwd)"

rm -f "$conf"
mkdir -p "$work/usr/etc"
printf 'passwd: files\n' >"$work/usr/etc/nsswitch.conf"
run add
check "add seeds /etc from /usr/etc" "passwd: files himmelblau" "$(dbline passwd)"

rm -f "$conf"
rm -rf "${work:?}/usr"
run remove
check "remove is a no-op without a conf" "" "$(dbline passwd)"

if [ "$fail" -eq 0 ]; then
  echo "All tests passed"
else
  echo "Some tests failed"
  exit 1
fi
