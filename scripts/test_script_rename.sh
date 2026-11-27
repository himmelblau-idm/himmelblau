#!/bin/sh
case "$1" in
    jdoe) printf 'john.doe@example.com\n' ;;
    *) printf '%s\n' "$1" ;;
esac
