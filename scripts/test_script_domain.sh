#!/bin/sh
case "$1" in
    *@*) printf '%s\n' "$1" ;;
    *) printf '%s@example.com\n' "$1" ;;
esac
