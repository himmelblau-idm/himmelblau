#!/usr/bin/env bash
#
# o365-browser-launcher.sh - Launch Microsoft 365 apps in a browser web app window
#
# Copyright (C) David Mulder <dmulder@samba.org> 2025
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

set -euo pipefail

# Browser detection order: Edge > Chrome > Chromium
# Edge has best M365 compatibility, Chrome is excellent, Chromium is fallback
BROWSERS=(
  "/opt/microsoft/msedge/microsoft-edge"
  "/usr/bin/microsoft-edge"
  "/usr/bin/google-chrome-stable"
  "/usr/bin/google-chrome"
  "/usr/bin/chromium-browser"
  "/usr/bin/chromium"
)

# Check if URL argument provided
if [ $# -lt 1 ]; then
  echo "Usage: $0 <url> [additional-args...]" >&2
  exit 1
fi

# Find first available browser and launch
for browser in "${BROWSERS[@]}"; do
  if [ -x "$browser" ]; then
    # Launch as web app: --new-window creates new instance, --app=<url> provides minimal chrome
    exec "$browser" --new-window --app="$1" "${@:2}"
  fi
done

# No browser found
echo "Error: No supported browser found (Microsoft Edge, Google Chrome, or Chromium)" >&2
echo "Please install one of the following:" >&2
echo "  - Microsoft Edge:  https://www.microsoft.com/edge" >&2
echo "  - Google Chrome:   https://www.google.com/chrome" >&2
echo "  - Chromium:        via your package manager (apt/dnf/zypper)" >&2
exit 1
