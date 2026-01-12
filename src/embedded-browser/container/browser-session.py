#!/usr/bin/env python3
"""
Himmelblau Browser Session Monitor

Monitors the Firefox window for authentication completion patterns.
Uses xdotool to inspect window titles and content.
"""

import subprocess
import sys
import time
import os
import re

# Success patterns to look for in window titles or page content
SUCCESS_PATTERNS = [
    "you have signed in",
    "you're signed in",
    "you are signed in",
    "close this window",
    "authentication successful",
    "successfully authenticated",
    "you can close this",
    "sign-in complete",
    "login successful",
]

# Failure patterns
FAILURE_PATTERNS = [
    "authentication failed",
    "access denied",
    "sign-in failed",
    "login failed",
    "invalid code",
    "code expired",
    "error occurred",
]

def get_window_title():
    """Get the title of the active Firefox window."""
    try:
        result = subprocess.run(
            ["xdotool", "search", "--name", "Firefox"],
            capture_output=True,
            text=True,
            timeout=5
        )
        window_ids = result.stdout.strip().split('\n')

        for window_id in window_ids:
            if window_id:
                result = subprocess.run(
                    ["xdotool", "getwindowname", window_id],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return result.stdout.strip().lower()
    except Exception as e:
        print(f"Error getting window title: {e}", file=sys.stderr)
    return ""

def check_for_completion(title):
    """Check if the window title indicates completion."""
    for pattern in SUCCESS_PATTERNS:
        if pattern in title:
            return "SUCCESS"

    for pattern in FAILURE_PATTERNS:
        if pattern in title:
            return "FAILED"

    return None

def write_status(status_file, status):
    """Write status to the status file."""
    try:
        with open(status_file, 'w') as f:
            f.write(status)
        print(f"Status written: {status}")
    except Exception as e:
        print(f"Error writing status: {e}", file=sys.stderr)

def main():
    if len(sys.argv) < 2:
        print("Usage: browser-session.py <url> [status_file]", file=sys.stderr)
        sys.exit(1)

    url = sys.argv[1]
    status_file = sys.argv[2] if len(sys.argv) > 2 else "/tmp/browser_status"

    print(f"Monitoring browser session for URL: {url}")
    print(f"Status file: {status_file}")

    # Wait for Firefox to start
    time.sleep(5)

    check_count = 0
    max_checks = 300  # 5 minutes at 1 check per second

    while check_count < max_checks:
        title = get_window_title()

        if title:
            status = check_for_completion(title)
            if status:
                print(f"Authentication {status.lower()}!")
                write_status(status_file, status)
                return

        check_count += 1
        time.sleep(1)

    # Timeout
    print("Session timed out")
    write_status(status_file, "TIMEOUT")

if __name__ == "__main__":
    main()
