#!/bin/bash
# Himmelblau Embedded Browser Container Entry Point
# Starts Xvfb, x11vnc, and Firefox for authentication

set -e

# Get URL from command line or environment
URL="${1:-${TARGET_URL:-https://microsoft.com/devicelogin}}"
STATUS_FILE="/tmp/browser_status"

echo "Starting Himmelblau browser session for URL: $URL"

# Clean up any existing X server
rm -f /tmp/.X1-lock /tmp/.X11-unix/X1 2>/dev/null || true

# Start virtual framebuffer
echo "Starting Xvfb..."
Xvfb :1 -screen 0 ${VNC_RESOLUTION:-800x600x24} -ac +extension GLX +render -noreset &
XVFB_PID=$!

# Wait for Xvfb to start
sleep 2

# Check if Xvfb is running
if ! kill -0 $XVFB_PID 2>/dev/null; then
    echo "ERROR: Xvfb failed to start"
    exit 1
fi

echo "Xvfb started with PID $XVFB_PID"

# Start VNC server
echo "Starting x11vnc..."
x11vnc -display :1 \
    -forever \
    -shared \
    -nopw \
    -rfbport ${VNC_PORT:-5900} \
    -xkb \
    -noxrecord \
    -noxfixes \
    -noxdamage \
    -wait 5 \
    -defer 5 \
    -bg

# Wait for VNC to start
sleep 1

echo "VNC server started on port ${VNC_PORT:-5900}"

# Start the browser session monitoring script in background
python3 /home/browseruser/browser-session.py "$URL" "$STATUS_FILE" &
MONITOR_PID=$!

# Start Firefox
echo "Starting Firefox with URL: $URL"
firefox \
    --new-window \
    --kiosk \
    --no-remote \
    "$URL" &
FIREFOX_PID=$!

echo "Firefox started with PID $FIREFOX_PID"

# Function to handle cleanup
cleanup() {
    echo "Cleaning up..."
    kill $FIREFOX_PID 2>/dev/null || true
    kill $MONITOR_PID 2>/dev/null || true
    killall x11vnc 2>/dev/null || true
    kill $XVFB_PID 2>/dev/null || true
    echo "Cleanup complete"
}

# Set up signal handlers
trap cleanup EXIT SIGTERM SIGINT

# Monitor for completion
echo "Monitoring for authentication completion..."
while true; do
    # Check if Firefox is still running
    if ! kill -0 $FIREFOX_PID 2>/dev/null; then
        echo "Firefox exited"
        break
    fi

    # Check status file for completion
    if [ -f "$STATUS_FILE" ]; then
        STATUS=$(cat "$STATUS_FILE")
        if [ "$STATUS" = "SUCCESS" ]; then
            echo "Authentication successful!"
            sleep 2
            break
        elif [ "$STATUS" = "FAILED" ]; then
            echo "Authentication failed!"
            sleep 2
            break
        fi
    fi

    sleep 2
done

echo "Browser session ended"
