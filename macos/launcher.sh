#!/bin/bash
#
# WiFi Bruteforce Launcher
# Automatically requests sudo privileges if needed
#

APP_NAME="WiFi Bruteforce"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BINARY="$SCRIPT_DIR/bruteforce-wifi"

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    osascript -e "display dialog \"Binary not found at: $BINARY\" buttons {\"OK\"} default button 1 with icon stop"
    exit 1
fi

# Check if we're already running as root
if [ "$EUID" -eq 0 ]; then
    # Already root, just run the app
    exec "$BINARY"
else
    # Not root - show dialog and request sudo
    # Use osascript with do shell script to run with admin privileges
    osascript <<EOF 2>/dev/null
tell application "System Events"
    activate
    set dialogResult to display dialog "WiFi Bruteforce requires administrator privileges to capture WiFi packets.\\n\\nYou will be prompted for your password." with title "$APP_NAME" buttons {"Cancel", "Continue"} default button "Continue" with icon caution
    if button returned of dialogResult is "Continue" then
        try
            do shell script "cd '$SCRIPT_DIR' && exec '$BINARY'" with administrator privileges
        on error errorMessage
            if errorMessage does not contain "User cancelled" then
                display dialog "Error: " & errorMessage buttons {"OK"} default button 1 with icon stop
            end if
        end try
    end if
end tell
EOF
fi
