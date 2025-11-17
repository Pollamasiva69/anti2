#!/bin/bash
#
# HTTP Flood Attack Simulation
# Tests HTTP flood protection
#

TARGET_URL="${1:-http://localhost/}"
CONCURRENT="${2:-100}"
REQUESTS="${3:-10000}"

echo "=== HTTP Flood Test ==="
echo "Target: $TARGET_URL"
echo "Concurrent: $CONCURRENT"
echo "Total Requests: $REQUESTS"
echo ""

if ! command -v ab &> /dev/null; then
    echo "Error: apache2-utils not installed"
    echo "Install with: sudo apt-get install apache2-utils"
    exit 1
fi

echo "Starting HTTP flood attack simulation..."
echo ""

ab -n "$REQUESTS" -c "$CONCURRENT" "$TARGET_URL"

echo ""
echo "Test complete"
echo "Check system logs for HTTP flood detection"
