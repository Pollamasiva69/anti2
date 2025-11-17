#!/bin/bash
#
# DDoS Protection System - Installation Script
# Installs the system system-wide
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

echo -e "${GREEN}DDoS Protection System - Installation${NC}"
echo "======================================"
echo ""

# Install directories
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/ddos-protect"
LOG_DIR="/var/log/ddos-protect"
SHARE_DIR="/usr/share/ddos-protect"

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$SHARE_DIR"
mkdir -p "$SHARE_DIR/ebpf"
mkdir -p "$SHARE_DIR/web"

# Install binary
echo -e "${YELLOW}Installing binary...${NC}"
if [ -f "bin/ddos-protect" ]; then
    install -m 755 bin/ddos-protect "$INSTALL_DIR/ddos-protect"
    echo "Installed: $INSTALL_DIR/ddos-protect"
else
    echo -e "${RED}Error: Binary not found. Run 'make' first.${NC}"
    exit 1
fi

# Install configuration
echo -e "${YELLOW}Installing configuration...${NC}"
if [ ! -f "$CONFIG_DIR/default.conf" ]; then
    install -m 644 config/default.conf "$CONFIG_DIR/default.conf"
    echo "Installed: $CONFIG_DIR/default.conf"
else
    echo "Configuration already exists, skipping..."
fi

# Install eBPF programs
echo -e "${YELLOW}Installing eBPF programs...${NC}"
if [ -f "ebpf/xdp_filter.o" ]; then
    install -m 644 ebpf/xdp_filter.o "$SHARE_DIR/ebpf/xdp_filter.o"
    echo "Installed: $SHARE_DIR/ebpf/xdp_filter.o"
fi

# Install web dashboard
echo -e "${YELLOW}Installing web dashboard...${NC}"
if [ -d "web" ]; then
    cp -r web/* "$SHARE_DIR/web/"
    echo "Installed: $SHARE_DIR/web/"
fi

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
install -m 644 scripts/systemd_service /etc/systemd/system/ddos-protect.service

# Reload systemd
systemctl daemon-reload

# Set permissions
echo -e "${YELLOW}Setting permissions...${NC}"
chown -R root:root "$CONFIG_DIR"
chown -R root:root "$SHARE_DIR"
chmod 755 "$LOG_DIR"

# Create user (if doesn't exist)
if ! id -u ddos-protect >/dev/null 2>&1; then
    echo -e "${YELLOW}Creating service user...${NC}"
    useradd -r -s /bin/false -d /nonexistent ddos-protect || true
fi

# Check dependencies
echo -e "${YELLOW}Checking dependencies...${NC}"

check_package() {
    if ! dpkg -l | grep -q "^ii  $1"; then
        echo -e "${YELLOW}Warning: Package '$1' not installed${NC}"
        echo "  Install with: apt-get install $1"
    else
        echo -e "${GREEN}✓${NC} $1"
    fi
}

check_package "libpcap-dev"
check_package "libjansson-dev"
check_package "libmicrohttpd-dev"

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Configuration file: $CONFIG_DIR/default.conf"
echo "Log file: $LOG_DIR/ddos-protect.log"
echo ""
echo "To start the service:"
echo "  systemctl start ddos-protect"
echo ""
echo "To enable on boot:"
echo "  systemctl enable ddos-protect"
echo ""
echo "To view status:"
echo "  systemctl status ddos-protect"
echo ""
echo "To view logs:"
echo "  journalctl -u ddos-protect -f"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "1. Edit $CONFIG_DIR/default.conf to configure your network interface"
echo "2. Change the API auth token before enabling the API"
echo "3. Review firewall rules and thresholds"
echo ""
