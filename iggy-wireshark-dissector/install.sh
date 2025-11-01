#!/bin/bash
# IGGY Wireshark Dissector Installation Script
# Supports macOS and Linux

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Darwin*)    PLATFORM="macOS";;
    Linux*)     PLATFORM="Linux";;
    *)          PLATFORM="UNKNOWN";;
esac

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}IGGY Wireshark Dissector Installer${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Detected platform: ${GREEN}${PLATFORM}${NC}"
echo ""

# Check if iggy.lua exists
if [ ! -f "iggy.lua" ]; then
    echo -e "${RED}Error: iggy.lua not found in current directory${NC}"
    echo "Please run this script from the iggy-wireshark-dissector directory"
    exit 1
fi

# Determine plugin directory
if [ "$PLATFORM" = "macOS" ]; then
    PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
    WIRESHARK_PATH="/Applications/Wireshark.app"
    WIRESHARK_BIN="$WIRESHARK_PATH/Contents/MacOS/Wireshark"
    INTERFACE="lo0"
elif [ "$PLATFORM" = "Linux" ]; then
    # Try multiple locations for Linux
    if [ -d "$HOME/.local/lib/wireshark/plugins" ] || [ ! -d "$HOME/.config/wireshark" ]; then
        PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
    else
        PLUGIN_DIR="$HOME/.config/wireshark/plugins"
    fi
    WIRESHARK_BIN="wireshark"
    INTERFACE="lo"
else
    echo -e "${RED}Unsupported platform: ${PLATFORM}${NC}"
    echo "Please install manually following the README.md"
    exit 1
fi

echo "Installation location: ${YELLOW}${PLUGIN_DIR}${NC}"
echo ""

# Check if Wireshark is installed
if [ "$PLATFORM" = "macOS" ]; then
    if [ ! -d "$WIRESHARK_PATH" ]; then
        echo -e "${YELLOW}Warning: Wireshark not found at ${WIRESHARK_PATH}${NC}"
        echo "Please install Wireshark from: https://www.wireshark.org/download.html"
        echo ""
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        VERSION=$("$WIRESHARK_BIN" --version 2>/dev/null | head -1 || echo "Unknown")
        echo -e "Wireshark: ${GREEN}${VERSION}${NC}"
    fi
elif [ "$PLATFORM" = "Linux" ]; then
    if ! command -v wireshark &> /dev/null; then
        echo -e "${YELLOW}Warning: Wireshark not found in PATH${NC}"
        echo "Please install Wireshark using your package manager"
        echo ""
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        VERSION=$(wireshark --version 2>/dev/null | head -1 || echo "Unknown")
        echo -e "Wireshark: ${GREEN}${VERSION}${NC}"
    fi
fi

echo ""
echo "Installing IGGY dissector..."
echo ""

# Create plugin directory
echo -e "Creating plugin directory: ${PLUGIN_DIR}"
mkdir -p "$PLUGIN_DIR"

# Copy dissector
echo -e "Copying iggy.lua..."
cp iggy.lua "$PLUGIN_DIR/"

# Verify installation
if [ -f "$PLUGIN_DIR/iggy.lua" ]; then
    SIZE=$(du -h "$PLUGIN_DIR/iggy.lua" | cut -f1)
    echo -e "${GREEN}✓${NC} Installation successful!"
    echo ""
    echo -e "Installed: ${GREEN}${PLUGIN_DIR}/iggy.lua${NC} (${SIZE})"
else
    echo -e "${RED}✗ Installation failed${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Next steps
echo -e "${BLUE}Next Steps:${NC}"
echo ""
echo "1. Start (or restart) Wireshark:"
if [ "$PLATFORM" = "macOS" ]; then
    echo -e "   ${YELLOW}open /Applications/Wireshark.app${NC}"
else
    echo -e "   ${YELLOW}wireshark${NC}"
fi
echo ""
echo "2. Or reload Lua plugins in running Wireshark:"
echo "   Analyze → Reload Lua Plugins"
if [ "$PLATFORM" = "macOS" ]; then
    echo -e "   Shortcut: ${YELLOW}Cmd+Shift+L${NC}"
else
    echo -e "   Shortcut: ${YELLOW}Ctrl+Shift+L${NC}"
fi
echo ""
echo "3. Verify installation:"
echo "   Help → About Wireshark → Plugins tab"
echo "   Search for: iggy"
echo ""
echo "4. Capture IGGY traffic:"
if [ "$PLATFORM" = "macOS" ]; then
    echo -e "   ${YELLOW}sudo tcpdump -i lo0 -w iggy.pcap 'tcp port 8090'${NC}"
else
    echo -e "   ${YELLOW}sudo tcpdump -i lo -w iggy.pcap 'tcp port 8090'${NC}"
fi
echo ""
echo "5. Use display filter in Wireshark:"
echo -e "   ${YELLOW}iggy${NC}"
echo ""

# Optional: Quick test
echo -e "${BLUE}Quick Test:${NC}"
echo ""
echo "Want to see example test messages? Run:"
echo -e "   ${YELLOW}cd test && python3 test_protocol.py${NC}"
echo ""
echo "For full documentation, see:"
echo "   README.md"
echo "   test/README.md"
echo ""

echo -e "${GREEN}Happy packet analyzing! 🎉${NC}"
