# Simple Makefile for building Iggy Wireshark dissector
#
# Usage:
#   make            - Build the plugin
#   make install    - Install to Wireshark plugin directory
#   make clean      - Clean build artifacts
#   make help       - Show this help

# Configuration
PLUGIN_NAME = iggy
WIRESHARK_PLUGIN_DIR ?= $(HOME)/.local/lib/wireshark/plugins
BUILD_DIR = build

# Detect OS
UNAME_S := $(shell uname -s)

# Platform-specific settings
ifeq ($(UNAME_S),Darwin)
    LIB_EXT = so
else ifeq ($(UNAME_S),Linux)
    LIB_EXT = so
else
    LIB_EXT = dll
endif

PLUGIN_FILE = $(BUILD_DIR)/$(PLUGIN_NAME).$(LIB_EXT)

.PHONY: all build install clean help test

all: build

build:
	@echo "Building Iggy dissector plugin..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. && cmake --build .

install: build
	@echo "Installing plugin to $(WIRESHARK_PLUGIN_DIR)..."
	@mkdir -p $(WIRESHARK_PLUGIN_DIR)
	@if [ -f "$(PLUGIN_FILE)" ]; then \
		cp $(PLUGIN_FILE) $(WIRESHARK_PLUGIN_DIR)/; \
		echo "Plugin installed successfully!"; \
		echo "Restart Wireshark or reload plugins (Analyze → Reload Lua Plugins)"; \
	else \
		echo "Error: Plugin file not found at $(PLUGIN_FILE)"; \
		exit 1; \
	fi

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)

uninstall:
	@echo "Removing plugin from $(WIRESHARK_PLUGIN_DIR)..."
	@rm -f $(WIRESHARK_PLUGIN_DIR)/$(PLUGIN_NAME).$(LIB_EXT)
	@rm -f $(WIRESHARK_PLUGIN_DIR)/$(PLUGIN_NAME).so
	@echo "Plugin uninstalled."

help:
	@echo "Iggy Wireshark Dissector Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make           - Build the plugin"
	@echo "  make install   - Install to Wireshark plugin directory"
	@echo "  make uninstall - Remove plugin from Wireshark"
	@echo "  make clean     - Clean build artifacts"
	@echo "  make help      - Show this help"
	@echo ""
	@echo "Environment Variables:"
	@echo "  WIRESHARK_PLUGIN_DIR - Override default plugin directory"
	@echo "                         (default: ~/.local/lib/wireshark/plugins)"

test:
	@echo "Running dissector tests..."
	@cd .. && cargo test -p wireshark --features protocol-tests
