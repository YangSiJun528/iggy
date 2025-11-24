# Makefile for Iggy Wireshark C dissector
BUILD_DIR = build
WIRESHARK_PLUGIN_DIR ?= $(HOME)/.local/lib/wireshark/plugins

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LIB_EXT = so
else ifeq ($(UNAME_S),Linux)
    LIB_EXT = so
else
    LIB_EXT = dll
endif

.PHONY: all build install clean uninstall help

all: build

build:
	@echo "Building Iggy C dissector..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. && cmake --build .

install: build
	@echo "Installing to $(WIRESHARK_PLUGIN_DIR)..."
	@mkdir -p $(WIRESHARK_PLUGIN_DIR)
	@cp $(BUILD_DIR)/iggy.$(LIB_EXT) $(WIRESHARK_PLUGIN_DIR)/
	@echo "Installed! Restart Wireshark to load the plugin."

clean:
	@rm -rf $(BUILD_DIR)

uninstall:
	@rm -f $(WIRESHARK_PLUGIN_DIR)/iggy.$(LIB_EXT)
	@echo "Plugin uninstalled."

help:
	@echo "Iggy Wireshark C Dissector"
	@echo ""
	@echo "Targets:"
	@echo "  make           - Build the plugin"
	@echo "  make install   - Install to Wireshark"
	@echo "  make uninstall - Remove from Wireshark"
	@echo "  make clean     - Clean build artifacts"
