# Building the Iggy C Dissector

This document describes how to build and install the Iggy Wireshark dissector written in C.

## Prerequisites

### macOS

```bash
# Install Wireshark (includes development headers)
brew install wireshark

# Or download from https://www.wireshark.org/download.html
```

### Linux (Ubuntu/Debian)

```bash
sudo apt-get install wireshark-dev libglib2.0-dev cmake build-essential
```

### Linux (Fedora/RHEL)

```bash
sudo dnf install wireshark-devel glib2-devel cmake gcc
```

### Windows

1. Download and install Wireshark from https://www.wireshark.org/download.html
2. Install Visual Studio 2019 or later with C++ build tools
3. Install CMake from https://cmake.org/download/

**Note**: Out-of-tree builds on Windows may not work as Windows builds don't typically include header packages. For Windows, consider building in-tree with Wireshark source.

## Quick Build (Using Makefile)

The easiest way to build and install:

```bash
cd wireshark/

# Build the plugin
make

# Install to Wireshark plugin directory
make install

# Clean build artifacts
make clean
```

## Manual Build (Using CMake)

### Out-of-Tree Build (Standalone Plugin)

This is the recommended approach for development:

```bash
cd wireshark/
mkdir build
cd build

# Configure
cmake ..

# Build
cmake --build .

# Install
cmake --install . --prefix ~/.local
```

### In-Tree Build (With Wireshark Source)

To build as part of Wireshark source tree:

1. Clone Wireshark source:
```bash
git clone https://gitlab.com/wireshark/wireshark.git
cd wireshark
```

2. Copy plugin files:
```bash
mkdir -p plugins/epan/iggy
cp /path/to/iggy/wireshark/*.c plugins/epan/iggy/
cp /path/to/iggy/wireshark/CMakeLists.txt plugins/epan/iggy/
```

3. Configure Wireshark to include the plugin:
```bash
# Edit CMakeListsCustom.txt in Wireshark root
echo 'set(CUSTOM_PLUGIN_SRC_DIR plugins/epan/iggy)' >> CMakeListsCustom.txt
```

4. Build Wireshark:
```bash
mkdir build
cd build
cmake ..
make
```

## Installation

### Plugin Directory Locations

The plugin should be installed to one of these directories:

**macOS:**
- Personal: `~/.local/lib/wireshark/plugins/`
- System: `/Applications/Wireshark.app/Contents/PlugIns/wireshark/`

**Linux:**
- Personal: `~/.local/lib/wireshark/plugins/`
- System: `/usr/lib/wireshark/plugins/` or `/usr/local/lib/wireshark/plugins/`

**Windows:**
- Personal: `%APPDATA%\Wireshark\plugins\`
- System: `C:\Program Files\Wireshark\plugins\`

### Manual Installation

Copy the built plugin file to the plugin directory:

```bash
# macOS/Linux
cp build/iggy.so ~/.local/lib/wireshark/plugins/

# Windows
copy build\Release\iggy.dll %APPDATA%\Wireshark\plugins\
```

### Verify Installation

1. Start Wireshark
2. Go to `Help → About Wireshark → Plugins`
3. Look for "Iggy Protocol" in the list
4. If not visible, go to `Analyze → Reload Lua Plugins` (works for C plugins too)

## Configuration

After installation, configure the dissector:

1. Open Wireshark preferences: `Wireshark → Preferences` (macOS) or `Edit → Preferences` (Linux/Windows)
2. Navigate to `Protocols → IGGY`
3. Set the server port (default: 8090)

## Troubleshooting

### "Plugin not found" or "Cannot load plugin"

- Ensure the plugin file has the correct extension (.so on Unix, .dll on Windows)
- Check file permissions: `chmod +x ~/.local/lib/wireshark/plugins/iggy.so`
- Verify Wireshark version compatibility (4.0+)

### "Undefined symbol" errors

This usually indicates a version mismatch. Rebuild against your exact Wireshark version:

```bash
# Check Wireshark version
wireshark --version

# Rebuild with matching headers
make clean
make
```

### CMake can't find Wireshark

Set the Wireshark directory explicitly:

```bash
cmake -DWireshark_DIR=/path/to/wireshark/lib/cmake/Wireshark ..
```

### Plugin not dissecting traffic

1. Check that traffic is on the configured port (default 8090)
2. Enable TCP port in dissector: `Analyze → Decode As...`
   - Field: TCP port
   - Value: 8090
   - Protocol: IGGY
3. Restart packet capture

## Development

### Rebuilding After Changes

```bash
make clean
make
make install
```

Then in Wireshark: `Analyze → Reload Lua Plugins`

### Adding New Commands

To add support for new Iggy commands:

1. Add command code constant:
```c
#define IGGY_CMD_YOUR_COMMAND 123
```

2. Add field declarations in `hf_register_info hf[]`

3. Implement dissector functions:
```c
static void dissect_your_command_request(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
static void dissect_your_command_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
```

4. Add cases to switch statements in `dissect_iggy()`

5. Update `get_command_name()` function

### Code Generation (Future)

For automation, consider creating a code generator that:
- Parses protocol definitions (from Rust code or separate spec)
- Generates field declarations
- Generates dissector functions
- Updates switch statements

See `CODEGEN.md` for details (to be created).

## Differences from Lua Version

### Advantages of C Implementation

1. **Performance**: Significantly faster dissection
2. **Native Integration**: Better Wireshark integration
3. **Type Safety**: Compile-time checks
4. **Memory Efficiency**: No Lua interpreter overhead
5. **Distribution**: Can be bundled with Wireshark

### Migration Notes

- Loading mechanism is different (plugin vs Lua script)
- Preferences are registered differently but work the same
- Request-response tracking uses conversation API instead of custom Lua state
- TCP reassembly is automatic via `tcp_dissect_pdus()`

## Testing

Run the protocol tests:

```bash
# Start Iggy server
cd /path/to/iggy
cargo run --bin iggy-server -- --with-default-root-credentials

# In another terminal, run tests
cd /path/to/iggy
cargo test -p wireshark --features protocol-tests
```

The tests will generate packet captures that you can open in Wireshark to verify the dissector works correctly.

## Resources

- [Wireshark Developer's Guide](https://www.wireshark.org/docs/wsdg_html_chunked/)
- [Wireshark Dissector API](https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html)
- [Example Dissectors](https://gitlab.com/wireshark/wireshark/-/tree/master/epan/dissectors)
