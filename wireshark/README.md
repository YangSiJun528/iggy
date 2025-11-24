# Wireshark Dissector for Iggy Protocol

Wireshark dissector for analyzing Iggy protocol traffic. Available in two implementations:

- **C dissector** (Recommended) - Native plugin with better performance and integration
- **Lua dissector** (Legacy) - Simpler but slower scripted dissector

## Quick Start

### C Dissector (Recommended)

```bash
cd wireshark/
make
make install
```

See [BUILD.md](BUILD.md) for detailed build instructions and troubleshooting.

### Lua Dissector (Legacy)

```bash
cp ./wireshark/dissector.lua ~/.local/lib/wireshark/plugins/
```

## Requirements

### C Dissector
- Wireshark 4.0 or higher
- CMake 3.12+
- C compiler (GCC, Clang, or MSVC)
- Wireshark development headers

### Lua Dissector
- Wireshark 4.6.0 or higher

## Running Tests

1. Start the server:
   ```bash
   cargo run --bin iggy-server -- --with-default-root-credentials
   ```

2. Run tests:
   ```bash
   cargo test -p wireshark --features protocol-tests
   ```

## Configuration

The default port used for protocol analysis is 8090. To change:

1. Open Wireshark preferences: `Wireshark → Preferences` (macOS) or `Edit → Preferences` (Linux/Windows)
2. Navigate to `Protocols → IGGY`
3. Set the server port

## Implementation Details

### C Dissector Features

- **Request-response tracking**: Automatically matches requests with responses
- **TCP reassembly**: Handles fragmented messages transparently
- **Conversation tracking**: Per-connection state management
- **Expert info**: Warnings for unknown commands or malformed packets
- **Native performance**: Significantly faster than Lua

Supported commands:
- Ping (1)
- User Login (38)
- Topic Create (302)

### Architecture

The C dissector uses Wireshark's standard plugin API:
- `proto_register_iggy()`: Registers protocol, fields, and preferences
- `proto_reg_handoff_iggy()`: Associates dissector with TCP port
- `dissect_iggy()`: Main dissection logic with bidirectional support
- TCP reassembly via `tcp_dissect_pdus()` for fragmented messages

### Adding New Commands

See [BUILD.md](BUILD.md#development) for instructions on extending the dissector.

## Code Generation (Planned)

To automate dissector maintenance, a code generator is planned that will:
- Parse Iggy protocol definitions from Rust code
- Generate C field declarations and dissector functions
- Update command tables automatically

This will eliminate manual synchronization between protocol changes and dissector code.

## Files

- `packet-iggy.c` - Main C dissector implementation
- `plugin.c` - Plugin registration (for in-tree builds)
- `CMakeLists.txt` - Build configuration
- `Makefile` - Convenience build wrapper
- `dissector.lua` - Legacy Lua implementation
- `BUILD.md` - Detailed build and development guide

## Troubleshooting

### Plugin not loading

Check Wireshark's plugin directory:
```bash
wireshark -v | grep "Personal Plugins"
```

Verify plugin is listed:
1. Open Wireshark
2. `Help → About Wireshark → Plugins`
3. Look for "Iggy Protocol"

### Traffic not being dissected

1. Verify port configuration matches your server
2. Try `Analyze → Decode As...` and manually set TCP port 8090 to IGGY
3. Check that you're capturing on the correct interface

### Duplicate protocol error (Lua)

Remove old Lua dissector:
```bash
rm ~/.local/lib/wireshark/plugins/dissector.lua
```

## Known Limitations

- QUIC protocol support not yet implemented
- Only a subset of Iggy commands currently supported (3 commands in C, 3 in Lua)
- Complex message payloads (e.g., send_messages) not yet fully dissected


