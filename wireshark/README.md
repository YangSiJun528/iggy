# Wireshark Dissector for Iggy Protocol

Wireshark dissector for analyzing Iggy protocol traffic, written in C.

## Requirements

- Wireshark 4.0 or higher
- Precompiled Iggy dissector plugin (`.so` for macOS/Linux, `.dll` for Windows)

## Installation

Copy the precompiled plugin to your Wireshark plugin directory:

### macOS
```bash
cp iggy.so ~/.local/lib/wireshark/plugins/
```

### Linux
```bash
cp iggy.so ~/.local/lib/wireshark/plugins/
```

### Windows
```powershell
copy iggy.dll %APPDATA%\Wireshark\plugins\
```

## Verification

1. Start Wireshark
2. Go to `Help → About Wireshark → Plugins`
3. Look for "Iggy Protocol" in the plugin list
4. If not visible, restart Wireshark

## Configuration

The default port for Iggy protocol analysis is 8090.

To change the port:
1. Open Wireshark preferences: `Wireshark → Preferences` (macOS) or `Edit → Preferences` (Linux/Windows)
2. Navigate to `Protocols → IGGY`
3. Set the server port

## Running Tests

1. Start the Iggy server:
   ```bash
   cargo run --bin iggy-server -- --with-default-root-credentials
   ```

2. Run protocol tests:
   ```bash
   cargo test -p wireshark --features protocol-tests
   ```

## Features

- **Request-response tracking**: Automatically matches requests with responses
- **TCP reassembly**: Handles fragmented messages transparently
- **Conversation tracking**: Per-connection state management
- **Expert info**: Warnings for unknown commands or malformed packets

### Supported Commands

- Ping (1)
- User Login (38)
- Topic Create (302)

## Troubleshooting

### Plugin not loading

Check Wireshark's plugin directory:
```bash
wireshark -v | grep "Personal Plugins"
```

Ensure the plugin file exists:
```bash
ls -la ~/.local/lib/wireshark/plugins/iggy.so
```

### Traffic not being dissected

1. Verify the port configuration matches your server (default: 8090)
2. Use `Analyze → Decode As...`:
   - Field: TCP port
   - Value: 8090
   - Protocol: IGGY
3. Check that you're capturing on the correct network interface

### Permission issues

Ensure the plugin file is readable:
```bash
chmod +r ~/.local/lib/wireshark/plugins/iggy.so
```

## Files

- `packet-iggy.c` - C dissector source code
- `README.md` - This file
- `.gitignore` - Git ignore rules

## Known Limitations

- QUIC protocol support not yet implemented
- Only a subset of Iggy commands currently supported
- Complex message payloads (e.g., send_messages) not yet fully dissected

## Development

For building the dissector from source, you'll need:
- Wireshark development headers
- CMake 3.12+
- C compiler (GCC, Clang, or MSVC)

Contact the Iggy team for build instructions if you need to compile the plugin.
