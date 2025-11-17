# Wireshark Dissector for Iggy Protocol

Wireshark dissector for analyzing Iggy protocol traffic, written in Lua.

## Requirements

- Wireshark 4.6.0 or higher
- Iggy server running on port 8090 (default)

## Running Tests

1. Start the server:
   ```bash
   cargo run --bin iggy-server -- --with-default-root-credentials
   ```

2. Run tests:
   ```bash
   cargo test -p wireshark --features protocol-tests
   ```

## Installation

Copy the dissector to Wireshark plugins directory:

```bash
cp ./wireshark/dissector.lua ~/.local/lib/wireshark/plugins/
```

Reload plugins in Wireshark: `Analyze → Reload Lua Plugins` (Ctrl+Shift+L)

### Troubleshooting

If you encounter a duplicate protocol error, remove and re-copy:
```bash
rm ~/.local/lib/wireshark/plugins/dissector.lua
```

## Usage

Filter Iggy traffic in Wireshark: `iggy`

## Documentation

- [DISSECTOR_GUIDE.md](DISSECTOR_GUIDE.md) - Development guide
- [REQUEST_RESPONSE_TRACKER.md](REQUEST_RESPONSE_TRACKER.md) - Request/response matching
- [SPEC.md](SPEC.md) - Protocol specification


