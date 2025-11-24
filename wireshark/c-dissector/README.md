# Iggy Wireshark C Dissector

Native C implementation of the Iggy protocol dissector for Wireshark.

## Building

### Prerequisites

**macOS:**
```bash
brew install wireshark cmake
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install wireshark-dev libglib2.0-dev cmake build-essential
```

### Build and Install

```bash
# Build
make

# Install to Wireshark
make install
```

The plugin will be installed to `~/.local/lib/wireshark/plugins/`.

## Features

- Iggy protocol dissection on TCP port 8090
- Request-response tracking
- Automatic TCP reassembly
- Supported commands: Ping (1), User Login (38), Topic Create (302)

## Verification

After installation:
1. Start Wireshark
2. `Help → About Wireshark → Plugins`
3. Look for "Iggy Protocol"

## Configuration

`Wireshark → Preferences → Protocols → IGGY` to change port.

## Development

Edit `packet-iggy.c` and run:
```bash
make clean && make && make install
```

Then restart Wireshark.
