# IGGY Wireshark Dissector

A Wireshark protocol dissector for [IGGY](https://github.com/iggy-rs/iggy) messaging system's TCP protocol.

## Features

- ✅ Full TCP protocol dissection for IGGY messaging
- ✅ Automatic Request/Response detection
- ✅ 50+ command types supported
- ✅ TCP reassembly for multi-segment messages
- ✅ Heuristic dissector for automatic protocol detection
- ✅ Detailed field parsing for common data types (Identifier, Partitioning, etc.)
- ✅ Human-readable command names and field values

### Supported Commands

**Currently Implemented:**
- System: PING, GET_STATS, GET_ME, GET_CLIENT(S)
- Authentication: LOGIN_USER, LOGOUT_USER, Personal Access Tokens
- Messages: POLL_MESSAGES, SEND_MESSAGES, Consumer Offset operations
- Streams: Full stream management (GET, CREATE, DELETE, UPDATE, PURGE)
- Topics: Full topic management
- Consumer Groups: Full consumer group management
- Partitions & Segments management

See [protocol-spec.md](protocol-spec.md) for detailed protocol documentation.

## Installation

### Prerequisites

- Wireshark 3.0 or later (Tested on Wireshark 4.6.0)
- IGGY server (for testing)

### Quick Install

**macOS (Recommended):**
```bash
# Automatic installation
./install.sh

# Or manual installation
mkdir -p ~/.local/lib/wireshark/plugins/
cp iggy.lua ~/.local/lib/wireshark/plugins/
```

**Linux:**
```bash
mkdir -p ~/.local/lib/wireshark/plugins/
cp iggy.lua ~/.local/lib/wireshark/plugins/
```

**Windows:**
```powershell
# Create directory if not exists
New-Item -ItemType Directory -Force -Path "$env:APPDATA\Wireshark\plugins"
Copy-Item iggy.lua "$env:APPDATA\Wireshark\plugins\"
```

Then restart Wireshark or reload plugins with: `Analyze` → `Reload Lua Plugins` (Cmd+Shift+L on macOS, Ctrl+Shift+L on others)

### Detailed Installation

#### Method 1: User Plugin Directory (Recommended)

**Advantages:** No admin rights needed, easy to update, user-specific

1. **Locate your Wireshark personal plugins directory:**

   You can find the exact path in Wireshark: `Help` → `About Wireshark` → `Folders` → `Personal Plugins`

   Common locations:
   - **macOS**: `~/.local/lib/wireshark/plugins/`
   - **Linux**: `~/.local/lib/wireshark/plugins/` or `~/.config/wireshark/plugins/`
   - **Windows**: `%APPDATA%\Wireshark\plugins\`

2. **Install the dissector:**

   **macOS:**
   ```bash
   # Navigate to the project directory
   cd iggy-wireshark-dissector

   # Create plugins directory
   mkdir -p ~/.local/lib/wireshark/plugins/

   # Copy the dissector
   cp iggy.lua ~/.local/lib/wireshark/plugins/

   # Verify installation
   ls -lh ~/.local/lib/wireshark/plugins/iggy.lua
   ```

   **Linux:**
   ```bash
   # Try the standard location first
   mkdir -p ~/.local/lib/wireshark/plugins/
   cp iggy.lua ~/.local/lib/wireshark/plugins/

   # If that doesn't work, try the config location
   mkdir -p ~/.config/wireshark/plugins/
   cp iggy.lua ~/.config/wireshark/plugins/
   ```

   **Windows (PowerShell):**
   ```powershell
   New-Item -ItemType Directory -Force -Path "$env:APPDATA\Wireshark\plugins"
   Copy-Item iggy.lua "$env:APPDATA\Wireshark\plugins\"
   ```

3. **Reload Wireshark plugins:**
   - Restart Wireshark, or
   - `Analyze` → `Reload Lua Plugins` (Cmd+Shift+L on macOS, Ctrl+Shift+L on others)

#### Method 2: Global Plugin Directory

**Advantages:** Available for all users
**Disadvantages:** Requires admin/sudo, harder to update

1. **Find the global plugins directory:**
   - **macOS**: `/Applications/Wireshark.app/Contents/PlugIns/wireshark/`
   - **Linux**: `/usr/lib/wireshark/plugins/` or `/usr/local/lib/wireshark/plugins/`
   - **Windows**: `C:\Program Files\Wireshark\plugins\`

2. **Copy with admin privileges:**

   **macOS:**
   ```bash
   sudo cp iggy.lua /Applications/Wireshark.app/Contents/PlugIns/wireshark/
   ```

   **Linux:**
   ```bash
   sudo cp iggy.lua /usr/lib/wireshark/plugins/
   # or
   sudo cp iggy.lua /usr/local/lib/wireshark/plugins/
   ```

   **Windows (Run as Administrator):**
   ```powershell
   Copy-Item iggy.lua "C:\Program Files\Wireshark\plugins\"
   ```

3. **Restart Wireshark**

### Verify Installation

1. **Open Wireshark**
   ```bash
   # macOS
   open /Applications/Wireshark.app

   # Linux
   wireshark

   # Windows
   # Use Start Menu or desktop shortcut
   ```

2. **Check in About dialog:**
   - Go to `Help` → `About Wireshark`
   - Click on `Plugins` tab
   - Search for "iggy"
   - You should see `iggy.lua` listed

3. **Check in Enabled Protocols:**
   - Go to `Analyze` → `Enabled Protocols`
   - Search for "IGGY"
   - Verify that "IGGY Messaging Protocol" is listed and enabled

You should also see this message in Wireshark's log:
```
IGGY Protocol Dissector loaded successfully
Registered on TCP ports: 8090, 8091, 8092
Heuristic dissector enabled
```

## Usage

### Capturing IGGY Traffic

#### Using Wireshark GUI

1. **Start Wireshark**

2. **Select the appropriate network interface:**
   - **macOS localhost**: `Loopback: lo0` (for local IGGY server)
   - **Linux localhost**: `Loopback: lo`
   - **Network traffic**: Select your ethernet/wifi interface

3. **Apply a capture filter (optional but recommended):**
   ```
   tcp port 8090
   ```
   This will only capture IGGY traffic and reduce noise.

4. **Start capture** - The dissector will automatically detect IGGY protocol packets

#### Using Command Line (tcpdump)

**macOS:**
```bash
# Capture localhost traffic
sudo tcpdump -i lo0 -w iggy_capture.pcap 'tcp port 8090'

# Note: macOS uses lo0, not lo!
```

**Linux:**
```bash
# Capture localhost traffic
sudo tcpdump -i lo -w iggy_capture.pcap 'tcp port 8090'
```

**Then open in Wireshark:**
```bash
# macOS
open -a Wireshark iggy_capture.pcap

# Linux
wireshark iggy_capture.pcap
```

#### Complete Example: Capture Real IGGY Traffic

**Terminal 1 - Start IGGY Server:**
```bash
iggy-server
# Server will listen on tcp://127.0.0.1:8090
```

**Terminal 2 - Start Packet Capture:**
```bash
# macOS
sudo tcpdump -i lo0 -w ~/Desktop/iggy_test.pcap 'tcp port 8090'

# Linux
sudo tcpdump -i lo -w ~/Desktop/iggy_test.pcap 'tcp port 8090'
```

**Terminal 3 - Generate IGGY Traffic:**
```bash
# Login
iggy-cli login root secret

# Create resources
iggy-cli stream create 1 test_stream
iggy-cli topic create 1 1 3 test_topic

# Send and receive messages
iggy-cli message send 1 1 "Hello Wireshark!"
iggy-cli message poll 1 1 consumer 1

# Cleanup
iggy-cli stream delete 1
iggy-cli logout
```

**Terminal 2 - Stop capture:**
```
Press Ctrl+C
```

**Open in Wireshark:**
```bash
# macOS
open -a Wireshark ~/Desktop/iggy_test.pcap

# Linux
wireshark ~/Desktop/iggy_test.pcap
```

### Display Filters

Use these filters to find specific IGGY traffic:

```bash
# All IGGY protocol packets
iggy

# Specific command by code
iggy.command == 1          # PING
iggy.command == 38         # LOGIN_USER
iggy.command == 100        # POLL_MESSAGES
iggy.command == 101        # SEND_MESSAGES

# By command name
iggy.command_name == "PING"
iggy.command_name == "LOGIN_USER"

# Responses only
iggy.status == 0           # Successful responses
iggy.status != 0           # Error responses

# Messages with specific identifiers
iggy.identifier.value.string == "my_stream"
iggy.identifier.value.numeric == 123

# Specific stream or topic
iggy.stream_id == 1
iggy.topic_id == 5

# Consumer operations
iggy.consumer.kind == 1    # Consumer
iggy.consumer.kind == 2    # ConsumerGroup

# Partitioning
iggy.partitioning.kind == 1  # Balanced
iggy.partitioning.kind == 2  # PartitionId
```

### Analyzing Traffic

1. **Follow a Session:**
   - Right-click on an IGGY packet
   - Select `Follow` → `TCP Stream`
   - See all IGGY commands in that session

2. **Inspect Fields:**
   - Click on any packet
   - Expand the "IGGY Protocol" section in the packet details pane
   - All fields are hierarchically organized

3. **Export Data:**
   - `File` → `Export Packet Dissections`
   - Choose format (Text, CSV, JSON, etc.)

## Configuration

### Custom Ports

By default, the dissector is registered on ports 8090, 8091, 8092.

To add custom ports:

1. Open `iggy.lua` in a text editor
2. Find the section near the end:
   ```lua
   tcp_port:add(8090, iggy_proto)
   tcp_port:add(8091, iggy_proto)
   tcp_port:add(8092, iggy_proto)
   ```
3. Add your custom port:
   ```lua
   tcp_port:add(YOUR_PORT, iggy_proto)
   ```
4. Save and reload Lua plugins

### Decode As

If IGGY is running on a non-standard port without adding it to the script:

1. Right-click on a packet from that port
2. Select `Decode As...`
3. Set "Current" to "IGGY"
4. Click OK

## Testing

### Generate Test Traffic

The easiest way to test the dissector is to use the IGGY CLI or SDK:

```bash
# Start IGGY server
iggy-server

# In another terminal, use IGGY CLI
iggy-cli

# Or use the test script (see test/ directory)
python test/generate_test_traffic.py
```

### Capture Traffic

```bash
# Start capturing before generating traffic
tcpdump -i lo -w iggy_test.pcap tcp port 8090

# Then generate traffic with IGGY client
# Stop tcpdump with Ctrl+C

# Open in Wireshark
wireshark iggy_test.pcap
```

## Troubleshooting

### Dissector Not Loading

1. Check Wireshark logs: `View` → `Internals` → `Wireshark Log`
2. Look for Lua errors
3. Verify the file is in the correct plugins directory
4. Check file permissions (must be readable)

### Protocol Not Detected

1. Verify the TCP port matches (default: 8090)
2. Try using `Decode As...` to force IGGY protocol
3. Check if packets are complete (not truncated)
4. Enable heuristic dissector: `Analyze` → `Enabled Protocols` → search "IGGY" → enable

### Fields Not Parsing

1. Check if you have the latest version of the dissector
2. Verify the IGGY server version matches the protocol spec
3. Some commands may not have full payload parsers yet (see protocol-spec.md)

### Performance Issues

The Lua dissector should handle most traffic fine. If you experience slowdowns:

1. Use display filters to limit visible packets
2. Disable other unused protocols: `Analyze` → `Enabled Protocols`
3. Consider using tshark for batch processing

## Development

### Adding New Command Parsers

To add a parser for a new command:

1. Find the command code in `protocol-spec.md`
2. Add a parser function in `iggy.lua`:
   ```lua
   command_parsers[YOUR_COMMAND_CODE] = function(buffer, pinfo, tree, offset)
       -- Parse your command payload
       -- Return bytes consumed or -1 if need more data
   end
   ```
3. Test with real traffic
4. Update documentation

### Project Structure

```
iggy-wireshark-dissector/
├── iggy.lua              # Main dissector implementation
├── protocol-spec.md      # Detailed protocol specification
├── PROGRESS.md           # Development progress tracking
├── README.md             # This file
├── test/                 # Test scripts and samples
└── docs/                 # Additional documentation
```

## Contributing

Contributions are welcome! Please:

1. Check `PROGRESS.md` for current status
2. Follow the existing code style
3. Test your changes thoroughly
4. Update documentation

## Resources

- **IGGY Project**: https://github.com/iggy-rs/iggy
- **IGGY Documentation**: https://docs.iggy.rs/
- **Wireshark Lua API**: https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html
- **Protocol Specification**: [protocol-spec.md](protocol-spec.md)

## License

This dissector is provided as-is for analyzing IGGY protocol traffic. Please ensure you comply with your local laws and regulations regarding network traffic analysis.

## Changelog

### Version 0.1.0 (2025-11-02)
- Initial release
- Basic protocol dissection (Request/Response)
- 50+ command codes supported
- Implemented parsers for key commands:
  - PING
  - LOGIN_USER
  - CREATE_STREAM
  - POLL_MESSAGES
  - SEND_MESSAGES
  - STORE_CONSUMER_OFFSET
- Common data type parsers (Identifier, Partitioning)
- TCP reassembly support
- Heuristic dissector for auto-detection

## Roadmap

- [ ] Complete parsers for all commands
- [ ] Response payload parsing
- [ ] Message data decoding
- [ ] Statistics and flow analysis
- [ ] Expert info for common issues
- [ ] Preferences UI for configuration
- [ ] Performance optimizations

---

For detailed protocol information, see [protocol-spec.md](protocol-spec.md).

For development progress, see [PROGRESS.md](PROGRESS.md).
