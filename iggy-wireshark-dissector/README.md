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

- Wireshark 3.0 or later
- IGGY server (for testing)

### Method 1: User Plugin Directory (Recommended)

1. Locate your Wireshark personal plugins directory:
   - **Linux/macOS**: `~/.local/lib/wireshark/plugins/` or `~/.wireshark/plugins/`
   - **Windows**: `%APPDATA%\Wireshark\plugins\`

   You can find the exact path in Wireshark: `Help` → `About Wireshark` → `Folders` → `Personal Plugins`

2. Copy `iggy.lua` to the plugins directory:
   ```bash
   # Linux/macOS
   mkdir -p ~/.local/lib/wireshark/plugins/
   cp iggy.lua ~/.local/lib/wireshark/plugins/

   # Or use the legacy location
   mkdir -p ~/.wireshark/plugins/
   cp iggy.lua ~/.wireshark/plugins/
   ```

3. Restart Wireshark or reload Lua plugins: `Analyze` → `Reload Lua Plugins` (Ctrl+Shift+L)

### Method 2: Global Plugin Directory

1. Find the global plugins directory:
   - **Linux**: `/usr/lib/wireshark/plugins/`
   - **macOS**: `/Applications/Wireshark.app/Contents/PlugIns/wireshark/`
   - **Windows**: `C:\Program Files\Wireshark\plugins\`

2. Copy `iggy.lua` to the global directory (requires admin/sudo):
   ```bash
   # Linux
   sudo cp iggy.lua /usr/lib/wireshark/plugins/

   # macOS
   sudo cp iggy.lua /Applications/Wireshark.app/Contents/PlugIns/wireshark/
   ```

3. Restart Wireshark

### Verify Installation

1. Open Wireshark
2. Go to `Analyze` → `Enabled Protocols`
3. Search for "IGGY"
4. Verify that "IGGY Messaging Protocol" is listed and enabled

You should also see this message in Wireshark's log:
```
IGGY Protocol Dissector loaded successfully
Registered on TCP ports: 8090, 8091, 8092
Heuristic dissector enabled
```

## Usage

### Capturing IGGY Traffic

1. Start capturing on the network interface where IGGY traffic flows
2. Apply a capture filter (optional):
   ```
   tcp port 8090
   ```

3. The dissector will automatically detect IGGY protocol packets

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
