# IGGY Dissector Testing

## Test Files

### test_protocol.py

Python script to generate test IGGY protocol messages.

**Usage:**
```bash
python3 test_protocol.py
```

This will:
1. Generate various IGGY protocol messages (PING, LOGIN, CREATE_STREAM, etc.)
2. Print them in hex format
3. Save them to `test_messages.bin`

## Testing the Dissector

### Option 1: Using IGGY SDK (Recommended)

The best way to test is with real IGGY traffic:

1. **Start IGGY server:**
   ```bash
   # Clone and build IGGY
   git clone https://github.com/iggy-rs/iggy.git
   cd iggy
   cargo build --release

   # Run server
   ./target/release/iggy-server
   ```

2. **Start packet capture:**
   ```bash
   # In another terminal
   sudo tcpdump -i lo -w iggy_real.pcap 'tcp port 8090'
   ```

3. **Generate traffic with IGGY CLI:**
   ```bash
   # In another terminal
   cd iggy

   # Login
   ./target/release/iggy-cli login root secret

   # Create stream
   ./target/release/iggy-cli stream create 1 test_stream

   # Create topic
   ./target/release/iggy-cli topic create 1 1 3 test_topic

   # Send messages
   ./target/release/iggy-cli message send 1 1 hello

   # Poll messages
   ./target/release/iggy-cli message poll 1 1 consumer 1

   # Cleanup
   ./target/release/iggy-cli stream delete 1
   ./target/release/iggy-cli logout
   ```

4. **Stop tcpdump** (Ctrl+C)

5. **Open in Wireshark:**
   ```bash
   wireshark iggy_real.pcap
   ```

### Option 2: Using Python Test Script

Generate test binary messages (without server):

1. **Generate test messages:**
   ```bash
   python3 test_protocol.py
   ```

2. **Create a pcap from the binary:**

   You can use `text2pcap` or `scapy` to convert the binary to pcap.

   Using scapy:
   ```python
   from scapy.all import *

   # Read binary messages
   with open('test_messages.bin', 'rb') as f:
       data = f.read()

   # Create TCP packet
   packet = IP(src="127.0.0.1", dst="127.0.0.1") / \
            TCP(sport=54321, dport=8090) / \
            Raw(load=data)

   # Write to pcap
   wrpcap('test_messages.pcap', packet)
   ```

3. **Open in Wireshark:**
   ```bash
   wireshark test_messages.pcap
   ```

### Option 3: Manual Testing

Create your own test by sending raw bytes:

```python
import socket
import struct

# Connect to IGGY server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 8090))

# Send PING (command 1, no payload)
length = struct.pack('<I', 4)  # Length = 4 (just command)
command = struct.pack('<I', 1)  # Command = 1 (PING)
sock.send(length + command)

# Receive response
response = sock.recv(1024)
print(f"Response: {response.hex()}")

sock.close()
```

Capture this with tcpdump running in the background.

## Verifying the Dissector

Once you have a pcap file:

1. **Open in Wireshark:**
   ```bash
   wireshark your_capture.pcap
   ```

2. **Check dissector is loaded:**
   - Go to `Analyze` → `Enabled Protocols`
   - Search for "IGGY"
   - Verify it's enabled

3. **Apply display filter:**
   ```
   iggy
   ```

4. **Verify parsing:**
   - Click on an IGGY packet
   - Expand "IGGY Protocol" in the packet details
   - Check that fields are correctly parsed:
     - Command names should be displayed
     - Identifiers should be decoded
     - All fields should be present

5. **Test specific commands:**
   ```
   iggy.command_name == "PING"
   iggy.command_name == "LOGIN_USER"
   iggy.command_name == "POLL_MESSAGES"
   ```

6. **Check Info column:**
   - Should show "Request: COMMAND_NAME" or "Response: Success/Error"

## Expected Output

For a PING command, you should see:

```
IGGY Protocol (Request)
├─ Length: 4
├─ Command Code: 1 (PING)
├─ Command Name: PING (generated)
└─ Payload: PING: No payload
```

For a LOGIN_USER command:

```
IGGY Protocol (Request)
├─ Length: 45
├─ Command Code: 38 (LOGIN_USER)
├─ Command Name: LOGIN_USER (generated)
└─ Payload
   ├─ Username: testuser
   ├─ Password: testpass123
   ├─ Version: dissector-test-v1.0
   └─ Context: wireshark-testing
```

## Troubleshooting

### Dissector not detecting packets

- Check the TCP port is 8090, 8091, or 8092
- Try "Decode As..." → select IGGY
- Verify dissector is enabled in `Analyze` → `Enabled Protocols`

### Fields not parsing correctly

- Check the IGGY server version matches protocol spec
- Compare packet bytes with protocol-spec.md
- Check Wireshark log for Lua errors: `View` → `Internals` → `Wireshark Log`

### No traffic captured

- Make sure tcpdump has proper permissions (use sudo)
- Verify the network interface is correct (lo for localhost)
- Check firewall settings

## Sample Commands for Testing

Here's a complete test sequence:

```bash
# Terminal 1: Start IGGY server
iggy-server

# Terminal 2: Start capture
sudo tcpdump -i lo -w test.pcap 'tcp port 8090'

# Terminal 3: Run commands
iggy-cli login root secret
iggy-cli stream create 1 mystream
iggy-cli topic create 1 1 3 mytopic
iggy-cli message send 1 1 "Hello World"
iggy-cli message poll 1 1 consumer 1
iggy-cli logout

# Terminal 2: Stop capture (Ctrl+C)

# Open Wireshark
wireshark test.pcap
```

## Testing Checklist

- [ ] Dissector loads without errors
- [ ] PING command is recognized
- [ ] LOGIN_USER shows username/password fields
- [ ] CREATE_STREAM shows stream ID and name
- [ ] CREATE_TOPIC shows all fields
- [ ] POLL_MESSAGES shows consumer, stream, topic, strategy
- [ ] SEND_MESSAGES shows message count and data
- [ ] Identifier fields are decoded (both numeric and string)
- [ ] Partitioning is decoded
- [ ] Responses show status (Success/Error)
- [ ] Info column shows command names
- [ ] Display filters work (iggy.command == 1, etc.)
- [ ] TCP reassembly works for large messages

## Performance Testing

For performance testing:

1. Generate lots of traffic
2. Open large pcap file
3. Check Wireshark performance
4. If slow, consider:
   - Using display filters to limit packets
   - Disabling other protocols
   - Using tshark for batch processing

## Reporting Issues

If you find issues with the dissector:

1. Note the IGGY server version
2. Save the pcap file showing the issue
3. Note the Wireshark version
4. Check for Lua errors in the log
5. Create an issue with all details

## Additional Resources

- **Protocol Spec**: `../protocol-spec.md`
- **Wireshark Dissector**: `../iggy.lua`
- **README**: `../README.md`
- **IGGY Documentation**: https://docs.iggy.rs/
