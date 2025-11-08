# Iggy Wireshark Dissector Tests

This directory contains integration tests for the Iggy Wireshark dissector (`dissector.lua`).

## Overview

The tests validate that the Wireshark dissector correctly parses Iggy protocol packets by:
1. Starting a packet capture with `tshark`
2. Performing real operations using the Iggy client
3. Analyzing the captured packets
4. Verifying that the dissector correctly identifies and parses Iggy protocol fields

## Prerequisites

### 1. Running Iggy Server

Before running the tests, you must have an Iggy server running on the configured address.

By default, tests expect a server at `127.0.0.1:3000` and automatically authenticate using the default root credentials (`iggy`/`iggy`).

To change the server address, edit the constants in `src/lib.rs`:

```rust
const SERVER_IP: &str = "127.0.0.1";
const SERVER_PORT: u16 = 3000;
```

**Note**: The tests use `AutoLogin` with default root credentials. If your server uses different credentials, you'll need to modify the `create_test_client()` function in `src/lib.rs`.

To start an Iggy server:

```bash
# From the workspace root
cargo run --bin iggy-server
```

### 2. Wireshark/tshark Installation

Install Wireshark (which includes tshark):

**macOS:**
```bash
brew install wireshark
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install tshark
```

**Linux (Fedora):**
```bash
sudo dnf install wireshark
```

### 3. Dissector Location

The tests automatically look for `dissector.lua` in the parent directory (workspace root). Ensure the dissector file exists at:
```
/path/to/iggy/dissector.lua
```

## Running Tests

### Run All Wireshark Tests

To run all wireshark dissector tests (they are marked with `#[ignore]` so they won't run in normal test runs):

```bash
# From the workspace root
cargo test -p wireshark -- --ignored

# Or from the wireshark directory
cargo test -- --ignored
```

### Run a Specific Test

```bash
# Run only the ping test
cargo test -p wireshark test_ping_dissection -- --ignored

# Run only the get_stats test
cargo test -p wireshark test_get_stats_dissection -- --ignored
```

### Run with Output

To see detailed output from the tests:

```bash
cargo test -p wireshark -- --ignored --nocapture
```

## Available Tests

### 1. `test_ping_dissection`
Tests that the dissector correctly identifies and parses Ping request/response packets.

### 2. `test_stream_topic_creation_dissection`
Tests dissection of stream and topic creation commands.

### 3. `test_message_send_receive_dissection`
Tests dissection of message send and poll operations.

### 4. `test_get_stats_dissection`
Tests dissection of GetStats command and response with payload.

## Test Architecture

Each test follows this pattern:

1. **Start Capture**: Launch tshark to capture packets on the test port
2. **Perform Operation**: Use Iggy client to perform real operations (ping, create stream, send messages, etc.)
3. **Stop Capture**: Stop tshark and save the capture to a pcap file
4. **Analyze**: Run tshark again with the dissector to parse the captured packets as JSON
5. **Verify**: Check that the dissector correctly identified and parsed the Iggy protocol fields

## Troubleshooting

### No packets captured

- Ensure the Iggy server is running on the correct address/port
- Check that tshark has permission to capture on the loopback interface
  ```bash
  # On Linux, you may need to add your user to the wireshark group
  sudo usermod -a -G wireshark $USER
  ```
- Verify the capture filter is correct for your platform (some systems use `lo0` instead of `lo`)

### Dissector not found

- Ensure `dissector.lua` exists in the workspace root
- Check the path in the test output

### Tests fail with "command not found: tshark"

- Install Wireshark/tshark (see Prerequisites)
- Ensure tshark is in your PATH

### Permission denied errors

On some systems, capturing packets requires elevated privileges:

```bash
# Linux - give yourself packet capture permissions (one-time setup)
sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)
```

## CI/CD Integration

These tests are marked with `#[ignore]` to prevent them from running in standard CI pipelines, as they require:
- A running Iggy server
- Wireshark/tshark installation
- Network capture permissions

For local development and validation of the dissector, run them manually with `--ignored` flag.

## Modifying Tests

To add new test scenarios:

1. Add a new test function in `src/lib.rs`
2. Mark it with `#[tokio::test]` and `#[ignore]`
3. Follow the existing pattern: capture → operate → analyze → verify
4. Use the Iggy client to perform real operations
5. Verify the dissected output matches the expected protocol fields
