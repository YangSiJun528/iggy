# Iggy Wireshark Protocol Tests

Rust-based integration tests for the Iggy Wireshark dissector.

## Purpose

These tests verify that the Wireshark dissector correctly parses Iggy protocol messages by:
1. Starting an Iggy server
2. Performing protocol operations
3. Capturing network traffic
4. Validating dissection results

## Running Tests

### Prerequisites

- Iggy server binary
- Rust toolchain
- Network capture permissions

### Execute Tests

```bash
# From repository root
cargo test -p wireshark --features protocol-tests

# Or from this directory
cd wireshark/rust/
cargo test --features protocol-tests
```

### Test Setup

1. Start Iggy server:
```bash
cargo run --bin iggy-server -- --with-default-root-credentials
```

2. Run tests in another terminal:
```bash
cargo test -p wireshark --features protocol-tests
```

## Test Coverage

Current tests cover:
- User authentication (login)
- Topic creation
- Basic protocol operations

## Configuration

Test configuration is in `Cargo.toml`:
- Feature flag: `protocol-tests`
- Dependencies: iggy, tokio, serde_json

## Adding New Tests

1. Edit `tests/protocol_tests.rs`
2. Add test functions with `#[tokio::test]`
3. Use Iggy client to perform operations
4. Capture and validate dissector output

## Files

- `Cargo.toml` - Test configuration
- `tests/protocol_tests.rs` - Test implementations
- `README.md` - This file
