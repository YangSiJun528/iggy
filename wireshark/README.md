# Wireshark Dissector for Iggy Protocol

Wireshark dissector for analyzing Iggy protocol traffic, written in Lua.

## Requirements

- Wireshark 4.6.0 or higher
- Iggy server

## Running Tests

1. Start the server:
   ```bash
   cargo run --bin iggy-server -- --with-default-root-credentials
   ```

2. Run tests:
   ```bash
   cargo test -p wireshark --features protocol-tests
   ```

## Wireshark Plugin Setup

1. Copy the dissector to Wireshark plugins directory(Mac 기준):
   ```bash
   cp ./wireshark/dissector.lua ~/.local/lib/wireshark/plugins/
   ```

2. Reload plugins in Wireshark: `Analyze → Reload Lua Plugins`

3. Run demo code or test code to generate traffic

### Configuration

프로토콜 분석 시 사용하는 기본 포트는 8090임. 만약 다른 포트를 사용한다면 target port를 변경해야 함.

Change the target port in preferences(Mac 기준): `Wireshark → Preferences → Protocols → IGGY → Server Port`

### Troubleshooting

If you encounter a duplicate protocol error, remove and re-copy:
```bash
rm ~/.local/lib/wireshark/plugins/dissector.lua
```

## Known Limitations & TODO

- QUIC protocol support not yet implemented
- 서버가 로컬에 실행중이여야 분석 가능
- Only a subset of Iggy commands currently supported
- Test code needs refactoring for better readability
- Test server should be isolated with a dedicated test script


