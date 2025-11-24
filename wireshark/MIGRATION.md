# Migration from Lua to C Dissector

This guide helps you migrate from the Lua dissector to the new C implementation.

## Why Migrate?

### Performance
- **C dissector**: Native code, 10-100x faster for complex captures
- **Lua dissector**: Interpreted, slower for large packet captures

### Integration
- **C dissector**: Full Wireshark API access, better conversation tracking
- **Lua dissector**: Limited API subset

### Maintenance
- **C dissector**: Type-safe, compile-time checks, code generation support
- **Lua dissector**: Runtime errors, manual field management

### Distribution
- **C dissector**: Can be bundled with Wireshark or distributed as binary
- **Lua dissector**: Requires users to manually copy script

## Quick Migration Steps

### 1. Remove Lua Dissector

```bash
# Find and remove Lua dissector
rm ~/.local/lib/wireshark/plugins/dissector.lua

# On macOS, also check:
rm /Applications/Wireshark.app/Contents/PlugIns/wireshark/dissector.lua
```

### 2. Build and Install C Dissector

```bash
cd wireshark/
make
make install
```

See [BUILD.md](BUILD.md) for detailed instructions.

### 3. Restart Wireshark

The C plugin is loaded at startup, so restart Wireshark completely.

### 4. Verify Installation

1. Open Wireshark
2. Go to `Help → About Wireshark → Plugins`
3. Look for "Iggy Protocol" with version 0.1.0

## API Differences

### Lua vs C Implementation

| Feature | Lua | C |
|---------|-----|---|
| Request-response tracking | Custom state table | Conversation API |
| TCP reassembly | Manual with `pinfo.desegment_len` | Automatic with `tcp_dissect_pdus()` |
| Field registration | Runtime table | Compile-time array |
| Preferences | `Pref.*` functions | `prefs_register_*()` API |
| Performance | ~100 µs per packet | ~1-5 µs per packet |

### Loading Mechanism

**Lua:**
```lua
-- dissector.lua is loaded on demand
-- Can be reloaded without restart
```

**C:**
```c
// plugin.c defines entry points
// Loaded at Wireshark startup
// Requires restart to reload
```

### Field Declaration

**Lua:**
```lua
local hf_username = ProtoField.string("iggy.login.username", "Username")
```

**C:**
```c
static int hf_iggy_login_username;

{ &hf_iggy_login_username,
    { "Username", "iggy.login.username",
    FT_STRING, BASE_NONE, NULL, 0x0,
    NULL, HFILL }
}
```

### Dissector Function

**Lua:**
```lua
function iggy.dissector(buffer, pinfo, tree)
    local length = buffer(0, 4):le_uint()
    -- ...
end
```

**C:**
```c
static int
dissect_iggy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    uint32_t length = tvb_get_letohl(tvb, 0);
    // ...
    return tvb_captured_length(tvb);
}
```

### Request-Response Tracking

**Lua:**
```lua
local conv_data = pinfo.conversation[iggy]
if not conv_data then
    conv_data = {queue = {first = 0, last = -1}}
end
```

**C:**
```c
conversation_t *conv = find_or_create_conversation(pinfo);
iggy_conv_data_t *conv_data =
    (iggy_conv_data_t *)conversation_get_proto_data(conv, proto_iggy);

if (!conv_data) {
    conv_data = wmem_new0(wmem_file_scope(), iggy_conv_data_t);
    // ...
    conversation_add_proto_data(conv, proto_iggy, conv_data);
}
```

## Feature Parity

Both implementations currently support the same commands:

| Command | Code | Lua | C |
|---------|------|-----|---|
| Ping | 1 | ✅ | ✅ |
| User Login | 38 | ✅ | ✅ |
| Topic Create | 302 | ✅ | ✅ |

## Known Issues and Differences

### Lua-specific Features

These Lua features don't have direct C equivalents:
- Runtime reload without restart
- Easy field experimentation in REPL

**Workaround:** Use incremental builds and restart Wireshark

### C-specific Features

These C features aren't available in Lua:
- Expert info annotations
- Direct memory pool access
- Optimized buffer handling

### Behavior Changes

**TCP Reassembly:**
- Lua: Manual desegmentation hints
- C: Automatic via `tcp_dissect_pdus()`

This means the C dissector may show packets differently if they span TCP segments.

## Testing After Migration

### 1. Verify Basic Functionality

```bash
# Start Iggy server
cargo run --bin iggy-server -- --with-default-root-credentials

# Run protocol tests
cargo test -p wireshark --features protocol-tests
```

### 2. Compare Dissection

Open the same capture in both versions:
1. Use Lua dissector on old capture
2. Use C dissector on same capture
3. Compare field values

### 3. Performance Test

For large captures (>10,000 packets):
```bash
# Time dissection
time tshark -r large_capture.pcap -Y iggy > /dev/null
```

Expect 10-100x speedup with C dissector.

## Troubleshooting

### "Duplicate protocol" error

Both dissectors are loaded. Remove Lua version:
```bash
rm ~/.local/lib/wireshark/plugins/dissector.lua
```

### C plugin not loading

Check for build issues:
```bash
cd wireshark/
make clean
make
```

Verify plugin location:
```bash
ls -la ~/.local/lib/wireshark/plugins/iggy.so
```

### Fields missing or wrong

Verify you're using the C dissector:
1. Check `Help → About → Plugins` for "Iggy Protocol 0.1.0"
2. Check filter field names: `iggy.login.username` (both versions use same names)

### Performance worse with C

This shouldn't happen. Possible causes:
- Debug build instead of release
- Old Wireshark version (<4.0)
- Very small captures where startup overhead dominates

## Rollback to Lua

If you need to rollback:

```bash
# Remove C plugin
make uninstall

# Or manually:
rm ~/.local/lib/wireshark/plugins/iggy.so

# Restore Lua dissector
cp dissector.lua ~/.local/lib/wireshark/plugins/

# Restart Wireshark
```

## Development Workflow Changes

### Lua Development
```bash
# 1. Edit dissector.lua
# 2. Reload: Analyze → Reload Lua Plugins
# 3. Test immediately
```

### C Development
```bash
# 1. Edit packet-iggy.c
# 2. Rebuild: make
# 3. Install: make install
# 4. Restart Wireshark
# 5. Test
```

**Tip:** Use `wireshark -v` to check plugin load errors without starting GUI.

## Adding New Commands

### In Lua
```lua
COMMANDS[404] = {
    name = "my.command",
    fields = { request = {}, response = {} },
    request_payload_dissector = function(self, buffer, tree, offset)
        -- dissection logic
    end,
    response_payload_dissector = function(self, buffer, tree, offset)
        -- dissection logic
    end
}
```

### In C
```c
// 1. Add command constant
#define IGGY_CMD_MY_COMMAND 404

// 2. Add field declarations
static int hf_iggy_my_command_field;

// 3. Add field registration
{ &hf_iggy_my_command_field, { "Field", "iggy.my_command.field", ... } }

// 4. Implement dissector function
static void dissect_my_command_request(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)

// 5. Add case to switch statement
case IGGY_CMD_MY_COMMAND:
    dissect_my_command_request(tvb, payload_tree, &offset);
    break;

// 6. Update get_command_name()
case IGGY_CMD_MY_COMMAND: return "my.command";

// 7. Rebuild and install
```

## Future: Code Generation

To reduce boilerplate, a code generator is planned (see [CODEGEN.md](CODEGEN.md)).

This will automatically:
- Generate field declarations
- Generate dissector functions
- Update switch statements
- Keep protocol definitions in sync

With code generation, adding commands will be as simple as annotating Rust structs:

```rust
#[wireshark(command_code = 404)]
pub struct MyCommand {
    pub field: String,
}
```

## Need Help?

- Build issues: See [BUILD.md](BUILD.md)
- Protocol questions: Check main Iggy documentation
- Feature requests: Open GitHub issue
