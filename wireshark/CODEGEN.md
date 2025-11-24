# Code Generation for Iggy Wireshark Dissector

This document describes the planned code generation system for automatically maintaining the Iggy C dissector based on protocol definitions.

## Motivation

The Iggy protocol has many commands with complex payloads. Manually maintaining dissector code for each command is:
- Time-consuming and error-prone
- Requires keeping dissector code in sync with protocol changes
- Makes it hard to ensure complete coverage

A code generator solves these issues by:
- Automatically generating dissector functions from protocol specs
- Ensuring consistency between protocol implementation and dissector
- Making it easy to add new commands or update existing ones

## Architecture

### Input Sources

The generator will read protocol definitions from:

1. **Rust source code**: Parse command definitions from `sdk/src/command.rs` or similar
2. **Protocol specification**: JSON/YAML schema describing message formats
3. **Annotations**: Special comments or attributes in Rust code

### Output

The generator produces:
- Field declarations (`hf_` variables)
- Field registration array entries
- Dissector functions for request/response payloads
- Command name mappings
- Value string arrays for enumerations

### Generation Modes

- **Full generation**: Complete dissector from scratch
- **Incremental**: Update only changed commands
- **Validation**: Check existing code against protocol spec

## Implementation Approaches

### Option 1: Parse Rust Code

Use Rust's `syn` crate to parse protocol definitions:

```rust
use syn::{parse_file, Item};

fn parse_protocol_definitions(rust_code: &str) -> Vec<Command> {
    let ast = parse_file(rust_code)?;

    for item in ast.items {
        if let Item::Struct(s) = item {
            // Extract command structure
        }
    }
}
```

**Pros:**
- Single source of truth (Rust code)
- Automatically stays in sync
- Can reuse serialization logic

**Cons:**
- Complex parsing of Rust type system
- May not capture all wire format details
- Requires understanding Rust macros and traits

### Option 2: Protocol Specification File

Define messages in a declarative format:

```yaml
commands:
  - code: 1
    name: ping
    request: {}
    response: {}

  - code: 38
    name: user.login
    request:
      - name: username
        type: length_prefixed_string
        length_type: u8
      - name: password
        type: length_prefixed_string
        length_type: u8
      - name: version
        type: optional_length_prefixed_string
        length_type: u32
      - name: context
        type: optional_length_prefixed_string
        length_type: u32
    response:
      - name: user_id
        type: u32
        encoding: little_endian
```

**Pros:**
- Simple, declarative format
- Easy to understand and modify
- Language-agnostic

**Cons:**
- Extra file to maintain
- Could get out of sync with implementation
- Duplication of information

### Option 3: Hybrid Approach (Recommended)

Combine both approaches:
1. Extract structure from Rust code
2. Supplement with wire format annotations
3. Generate dissector code

```rust
#[derive(Serialize, Deserialize)]
#[wireshark(command_code = 38, name = "user.login")]
pub struct LoginUser {
    #[wireshark(type = "length_prefixed_string", length_type = "u8")]
    pub username: String,

    #[wireshark(type = "length_prefixed_string", length_type = "u8")]
    pub password: String,

    #[wireshark(type = "optional_length_prefixed_string", length_type = "u32")]
    pub version: Option<String>,

    #[wireshark(type = "optional_length_prefixed_string", length_type = "u32")]
    pub context: Option<String>,
}
```

## Code Generation Tool

### Structure

```
wireshark/
├── codegen/
│   ├── Cargo.toml          # Code generator package
│   ├── src/
│   │   ├── main.rs         # CLI entry point
│   │   ├── parser.rs       # Parse protocol definitions
│   │   ├── generator.rs    # Generate C code
│   │   └── templates/      # Code templates
│   └── README.md
├── packet-iggy.c           # Generated output (with markers)
└── packet-iggy-manual.c    # Manual additions
```

### Usage

```bash
# Generate dissector code
cargo run --bin iggy-wireshark-codegen

# Output files
# - packet-iggy-generated.c (fields and dissectors)
# - packet-iggy-generated.h (declarations)

# Manual code includes generated files
#include "packet-iggy-generated.h"
```

### Code Templates

Use template system (e.g., Tera, Handlebars) for generating C code:

**Field declaration template:**
```c
// Generated field for {{command_name}}.{{field_name}}
static int hf_iggy_{{command_snake}}_{{field_snake}};
```

**Field registration template:**
```c
{ &hf_iggy_{{command_snake}}_{{field_snake}},
    { "{{field_display_name}}", "iggy.{{command_name}}.{{field_name}}",
    FT_{{field_type}}, BASE_{{base_format}}, {{value_strings}}, 0x0,
    {{description}}, HFILL }
},
```

**Dissector function template:**
```c
static void
dissect_{{command_snake}}_request(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    {{#each fields}}
    {{#if length_prefix}}
    {{type}} {{name}}_len = tvb_get_{{read_function}}(tvb, *offset);
    proto_tree_add_item(tree, hf_iggy_{{../command_snake}}_{{snake name}}_len, tvb, *offset, {{length_size}}, {{encoding}});
    *offset += {{length_size}};
    {{/if}}

    proto_tree_add_item(tree, hf_iggy_{{../command_snake}}_{{snake name}}, tvb, *offset, {{size_expr}}, {{encoding}});
    *offset += {{size_expr}};
    {{/each}}
}
```

## Integration with Build System

### CMake Integration

```cmake
# Check if codegen tool exists
find_program(IGGY_CODEGEN iggy-wireshark-codegen)

if(IGGY_CODEGEN)
    # Generate code during build
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/packet-iggy-generated.c
        COMMAND ${IGGY_CODEGEN} --output ${CMAKE_CURRENT_SOURCE_DIR}
        DEPENDS ${IGGY_SDK_PATH}/src/command.rs
        COMMENT "Generating Iggy dissector code"
    )
else()
    message(WARNING "iggy-wireshark-codegen not found, using pre-generated code")
endif()
```

### Makefile Integration

```makefile
CODEGEN = cargo run --manifest-path codegen/Cargo.toml --

.PHONY: generate
generate:
	$(CODEGEN) --output .
	@echo "Dissector code generated"

build: generate
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. && cmake --build .
```

## Future Enhancements

### 1. Bidirectional Inference

Automatically detect request/response pairs:
```rust
#[wireshark(response_to = "LoginUser")]
pub struct LoginUserResponse {
    pub user_id: u32,
}
```

### 2. Enum Value Strings

Generate value_string arrays from Rust enums:
```rust
#[derive(Serialize, Deserialize)]
#[wireshark(generate_value_strings)]
pub enum Status {
    Ok = 0,
    Error = 1,
    InvalidCommand = 3,
}

// Generates:
// static const value_string iggy_status_vals[] = {
//     { 0, "OK" },
//     { 1, "Error" },
//     { 3, "Invalid Command" },
//     { 0, NULL }
// };
```

### 3. Conditional Dissection

Handle protocol variations based on version or flags:
```rust
#[wireshark(if = "version >= 2")]
pub compression: Option<CompressionType>,
```

### 4. Expert Info Generation

Automatically add expert info for unusual values:
```rust
#[wireshark(expert_warn_if = "replication_factor > 5")]
pub replication_factor: u8,
```

### 5. Test Generation

Generate test cases from examples:
```rust
#[wireshark(test_case = "login_success")]
pub struct LoginUser {
    // Generates test that verifies dissection of login_success.pcap
}
```

## Migration Plan

1. **Phase 1**: Create basic code generator for field declarations
2. **Phase 2**: Add dissector function generation
3. **Phase 3**: Integrate with build system
4. **Phase 4**: Add advanced features (enums, conditional dissection)
5. **Phase 5**: Generate tests and documentation

## Example: Generated Code

Input:
```rust
#[wireshark(command_code = 38, name = "user.login")]
pub struct LoginUser {
    #[wireshark(type = "length_prefixed_string", length_type = "u8")]
    pub username: String,

    #[wireshark(type = "length_prefixed_string", length_type = "u8")]
    pub password: String,
}
```

Output:
```c
// Generated by iggy-wireshark-codegen - DO NOT EDIT
#define IGGY_CMD_USER_LOGIN 38

static int hf_iggy_login_username_len;
static int hf_iggy_login_username;
static int hf_iggy_login_password_len;
static int hf_iggy_login_password;

static void
dissect_user_login_request(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t username_len = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_iggy_login_username_len, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_iggy_login_username, tvb, *offset, username_len, ENC_UTF_8);
    *offset += username_len;

    uint8_t password_len = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_iggy_login_password_len, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_iggy_login_password, tvb, *offset, password_len, ENC_UTF_8);
    *offset += password_len;
}

// Field registration entries
{ &hf_iggy_login_username_len,
    { "Username Length", "iggy.login.username_len",
    FT_UINT8, BASE_DEC, NULL, 0x0,
    NULL, HFILL }
},
{ &hf_iggy_login_username,
    { "Username", "iggy.login.username",
    FT_STRING, BASE_NONE, NULL, 0x0,
    NULL, HFILL }
},
// ... more fields
```

## References

- [Rust syn crate](https://docs.rs/syn/)
- [Tera templates](https://tera.netlify.app/)
- [Protocol Buffers approach](https://developers.google.com/protocol-buffers)
- [Cap'n Proto code generation](https://capnproto.org/otherlang.html)
