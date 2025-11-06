-- Iggy Protocol Dissector
-- Supports Request/Response detection with extensible command registry

local iggy = Proto("iggy", "Iggy Protocol")

----------------------------------------
-- Constants
----------------------------------------
local IGGY_MIN_HEADER_LEN = 8  -- Minimum: LENGTH(4) + CODE/STATUS(4)

----------------------------------------
-- Common Protocol fields (used across all messages)
----------------------------------------
local pf_message_type   = ProtoField.string("iggy.message_type", "Message Type")
local pf_req_length     = ProtoField.uint32("iggy.request.length", "Length", base.DEC)
local pf_req_code       = ProtoField.uint32("iggy.request.code", "Command Code", base.DEC)
local pf_req_code_name  = ProtoField.string("iggy.request.code_name", "Command Name")
local pf_req_payload    = ProtoField.bytes("iggy.request.payload", "Payload")

local pf_resp_status      = ProtoField.uint32("iggy.response.status", "Status", base.DEC)
local pf_resp_status_name = ProtoField.string("iggy.response.status_name", "Status Name")
local pf_resp_length      = ProtoField.uint32("iggy.response.length", "Length", base.DEC)
local pf_resp_payload     = ProtoField.bytes("iggy.response.payload", "Payload")

-- Status code mappings
local status_codes = {
    [0] = "OK",
    [1] = "Error",
    [2] = "InvalidConfiguration",
    [3] = "InvalidCommand",
    [40] = "Unauthenticated",
    [41] = "Unauthorized",
    [42] = "InvalidCredentials",
    [43] = "InvalidUsername",
    [44] = "InvalidPassword",
}

----------------------------------------
-- Expert info
----------------------------------------
local ef_too_short      = ProtoExpert.new("iggy.too_short.expert",
                                          "Iggy packet too short",
                                          expert.group.MALFORMED, expert.severity.ERROR)
local ef_invalid_length = ProtoExpert.new("iggy.invalid_length.expert",
                                          "Invalid length field",
                                          expert.group.MALFORMED, expert.severity.WARN)
local ef_error_status   = ProtoExpert.new("iggy.error_status.expert",
                                          "Error response",
                                          expert.group.RESPONSE_CODE, expert.severity.WARN)

iggy.experts = { ef_too_short, ef_invalid_length, ef_error_status }

----------------------------------------
-- Basic type helpers (for reusability)
----------------------------------------

-- Read basic types (returns value only)
local function read_u8(tvbuf, offset)
    return tvbuf:range(offset, 1):uint()
end

local function read_u32_le(tvbuf, offset)
    return tvbuf:range(offset, 4):le_uint()
end

local function read_u64_le(tvbuf, offset)
    return tvbuf:range(offset, 8):le_uint64()
end

-- Dissect basic types (adds to tree, returns new offset or nil on bounds check failure)
local function dissect_u8(tvbuf, tree, offset, field, pktlen)
    if offset + 1 > pktlen then
        return nil
    end
    tree:add(field, tvbuf:range(offset, 1))
    return offset + 1
end

local function dissect_u32_le(tvbuf, tree, offset, field, pktlen)
    if offset + 4 > pktlen then
        return nil
    end
    tree:add_le(field, tvbuf:range(offset, 4))
    return offset + 4
end

local function dissect_u64_le(tvbuf, tree, offset, field, pktlen)
    if offset + 8 > pktlen then
        return nil
    end
    tree:add_le(field, tvbuf:range(offset, 8))
    return offset + 8
end

----------------------------------------
-- Common data type dissectors
----------------------------------------

-- Dissect Identifier (kind + length + value)
-- Returns: offset after parsing, display_value
local function dissect_identifier(tvbuf, tree, offset, field_name)
    local remaining = tvbuf:len() - offset
    if remaining < 3 then
        return offset, nil
    end

    local kind = read_u8(tvbuf, offset)
    local length = read_u8(tvbuf, offset + 1)

    if remaining < 2 + length then
        return offset, nil
    end

    local kind_name = (kind == 1) and "Numeric" or (kind == 2) and "String" or "Unknown"
    local id_tree = tree:add(string.format("%s: %s (%d bytes)", field_name, kind_name, length))

    id_tree:add(string.format("  Kind: %s (%d)", kind_name, kind), tvbuf:range(offset, 1))
    id_tree:add(string.format("  Length: %d", length), tvbuf:range(offset + 1, 1))

    local display_value = ""
    if kind == 1 and length == 4 then
        -- Numeric identifier (u32 little-endian)
        local value = read_u32_le(tvbuf, offset + 2)
        id_tree:add(string.format("  Value: %d", value), tvbuf:range(offset + 2, 4))
        display_value = tostring(value)
    elseif kind == 2 then
        -- String identifier
        local value = tvbuf:range(offset + 2, length):string()
        id_tree:add(string.format("  Value: %s", value), tvbuf:range(offset + 2, length))
        display_value = value
    else
        id_tree:add("  Value: (raw)", tvbuf:range(offset + 2, length))
        display_value = "(unknown)"
    end

    return offset + 2 + length, display_value
end

-- Dissect Consumer (kind + Identifier)
-- Returns: offset after parsing, display_value
local function dissect_consumer(tvbuf, tree, offset, field_name)
    local remaining = tvbuf:len() - offset
    if remaining < 4 then
        return offset, nil
    end

    local consumer_kind = read_u8(tvbuf, offset)
    local consumer_kind_name = (consumer_kind == 1) and "Consumer" or (consumer_kind == 2) and "ConsumerGroup" or "Unknown"

    local consumer_tree = tree:add(string.format("%s: %s", field_name, consumer_kind_name))
    consumer_tree:add(string.format("  Kind: %s (%d)", consumer_kind_name, consumer_kind), tvbuf:range(offset, 1))

    local new_offset, id_value = dissect_identifier(tvbuf, consumer_tree, offset + 1, "ID")
    if not id_value then
        return offset, nil
    end

    return new_offset, string.format("%s|%s", consumer_kind_name, id_value)
end

----------------------------------------
-- Command Registry
-- Each command has: name, fields (ProtoFields), dissect_payload function
----------------------------------------
local commands = {
    [1] = {
        name = "Ping",
        fields = {},
        dissect_payload = nil,  -- No payload
    },
    [10] = {
        name = "GetStats",
        fields = {},
        dissect_payload = nil,  -- No payload
    },
    [11] = {
        name = "GetSnapshot",
        fields = {},
        dissect_payload = nil,
    },
    [12] = {
        name = "GetClusterMetadata",
        fields = {},
        dissect_payload = nil,
    },
    [20] = {
        name = "GetMe",
        fields = {},
        dissect_payload = nil,
    },
    [21] = {
        name = "GetClient",
        fields = {},
        dissect_payload = nil,
    },
    [22] = {
        name = "GetClients",
        fields = {},
        dissect_payload = nil,
    },
    [31] = {
        name = "GetUser",
        fields = {},
        dissect_payload = nil,
    },
    [32] = {
        name = "GetUsers",
        fields = {},
        dissect_payload = nil,
    },
    [33] = {
        name = "CreateUser",
        fields = {},
        dissect_payload = nil,
    },
    [34] = {
        name = "DeleteUser",
        fields = {},
        dissect_payload = nil,
    },
    [35] = {
        name = "UpdateUser",
        fields = {},
        dissect_payload = nil,
    },
    [36] = {
        name = "UpdatePermissions",
        fields = {},
        dissect_payload = nil,
    },
    [37] = {
        name = "ChangePassword",
        fields = {},
        dissect_payload = nil,
    },
    [38] = {
        name = "LoginUser",
        fields = {
            username_len = ProtoField.uint8("iggy.login.username_len", "Username Length", base.DEC),
            username     = ProtoField.string("iggy.login.username", "Username"),
            password_len = ProtoField.uint8("iggy.login.password_len", "Password Length", base.DEC),
            password     = ProtoField.string("iggy.login.password", "Password"),
            version_len  = ProtoField.uint32("iggy.login.version_len", "Version Length", base.DEC),
            version      = ProtoField.string("iggy.login.version", "Version"),
            context_len  = ProtoField.uint32("iggy.login.context_len", "Context Length", base.DEC),
            context      = ProtoField.string("iggy.login.context", "Context"),
        },
        dissect_payload = function(self, tvbuf, payload_tree, offset, payload_len)
            local pktlen = offset + payload_len

            -- Username (u8 length + string)
            if offset + 1 <= pktlen then
                local username_len = read_u8(tvbuf, offset)
                payload_tree:add(self.fields.username_len, tvbuf:range(offset, 1))
                offset = offset + 1

                if username_len > 0 and offset + username_len <= pktlen then
                    payload_tree:add(self.fields.username, tvbuf:range(offset, username_len))
                    offset = offset + username_len
                end
            end

            -- Password (u8 length + string)
            if offset + 1 <= pktlen then
                local password_len = read_u8(tvbuf, offset)
                payload_tree:add(self.fields.password_len, tvbuf:range(offset, 1))
                offset = offset + 1

                if password_len > 0 and offset + password_len <= pktlen then
                    payload_tree:add(self.fields.password, tvbuf:range(offset, password_len))
                    offset = offset + password_len
                end
            end

            -- Version (u32 length + string)
            if offset + 4 <= pktlen then
                local version_len = read_u32_le(tvbuf, offset)
                payload_tree:add_le(self.fields.version_len, tvbuf:range(offset, 4))
                offset = offset + 4

                if version_len > 0 and offset + version_len <= pktlen then
                    payload_tree:add(self.fields.version, tvbuf:range(offset, version_len))
                    offset = offset + version_len
                end
            end

            -- Context (u32 length + string)
            if offset + 4 <= pktlen then
                local context_len = read_u32_le(tvbuf, offset)
                payload_tree:add_le(self.fields.context_len, tvbuf:range(offset, 4))
                offset = offset + 4

                if context_len > 0 and offset + context_len <= pktlen then
                    payload_tree:add(self.fields.context, tvbuf:range(offset, context_len))
                    offset = offset + context_len
                end
            end
        end,
    },
    [39] = {
        name = "LogoutUser",
        fields = {},
        dissect_payload = nil,
    },
    [121] = {
        name = "StoreConsumerOffset",
        fields = {
            partition_id = ProtoField.uint32("iggy.store_offset.partition_id", "Partition ID", base.DEC),
            offset       = ProtoField.uint64("iggy.store_offset.offset", "Offset", base.DEC),
        },
        dissect_payload = function(self, tvbuf, payload_tree, offset, payload_len)
            local pktlen = offset + payload_len

            -- Consumer (common data type)
            local new_offset, consumer_value = dissect_consumer(tvbuf, payload_tree, offset, "Consumer")
            if not consumer_value then return end
            offset = new_offset

            -- Stream ID (common data type)
            offset, _ = dissect_identifier(tvbuf, payload_tree, offset, "Stream ID")
            if not offset then return end

            -- Topic ID (common data type)
            offset, _ = dissect_identifier(tvbuf, payload_tree, offset, "Topic ID")
            if not offset then return end

            -- Partition ID (u32, 0 = None)
            offset = dissect_u32_le(tvbuf, payload_tree, offset, self.fields.partition_id, pktlen)
            if not offset then return end

            -- Offset (u64)
            offset = dissect_u64_le(tvbuf, payload_tree, offset, self.fields.offset, pktlen)
            if not offset then return end
        end,
    },
}

----------------------------------------
-- Register all protocol fields
----------------------------------------
-- Start with common fields
local all_fields = {
    pf_message_type,
    pf_req_length, pf_req_code, pf_req_code_name, pf_req_payload,
    pf_resp_status, pf_resp_status_name, pf_resp_length, pf_resp_payload,
}

-- Add command-specific fields
for _code, command in pairs(commands) do
    for _field_name, field in pairs(command.fields) do
        table.insert(all_fields, field)
    end
end

iggy.fields = all_fields

----------------------------------------
-- Helper: Detect if packet is request or response
----------------------------------------
local function detect_message_type(tvbuf)
    local pktlen = tvbuf:len()
    if pktlen < 8 then
        return nil
    end

    local first_field = tvbuf:range(0, 4):le_uint()
    local second_field = tvbuf:range(4, 4):le_uint()

    -- Try to detect as Request first
    -- Request format: LENGTH(4) + CODE(4) + PAYLOAD(N)
    -- where LENGTH = CODE(4) + PAYLOAD(N)
    -- Total packet size = 4 + LENGTH
    if commands[second_field] then
        -- second_field is a known command code
        local expected_total = 4 + first_field
        if expected_total == pktlen and first_field >= 4 then
            return "request"
        end
    end

    -- Try to detect as Response
    -- Response format: STATUS(4) + LENGTH(4) + PAYLOAD(N)
    -- Error handling: if STATUS != 0, LENGTH = 0 (no payload)
    -- Success: if STATUS = 0, LENGTH = payload length
    -- Total packet size = 8 + payload_length = 8 + LENGTH

    -- For error responses: STATUS != 0, LENGTH = 0
    if first_field ~= 0 and second_field == 0 and pktlen == 8 then
        return "response"
    end

    -- For success responses: STATUS = 0, LENGTH >= 0
    if first_field == 0 then
        local expected_total = 8 + second_field
        if expected_total == pktlen then
            return "response"
        end
    end

    -- Additional heuristic for responses with unknown status codes
    -- Check if packet size matches the length field assumption
    local expected_total = 8 + second_field
    if expected_total == pktlen and second_field < 1000000 then
        return "response"
    end

    return nil
end

----------------------------------------
-- Request dissector
----------------------------------------
local function dissect_request(tvbuf, pktinfo, tree)
    local pktlen = tvbuf:len()

    -- Check minimum length
    if pktlen < IGGY_MIN_HEADER_LEN then
        return 0
    end

    -- Read LENGTH field (at offset 0)
    -- LENGTH = CODE(4) + PAYLOAD(N)
    local msg_length = tvbuf:range(0, 4):le_uint()

    -- Total message size = LENGTH field (4 bytes) + LENGTH value
    local total_len = 4 + msg_length

    -- Check if we have the complete message
    if pktlen < total_len then
        return 0
    end

    local subtree = tree:add(iggy, tvbuf:range(0, total_len), "Iggy Request")
    subtree:add(pf_message_type, "Request"):set_generated()

    -- LENGTH field
    subtree:add_le(pf_req_length, tvbuf:range(0, 4))

    -- CODE field
    local command_code = tvbuf:range(4, 4):le_uint()
    subtree:add_le(pf_req_code, tvbuf:range(4, 4))

    -- Get command info from registry
    local command_info = commands[command_code]
    local command_name = command_info and command_info.name or string.format("Unknown(0x%x)", command_code)
    subtree:add(pf_req_code_name, command_name):set_generated()

    -- PAYLOAD
    local payload_len = total_len - 8
    if payload_len > 0 then
        local payload_tree = subtree:add(pf_req_payload, tvbuf:range(8, payload_len))

        -- Use command-specific payload dissector if available
        if command_info and command_info.dissect_payload then
            command_info.dissect_payload(command_info, tvbuf, payload_tree, 8, payload_len)
        end
    end

    -- Update info column
    pktinfo.cols.info:set(string.format("Request: %s (code=%d, length=%d)",
                                        command_name, command_code, msg_length))

    -- Validate length
    local expected_length = 4 + payload_len
    if msg_length ~= expected_length then
        subtree:add_proto_expert_info(ef_invalid_length,
            string.format("Length mismatch: field=%d, expected=%d", msg_length, expected_length))
    end

    return total_len
end

----------------------------------------
-- Response dissector
----------------------------------------
local function dissect_response(tvbuf, pktinfo, tree)
    local pktlen = tvbuf:len()

    -- Check minimum length
    if pktlen < IGGY_MIN_HEADER_LEN then
        return 0
    end

    -- Read LENGTH field (at offset 4)
    -- LENGTH = payload length (0 for error responses)
    local msg_length = tvbuf:range(4, 4):le_uint()

    -- Total message size = STATUS(4) + LENGTH(4) + PAYLOAD(LENGTH)
    local total_len = 8 + msg_length

    -- Check if we have the complete message
    if pktlen < total_len then
        return 0
    end

    local subtree = tree:add(iggy, tvbuf:range(0, total_len), "Iggy Response")
    subtree:add(pf_message_type, "Response"):set_generated()

    -- STATUS field
    local status = tvbuf:range(0, 4):le_uint()
    subtree:add_le(pf_resp_status, tvbuf:range(0, 4))

    -- Status name
    local status_name = status_codes[status] or (status == 0 and "OK" or string.format("Error(%d)", status))
    subtree:add(pf_resp_status_name, status_name):set_generated()

    -- LENGTH field
    subtree:add_le(pf_resp_length, tvbuf:range(4, 4))

    -- PAYLOAD
    local payload_len = total_len - 8
    if payload_len > 0 then
        subtree:add(pf_resp_payload, tvbuf:range(8, payload_len))
    end

    -- Update info column
    if status == 0 then
        pktinfo.cols.info:set(string.format("Response: OK (length=%d)", msg_length))
    else
        pktinfo.cols.info:set(string.format("Response: %s (status=%d, length=%d)",
                                            status_name, status, msg_length))
        subtree:add_proto_expert_info(ef_error_status,
            string.format("Error status: %d", status))
    end

    -- Validate: error responses should have length=0
    if status ~= 0 and msg_length ~= 0 then
        subtree:add_proto_expert_info(ef_invalid_length,
            "Error response should have length=0")
    end

    return total_len
end

----------------------------------------
-- Main dissector
----------------------------------------
function iggy.dissector(tvbuf, pktinfo, root)
    pktinfo.cols.protocol:set("IGGY")

    local msg_type = detect_message_type(tvbuf)

    if msg_type == "request" then
        return dissect_request(tvbuf, pktinfo, root)
    elseif msg_type == "response" then
        return dissect_response(tvbuf, pktinfo, root)
    else
        local tree = root:add(iggy, tvbuf(), "Iggy Protocol (Unknown)")
        tree:add_proto_expert_info(ef_too_short, "Cannot determine message type")
        return 0
    end
end

----------------------------------------
-- Heuristic dissector
----------------------------------------
local function heur_dissect_iggy(tvbuf, pktinfo, root)
    if tvbuf:len() < 8 then
        return false
    end

    local msg_type = detect_message_type(tvbuf)

    if not msg_type then
        return false
    end

    iggy.dissector(tvbuf, pktinfo, root)
    pktinfo.conversation = iggy

    return true
end

iggy:register_heuristic("tcp", heur_dissect_iggy)
