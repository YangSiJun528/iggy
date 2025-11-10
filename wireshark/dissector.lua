-- Iggy Protocol Dissector
-- Supports Request/Response detection with extensible command registry
--
-- Error Handling Convention:
--   ALL error conditions MUST use ProtoExpert (tree:add_proto_expert_info)
--   NEVER use plain tree:add() for error/warning conditions
--   This ensures errors are visible in Wireshark's Expert Info system
--
-- Exception Handling Patterns:
--   1. Helper functions that can fail:
--      - Return nil on error AND add expert info to tree
--      - Caller checks return value: if not offset then return end
--   2. Dissector functions:
--      - Always use subtree:add_proto_expert_info(ef_*, "description")
--      - Never silently ignore errors
--   3. Validation checks:
--      - Use specific expert info for each error type (malformed, protocol error, etc.)
--      - Include relevant details in error message (offsets, expected vs actual values)

local iggy = Proto("iggy", "Iggy Protocol")

----------------------------------------
-- Preferences
----------------------------------------
iggy.prefs.server_port = Pref.uint("Server Port", 8090, "Target TCP server port")

----------------------------------------
-- Fields
-- Naming convention:
--   f_message_type         - Common fields (applies to both request and response)
--   f_req_*                - Request common fields (all requests)
--   f_resp_*               - Response common fields (all responses)
--   f_<cmdname>_*          - Command-specific fields (e.g., f_login_* for LoginUser command)
--
-- Reference: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField
--   ProtoField.some_type(abbr, [name], [base], [valuestring], [mask], [description])
----------------------------------------
-- Common fields
local f_message_type = ProtoField.string("iggy.message_type", "Message Type")

-- Request common fields
local f_req_length = ProtoField.uint32("iggy.request.length", "Length", base.DEC, nil, nil, "Length of command code + payload")
local f_req_command = ProtoField.uint32("iggy.request.command", "Command Code", base.DEC)
local f_req_command_name = ProtoField.string("iggy.request.command_name", "Command Name")
local f_req_payload = ProtoField.bytes("iggy.request.payload", "Payload")

-- Response common fields
local f_resp_status = ProtoField.uint32("iggy.response.status", "Status Code", base.DEC)
local f_resp_status_name = ProtoField.string("iggy.response.status_name", "Status Name")
local f_resp_length = ProtoField.uint32("iggy.response.length", "Length", base.DEC, nil, nil, "Length of payload")
local f_resp_payload = ProtoField.bytes("iggy.response.payload", "Payload")

-- Command-specific fields: LoginUser (code=38)
local f_login_username_len = ProtoField.uint8("iggy.login.username_len", "Username Length", base.DEC)
local f_login_username = ProtoField.string("iggy.login.username", "Username")
local f_login_password_len = ProtoField.uint8("iggy.login.password_len", "Password Length", base.DEC)
local f_login_password = ProtoField.string("iggy.login.password", "Password")
local f_login_version_len = ProtoField.uint32("iggy.login.version_len", "Version Length", base.DEC)
local f_login_version = ProtoField.string("iggy.login.version", "Version")
local f_login_context_len = ProtoField.uint32("iggy.login.context_len", "Context Length", base.DEC)
local f_login_context = ProtoField.string("iggy.login.context", "Context")
local f_login_user_id = ProtoField.uint32("iggy.login.user_id", "User ID", base.DEC)

iggy.fields = {
    f_message_type,
    f_req_length, f_req_command, f_req_command_name, f_req_payload,
    f_resp_status, f_resp_status_name, f_resp_length, f_resp_payload,
    -- LoginUser fields
    f_login_username_len, f_login_username, f_login_password_len, f_login_password,
    f_login_version_len, f_login_version, f_login_context_len, f_login_context,
    f_login_user_id,
}

----------------------------------------
-- Expert Info
-- Naming convention: ef_<category>_<specific>
----------------------------------------
-- Malformed packet errors
local ef_malformed_too_short = ProtoExpert.new("iggy.malformed.too_short", "Packet too short", expert.group.MALFORMED, expert.severity.ERROR)
local ef_malformed_invalid_length = ProtoExpert.new("iggy.malformed.invalid_length", "Invalid length field", expert.group.MALFORMED, expert.severity.WARN)
local ef_malformed_incomplete_payload = ProtoExpert.new("iggy.malformed.incomplete_payload", "Incomplete payload", expert.group.MALFORMED, expert.severity.ERROR)

-- Protocol-specific warnings
local ef_protocol_error_status = ProtoExpert.new("iggy.protocol.error_status", "Error response", expert.group.RESPONSE_CODE, expert.severity.WARN)
local ef_protocol_unknown_request = ProtoExpert.new("iggy.protocol.unknown_request", "Request not captured or unknown", expert.group.SEQUENCE, expert.severity.NOTE)

iggy.experts = {
    ef_malformed_too_short,
    ef_malformed_invalid_length,
    ef_malformed_incomplete_payload,
    ef_protocol_error_status,
    ef_protocol_unknown_request,
}

----------------------------------------
-- Helper functions
----------------------------------------

-- Read u8
local function read_u8(buffer, offset)
    if offset + 1 > buffer:len() then
        return nil
    end
    return buffer(offset, 1):uint()
end

-- Read u32 (little-endian)
local function read_u32_le(buffer, offset)
    if offset + 4 > buffer:len() then
        return nil
    end
    return buffer(offset, 4):le_uint()
end

-- Dissect string with u8 length prefix
-- Returns new offset or nil on error (with expert info added to tree)
local function dissect_string_u8_len(buffer, tree, offset, len_field, str_field)
    local buflen = buffer:len()
    if offset + 1 > buflen then
        tree:add_proto_expert_info(ef_malformed_incomplete_payload,
            string.format("Cannot read string length at offset %d", offset))
        return nil
    end

    local str_len = buffer(offset, 1):uint()
    tree:add(len_field, buffer(offset, 1))

    if offset + 1 + str_len > buflen then
        tree:add_proto_expert_info(ef_malformed_incomplete_payload,
            string.format("String data incomplete: expected %d bytes at offset %d", str_len, offset + 1))
        return nil
    end

    if str_len > 0 then
        tree:add(str_field, buffer(offset + 1, str_len))
    end

    return offset + 1 + str_len
end

-- Dissect string with u32 length prefix (little-endian)
-- Returns new offset or nil on error (with expert info added to tree)
local function dissect_string_u32_le_len(buffer, tree, offset, len_field, str_field)
    local buflen = buffer:len()
    if offset + 4 > buflen then
        tree:add_proto_expert_info(ef_malformed_incomplete_payload,
            string.format("Cannot read string length at offset %d", offset))
        return nil
    end

    local str_len = buffer(offset, 4):le_uint()
    tree:add_le(len_field, buffer(offset, 4))

    if offset + 4 + str_len > buflen then
        tree:add_proto_expert_info(ef_malformed_incomplete_payload,
            string.format("String data incomplete: expected %d bytes at offset %d", str_len, offset + 4))
        return nil
    end

    if str_len > 0 then
        tree:add(str_field, buffer(offset + 4, str_len))
    end

    return offset + 4 + str_len
end

----------------------------------------
-- TCP stream tracking for request-response matching
-- Each TCP stream has a FIFO queue of request command codes
----------------------------------------
local stream_request_queues = {}
local tcp_stream_field = Field.new("tcp.stream")

-- Helper: Enqueue a request code for a TCP stream
local function enqueue_request(stream_id, command_code)
    if not stream_request_queues[stream_id] then
        stream_request_queues[stream_id] = {}
    end
    table.insert(stream_request_queues[stream_id], command_code)
end

-- Helper: Dequeue a request code for a TCP stream
local function dequeue_request(stream_id)
    local queue = stream_request_queues[stream_id]
    if not queue or #queue == 0 then
        return nil
    end
    local command_code = table.remove(queue, 1)

    -- Clean up empty queue to prevent memory accumulation
    if #queue == 0 then
        stream_request_queues[stream_id] = nil
    end

    return command_code
end

----------------------------------------
-- Command Registry
-- Each command MUST have:
--   - name: Command name (non-empty string)
--   - request_payload_dissector: function(buffer, tree, offset) - NEVER nil, use empty function if no payload
--   - response_payload_dissector: function(buffer, tree, offset) - NEVER nil, use empty function if no payload
--
-- Why dissectors can't be nil:
--   If COMMANDS[code] exists but dissector is nil, we can't tell if:
--     1. The command has no payload (expected), or
--     2. Someone forgot to implement the dissector (bug)
--   Always use explicit empty function for no-payload commands.
----------------------------------------
local COMMANDS = {
    [1] = {
        name = "Ping",
        request_payload_dissector = function(buffer, tree, offset)
            -- No request payload
        end,
        response_payload_dissector = function(buffer, tree, offset)
            -- No response payload
        end,
    },
    [38] = {
        name = "LoginUser",
        request_payload_dissector = function(buffer, tree, offset)
            -- Username (u8 length + string)
            offset = dissect_string_u8_len(buffer, tree, offset, f_login_username_len, f_login_username)
            if not offset then return end

            -- Password (u8 length + string)
            offset = dissect_string_u8_len(buffer, tree, offset, f_login_password_len, f_login_password)
            if not offset then return end

            -- Version (u32 length + string, optional)
            offset = dissect_string_u32_le_len(buffer, tree, offset, f_login_version_len, f_login_version)
            if not offset then return end

            -- Context (u32 length + string, optional)
            offset = dissect_string_u32_le_len(buffer, tree, offset, f_login_context_len, f_login_context)
            if not offset then return end
        end,
        response_payload_dissector = function(buffer, tree, offset)
            -- LoginUser response payload: user_id (u32, little-endian)
            -- Reference: core/binary_protocol/src/utils/mapper.rs:455-465
            local buflen = buffer:len()

            -- Need 4 bytes for user_id
            if offset + 4 > buflen then
                tree:add_proto_expert_info(ef_malformed_incomplete_payload,
                    "LoginUser response: expected 4 bytes for user_id")
                return
            end

            -- Parse user_id (u32, little-endian)
            tree:add_le(f_login_user_id, buffer(offset, 4))
        end,
    },
}

-- Validate all registered commands
for code, cmd in pairs(COMMANDS) do
    assert(type(code) == "number", "Command code must be a number")
    assert(type(cmd.name) == "string" and cmd.name ~= "",
        string.format("Command %d: name must be a non-empty string", code))
    assert(type(cmd.request_payload_dissector) == "function",
        string.format("Command %d (%s): request_payload_dissector must be a function (use empty function if no payload)", code, cmd.name))
    assert(type(cmd.response_payload_dissector) == "function",
        string.format("Command %d (%s): response_payload_dissector must be a function (use empty function if no payload)", code, cmd.name))
end

----------------------------------------
-- Status Code Registry
----------------------------------------
local STATUS_CODES = {
    [0] = "OK",
    [2] = "Unauthenticated",
    -- Add more status codes as needed
}

----------------------------------------
-- Helper: Validate request format
----------------------------------------
local function is_valid_request(buffer)
    local buflen = buffer:len()
    if buflen < 8 then
        return false
    end

    local first_field = buffer(0, 4):le_uint()
    local second_field = buffer(4, 4):le_uint()

    -- Request format: LENGTH(4) + CODE(4) + PAYLOAD(N)
    -- where LENGTH = CODE(4) + PAYLOAD(N)
    -- Total packet size = 4 + LENGTH

    -- Check if second field is a known command code
    if COMMANDS[second_field] then
        local expected_total = 4 + first_field
        if expected_total == buflen and first_field >= 4 then
            return true
        end
    end

    return false
end

----------------------------------------
-- Helper: Validate response format
----------------------------------------
local function is_valid_response(buffer)
    local buflen = buffer:len()
    if buflen < 8 then
        return false
    end

    local first_field = buffer(0, 4):le_uint()
    local second_field = buffer(4, 4):le_uint()

    -- Response format: STATUS(4) + LENGTH(4) + PAYLOAD(N)
    -- Total packet size = 8 + LENGTH

    -- For error responses: STATUS != 0, LENGTH = 0
    if first_field ~= 0 and second_field == 0 and buflen == 8 then
        return true
    end

    -- For success responses: STATUS = 0, LENGTH >= 0
    if first_field == 0 then
        local expected_total = 8 + second_field
        if expected_total == buflen then
            return true
        end
    end

    -- Additional heuristic for responses with unknown status codes
    local expected_total = 8 + second_field
    if expected_total == buflen and second_field < 1000000 then
        return true
    end

    return false
end

----------------------------------------
-- Request dissector
----------------------------------------
local function dissect_request(buffer, pinfo, tree)
    local buflen = buffer:len()

    if buflen < 8 then
        return 0
    end

    local length = buffer(0, 4):le_uint()
    local total_len = 4 + length

    if buflen < total_len then
        return 0
    end

    local subtree = tree:add(iggy, buffer(0, total_len), "Iggy Protocol - Request")
    subtree:add(f_message_type, "Request"):set_generated()

    -- Length field
    subtree:add_le(f_req_length, buffer(0, 4))

    -- Command code
    local command_code = buffer(4, 4):le_uint()
    subtree:add_le(f_req_command, buffer(4, 4))

    -- Command name
    local command_info = COMMANDS[command_code]
    local command_name = command_info and command_info.name or string.format("Unknown(0x%x)", command_code)
    subtree:add(f_req_command_name, command_name):set_generated()

    -- Payload
    local payload_len = total_len - 8
    if payload_len > 0 then
        local payload_tree = subtree:add(f_req_payload, buffer(8, payload_len))

        -- Use command-specific request payload dissector
        if command_info then
            command_info.request_payload_dissector(buffer, payload_tree, 8)
        end
    end

    -- Track request code for request-response matching
    local tcp_stream = tcp_stream_field()
    if tcp_stream then
        enqueue_request(tcp_stream.value, command_code)
    end

    -- Update info column
    pinfo.cols.info:set(string.format("Request: %s (code=%d, length=%d)", command_name, command_code, length))

    -- Validate length
    local expected_length = 4 + payload_len
    if length ~= expected_length then
        subtree:add_proto_expert_info(ef_malformed_invalid_length,
            string.format("Length mismatch: field=%d, expected=%d", length, expected_length))
    end

    return total_len
end

----------------------------------------
-- Response dissector
----------------------------------------
local function dissect_response(buffer, pinfo, tree)
    local buflen = buffer:len()

    if buflen < 8 then
        return 0
    end

    local status = buffer(0, 4):le_uint()
    local length = buffer(4, 4):le_uint()
    local total_len = 8 + length

    if buflen < total_len then
        return 0
    end

    local subtree = tree:add(iggy, buffer(0, total_len), "Iggy Protocol - Response")
    subtree:add(f_message_type, "Response"):set_generated()

    -- Status code
    subtree:add_le(f_resp_status, buffer(0, 4))

    -- Status name
    local status_name = STATUS_CODES[status] or (status == 0 and "OK" or string.format("Error(%d)", status))
    subtree:add(f_resp_status_name, status_name):set_generated()

    -- Length field
    subtree:add_le(f_resp_length, buffer(4, 4))

    -- Get matching request code for this TCP stream (FIFO order)
    local tcp_stream = tcp_stream_field()
    local command_code = tcp_stream and dequeue_request(tcp_stream.value)
    local command_info = command_code and COMMANDS[command_code]

    -- Add command name to response if we know which request this is responding to
    if command_info then
        subtree:add(f_req_command_name, command_info.name):set_generated()
    end

    -- Payload
    local payload_len = total_len - 8
    if payload_len > 0 then
        local payload_tree = subtree:add(f_resp_payload, buffer(8, payload_len))

        if command_info then
            -- Use command-specific response payload dissector (only for success responses)
            if status == 0 then
                -- Call response payload dissector with full buffer and offset pointing to payload start
                command_info.response_payload_dissector(buffer, payload_tree, 8)
            else
                -- Error response with payload (protocol violation will be flagged below)
                -- Payload might contain error message, but we don't parse it
            end
        else
            -- Request not captured or unknown - cannot match response to request
            payload_tree:add_proto_expert_info(ef_protocol_unknown_request,
                "Cannot dissect payload: request not captured or unknown command")
        end
    elseif not command_info then
        -- No payload and unknown request
        subtree:add_proto_expert_info(ef_protocol_unknown_request,
            "Request not captured or unknown command")
    end

    -- Update info column
    local command_name_str = command_info and command_info.name or "Unknown"
    if status == 0 then
        pinfo.cols.info:set(string.format("Response: %s OK (length=%d)", command_name_str, length))
    else
        pinfo.cols.info:set(string.format("Response: %s %s (status=%d, length=%d)",
            command_name_str, status_name, status, length))
        subtree:add_proto_expert_info(ef_protocol_error_status, string.format("Error status: %d", status))
    end

    -- Validate: error responses should have length=0
    if status ~= 0 and length ~= 0 then
        subtree:add_proto_expert_info(ef_malformed_invalid_length, "Error response should have length=0")
    end

    return total_len
end

----------------------------------------
-- Main dissector
----------------------------------------
function iggy.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("IGGY")

    -- Check for TCP connection termination and clean up queue
    local tcp_stream = tcp_stream_field()
    local tcp_flags_fin = Field.new("tcp.flags.fin")
    local tcp_flags_reset = Field.new("tcp.flags.reset")

    local fin = tcp_flags_fin()
    local rst = tcp_flags_reset()

    if tcp_stream and (fin or rst) then
        -- Clean up queue when connection closes (FIN or RST)
        stream_request_queues[tcp_stream.value] = nil
    end

    local buflen = buffer:len()

    -- TCP Desegmentation: Step 1 - Check minimum header size
    if buflen < 4 then
        -- Need at least 4 bytes to read the first field (length or status)
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return
    end

    -- Determine direction based on port
    local server_port = iggy.prefs.server_port
    local is_request = (pinfo.dst_port == server_port)
    local is_response = (pinfo.src_port == server_port)

    -- TCP Desegmentation: Step 2 - Calculate required length based on direction
    if is_request then
        -- Assume this is a request, validate format
        if is_valid_request(buffer) then
            -- Request format: LENGTH(4) + CODE(4) + PAYLOAD(N)
            -- Total size = 4 + LENGTH
            local length = buffer(0, 4):le_uint()
            local total_len = 4 + length

            if buflen < total_len then
                pinfo.desegment_len = total_len - buflen
                return
            end

            return dissect_request(buffer, pinfo, tree)
        else
            -- Port indicates request, but format doesn't match
            local subtree = tree:add(iggy, buffer(), "Iggy Protocol (Malformed)")
            subtree:add_proto_expert_info(ef_malformed_invalid_length,
                string.format("Expected request format (dst_port=%d), but format validation failed", server_port))
            pinfo.cols.info:set("Malformed request")
            return 0
        end

    elseif is_response then
        -- Assume this is a response, validate format
        if is_valid_response(buffer) then
            -- Response format: STATUS(4) + LENGTH(4) + PAYLOAD(N)
            -- Need at least 8 bytes to read header
            if buflen < 8 then
                pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                return
            end

            local payload_len = buffer(4, 4):le_uint()
            local total_len = 8 + payload_len

            if buflen < total_len then
                pinfo.desegment_len = total_len - buflen
                return
            end

            return dissect_response(buffer, pinfo, tree)
        else
            -- Port indicates response, but format doesn't match
            local subtree = tree:add(iggy, buffer(), "Iggy Protocol (Malformed)")
            subtree:add_proto_expert_info(ef_malformed_invalid_length,
                string.format("Expected response format (src_port=%d), but format validation failed", server_port))
            pinfo.cols.info:set("Malformed response")
            return 0
        end

    else
        -- Neither request nor response port - shouldn't happen with port-based registration
        if buflen < 8 then
            local subtree = tree:add(iggy, buffer(), "Iggy Protocol (Malformed)")
            subtree:add_proto_expert_info(ef_malformed_too_short)
            pinfo.cols.info:set("Malformed packet (too short)")
            return 0
        end

        local subtree = tree:add(iggy, buffer(), "Iggy Protocol (Unknown)")
        pinfo.cols.info:set(string.format("Unknown direction (src=%d, dst=%d, server=%d)",
            pinfo.src_port, pinfo.dst_port, server_port))
        return 0
    end
end

----------------------------------------
-- Port registration management
----------------------------------------
local current_port = 0

function iggy.init()
    -- Clear request queues to prevent memory accumulation
    stream_request_queues = {}

    local tcp_port = DissectorTable.get("tcp.port")

    -- Remove old port registration if exists
    if current_port > 0 then
        tcp_port:remove(current_port, iggy)
    end

    -- Register new port
    current_port = iggy.prefs.server_port
    if current_port > 0 then
        tcp_port:add(current_port, iggy)
    end
end
