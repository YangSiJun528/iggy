-- Iggy Protocol Dissector
-- ref: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_Proto
local iggy = Proto("iggy", "Iggy Protocol")

----------------------------------------
-- Preferences
----------------------------------------
iggy.prefs.server_port = Pref.uint("Server Port", 8090, "Target TCP server port")

----------------------------------------
-- Expert Info
----------------------------------------
local ef_too_short = ProtoExpert.new("iggy.too_short", "Packet too short", expert.group.MALFORMED, expert.severity.ERROR)
local ef_invalid_length = ProtoExpert.new("iggy.invalid_length", "Invalid length field", expert.group.MALFORMED, expert.severity.WARN)
local ef_error_status = ProtoExpert.new("iggy.error_status", "Error response", expert.group.RESPONSE_CODE, expert.severity.WARN)

iggy.experts = { ef_too_short, ef_invalid_length, ef_error_status }

----------------------------------------
-- Fields
-- Naming convention:
--   f_message_type         - Common fields (applies to both request and response)
--   f_req_*                - Request common fields (all requests)
--   f_resp_*               - Response common fields (all responses)
--   f_<cmdname>_req_*      - Command-specific request fields (e.g., f_login_req_username)
--   f_<cmdname>_resp_*     - Command-specific response fields (e.g., f_login_resp_user_id)
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

-- Command-specific fields
-- LoginUser (code=38)
-- Request fields
local f_login_req_username_len = ProtoField.uint8("iggy.login.req.username_len", "Username Length", base.DEC)
local f_login_req_username = ProtoField.string("iggy.login.req.username", "Username")
local f_login_req_password_len = ProtoField.uint8("iggy.login.req.password_len", "Password Length", base.DEC)
local f_login_req_password = ProtoField.string("iggy.login.req.password", "Password")
local f_login_req_version_len = ProtoField.uint32("iggy.login.req.version_len", "Version Length", base.DEC)
local f_login_req_version = ProtoField.string("iggy.login.req.version", "Version")
local f_login_req_context_len = ProtoField.uint32("iggy.login.req.context_len", "Context Length", base.DEC)
local f_login_req_context = ProtoField.string("iggy.login.req.context", "Context")
-- Response fields
local f_login_resp_user_id = ProtoField.uint32("iggy.login.resp.user_id", "User ID", base.DEC)

iggy.fields = {
    f_message_type,
    f_req_length, f_req_command, f_req_command_name, f_req_payload,
    f_resp_status, f_resp_status_name, f_resp_length, f_resp_payload,
    -- LoginUser request fields
    f_login_req_username_len, f_login_req_username, f_login_req_password_len, f_login_req_password,
    f_login_req_version_len, f_login_req_version, f_login_req_context_len, f_login_req_context,
    -- LoginUser response fields
    f_login_resp_user_id,
}

----------------------------------------
-- Command Registry
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
            -- Username & Password at least 3 bytes: core/common/src/commands/users/defaults.rs

            -- Username (u8 length + string)
            local username_len = buffer(offset, 1):uint()
            tree:add(f_login_req_username_len, buffer(offset, 1))
            offset = offset + 1
            tree:add(f_login_req_username, buffer(offset, username_len))
            offset = offset + username_len

            -- Password (u8 length + string)
            local password_len = buffer(offset, 1):uint()
            tree:add(f_login_req_password_len, buffer(offset, 1))
            offset = offset + 1
            tree:add(f_login_req_password, buffer(offset, password_len))
            offset = offset + password_len

            -- Version (u32 length + string, optional)
            local version_len = buffer(offset, 4):le_uint()
            tree:add_le(f_login_req_version_len, buffer(offset, 4))
            offset = offset + 4
            if version_len > 0 then
                tree:add(f_login_req_version, buffer(offset, version_len))
                offset = offset + version_len
            end

            -- Context (u32 length + string, optional)
            local context_len = buffer(offset, 4):le_uint()
            tree:add_le(f_login_req_context_len, buffer(offset, 4))
            offset = offset + 4
            if context_len > 0 then
                tree:add(f_login_req_context, buffer(offset, context_len))
            end
        end,
        response_payload_dissector = function(buffer, tree, offset)
            -- see: core/binary_protocol/src/utils/mapper.rs:455
            tree:add_le(f_login_resp_user_id, buffer(offset, 4))
        end,
    },
}

-- Validate all registered commands
local dissector_err = "must be function, not nil (nil is ambiguous: no payload or unimplemented)"
for code, cmd in pairs(COMMANDS) do
    assert(type(code) == "number", "Command code must be a number")
    assert(type(cmd.name) == "string" and cmd.name:match("%S"),
        string.format("Command %d: name must be non-empty string", code))
    assert(type(cmd.request_payload_dissector) == "function",
        string.format("Command %d (%s): request_payload_dissector %s", code, cmd.name, dissector_err))
    assert(type(cmd.response_payload_dissector) == "function",
        string.format("Command %d (%s): response_payload_dissector %s", code, cmd.name, dissector_err))
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
-- TCP stream tracking for request-response matching
----------------------------------------
local stream_requests = {}
local tcp_stream_field = Field.new("tcp.stream")

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

        -- Use command-specific request dissector if available
        if command_info and command_info.request_payload_dissector then
            command_info.request_payload_dissector(buffer, payload_tree, 8)
        end
    end

    -- Track request code for request-response matching
    local tcp_stream = tcp_stream_field()
    if tcp_stream then
        stream_requests[tcp_stream.value] = command_code
    end

    -- Update info column
    pinfo.cols.info:set(string.format("Request: %s (code=%d, length=%d)", command_name, command_code, length))

    -- Validate length
    local expected_length = 4 + payload_len
    if length ~= expected_length then
        subtree:add_proto_expert_info(ef_invalid_length,
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

    -- Get last request code for this TCP stream
    local tcp_stream = tcp_stream_field()
    local command_code = tcp_stream and stream_requests[tcp_stream.value]
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
            -- Use command-specific response dissector if available (only for success responses)
            if status == 0 and command_info.response_payload_dissector then
                -- Call response dissector with full buffer and offset pointing to payload start
                command_info.response_payload_dissector(buffer, payload_tree, 8)
            elseif status ~= 0 then
                -- Error response - payload might contain error message
                payload_tree:add("Error response (no payload dissector for error responses)"):set_generated()
            end
        else
            payload_tree:add("Request not captured or unknown - cannot dissect payload"):set_generated()
        end
    elseif not command_info then
        -- No payload and unknown request
        subtree:add("Request not captured or unknown"):set_generated()
    end

    -- Update info column
    local command_name_str = command_info and command_info.name or "Unknown"
    if status == 0 then
        pinfo.cols.info:set(string.format("Response: %s OK (length=%d)", command_name_str, length))
    else
        pinfo.cols.info:set(string.format("Response: %s %s (status=%d, length=%d)",
            command_name_str, status_name, status, length))
        subtree:add_proto_expert_info(ef_error_status, string.format("Error status: %d", status))
    end

    -- Validate: error responses should have length=0
    if status ~= 0 and length ~= 0 then
        subtree:add_proto_expert_info(ef_invalid_length, "Error response should have length=0")
    end

    return total_len
end

----------------------------------------
-- Main dissector
----------------------------------------
function iggy.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("IGGY")

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
            subtree:add_proto_expert_info(ef_invalid_length,
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
            subtree:add_proto_expert_info(ef_invalid_length,
                string.format("Expected response format (src_port=%d), but format validation failed", server_port))
            pinfo.cols.info:set("Malformed response")
            return 0
        end

    else
        -- Neither request nor response port - shouldn't happen with port-based registration
        if buflen < 8 then
            local subtree = tree:add(iggy, buffer(), "Iggy Protocol (Malformed)")
            subtree:add_proto_expert_info(ef_too_short)
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
