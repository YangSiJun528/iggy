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

-- ref: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_Proto
local iggy = Proto("iggy", "Iggy Protocol")

----------------------------------------
-- Preferences
----------------------------------------
iggy.prefs.server_port = Pref.uint("Server Port", 8090, "Target TCP server port")

----------------------------------------
-- Expert Info
----------------------------------------
-- Used only for dissection errors caught by pcall
local ef_dissection_error = ProtoExpert.new("iggy.dissection_error", "Dissection error", expert.group.MALFORMED, expert.severity.ERROR)

iggy.experts = {
    ef_dissection_error,
}

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
for code, cmd in pairs(COMMANDS) do
    assert(type(code) == "number", "Command code must be a number")
    assert(type(cmd.name) == "string" and cmd.name:match("%S"),
        string.format("Command %d: name must be a non-empty string (not just whitespace)", code))
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
-- TCP stream tracking for request-response matching
-- Each TCP stream has a FIFO queue of request command codes
----------------------------------------
-- Private state
local queues = {}

-- Public interface
local stream_queues = {}

function stream_queues.enqueue(stream_id, command_code)
    if not queues[stream_id] then
        queues[stream_id] = {}
    end
    table.insert(queues[stream_id], command_code)
end

function stream_queues.dequeue(stream_id)
    local queue = queues[stream_id]
    if not queue or #queue == 0 then
        return nil
    end
    local command_code = table.remove(queue, 1)

    -- Clean up empty queue to prevent memory accumulation
    if #queue == 0 then
        queues[stream_id] = nil
    end

    return command_code
end

function stream_queues.clear_stream(stream_id)
    queues[stream_id] = nil
end

function stream_queues.clear_all()
    queues = {}
end

----------------------------------------
-- Main dissector
----------------------------------------
function iggy.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("IGGY")

    -- Check for TCP connection termination and clean up queue
    local tcp_stream = Field.new("tcp.stream")
    local tcp_flags_fin = Field.new("tcp.flags.fin")
    local tcp_flags_reset = Field.new("tcp.flags.reset")

    local fin = tcp_flags_fin()
    local rst = tcp_flags_reset()

    if tcp_stream and (fin or rst) then
        -- Clean up queue when connection closes (FIN or RST)
        stream_queues.clear_stream(tcp_stream.value)
    end

    local buflen = buffer:len()
    local server_port = iggy.prefs.server_port
    local is_request = (pinfo.dst_port == server_port)
    local is_response = (pinfo.src_port == server_port)

    ----------------------------------------
    -- TCP Desegmentation: Ensure we have complete packet
    ----------------------------------------

    -- Step 1: Need at least 8 bytes for header
    if buflen < 8 then
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return
    end

    -- Step 2: Parse header and calculate total packet size
    local total_len
    if is_request then
        -- Request format: LENGTH(4) + CODE(4) + PAYLOAD(N)
        local length_field = buffer(0, 4):le_uint()
        total_len = 4 + length_field
    elseif is_response then
        -- Response format: STATUS(4) + LENGTH(4) + PAYLOAD(N)
        local length_field = buffer(4, 4):le_uint()
        total_len = 8 + length_field
    end

    -- Request more data if needed
    if buflen < total_len then
        pinfo.desegment_len = total_len - buflen
        return
    end

    ----------------------------------------
    -- Dissect packet with error handling
    ----------------------------------------
    local HEADER_SIZE = 8
    local payload_offset = HEADER_SIZE
    local payload_len = total_len - HEADER_SIZE

    local status, err = pcall(function()
        if is_request then
            -- Request dissection
            local length = buffer(0, 4):le_uint()
            local command_code = buffer(4, 4):le_uint()

            local subtree = tree:add(iggy, buffer(0, total_len), "Iggy Protocol - Request")
            subtree:add(f_message_type, "Request"):set_generated()

            -- Length and command code
            subtree:add_le(f_req_length, buffer(0, 4))
            subtree:add_le(f_req_command, buffer(4, 4))

            -- Early return for unknown commands
            local command_info = COMMANDS[command_code]
            if not command_info then
                local unknown_name = string.format("Unknown(0x%x)", command_code)
                subtree:add(f_req_command_name, unknown_name):set_generated()

                if payload_len > 0 then
                    subtree:add(f_req_payload, buffer(payload_offset, payload_len))
                end

                pinfo.cols.info:set(string.format("Request: %s (code=%d, length=%d)", unknown_name, command_code, length))
                return
            end

            -- After this point, command_info is guaranteed to exist
            local command_name = command_info.name
            subtree:add(f_req_command_name, command_name):set_generated()

            -- Payload
            if payload_len > 0 then
                local payload_tree = subtree:add(f_req_payload, buffer(payload_offset, payload_len))
                command_info.request_payload_dissector(buffer, payload_tree, payload_offset)
            end

            -- Track request code for request-response matching
            if tcp_stream then
                stream_queues.enqueue(tcp_stream.value, command_code)
            end

            -- Update info column
            pinfo.cols.info:set(string.format("Request: %s (code=%d, length=%d)", command_name, command_code, length))

        elseif is_response then
            -- Response dissection
            local status_code = buffer(0, 4):le_uint()
            local length = buffer(4, 4):le_uint()

            local subtree = tree:add(iggy, buffer(0, total_len), "Iggy Protocol - Response")
            subtree:add(f_message_type, "Response"):set_generated()

            -- Status code and length
            subtree:add_le(f_resp_status, buffer(0, 4))
            subtree:add_le(f_resp_length, buffer(4, 4))

            -- Status name
            local status_name = STATUS_CODES[status_code] or (status_code == 0 and "OK" or string.format("Error(%d)", status_code))
            subtree:add(f_resp_status_name, status_name):set_generated()

            -- Get matching request code for this TCP stream (FIFO order)
            local command_code = tcp_stream and stream_queues.dequeue(tcp_stream.value)
            local command_info = command_code and COMMANDS[command_code]

            -- Early return for unknown commands (no matching request or unimplemented command)
            if not command_info then
                local unknown_name = "Unknown"
                if payload_len > 0 then
                    subtree:add(f_resp_payload, buffer(payload_offset, payload_len))
                end

                if status_code == 0 then
                    pinfo.cols.info:set(string.format("Response: %s OK (length=%d)", unknown_name, length))
                else
                    pinfo.cols.info:set(string.format("Response: %s %s (status=%d, length=%d)",
                        unknown_name, status_name, status_code, length))
                end
                return
            end

            -- After this point, command_info is guaranteed to exist
            local command_name = command_info.name
            subtree:add(f_req_command_name, command_name):set_generated()

            -- Payload (only for success responses)
            if payload_len > 0 and status_code == 0 then
                local payload_tree = subtree:add(f_resp_payload, buffer(payload_offset, payload_len))
                command_info.response_payload_dissector(buffer, payload_tree, payload_offset)
            end

            -- Update info column
            if status_code == 0 then
                pinfo.cols.info:set(string.format("Response: %s OK (length=%d)", command_name, length))
            else
                pinfo.cols.info:set(string.format("Response: %s %s (status=%d, length=%d)",
                    command_name, status_name, status_code, length))
            end
        end
    end)

    -- Handle dissection errors
    if not status then
        local subtree = tree:add(iggy, buffer(), "Iggy Protocol (Dissection Error)")
        subtree:add_proto_expert_info(ef_dissection_error,
            string.format("Error: %s", err))
        pinfo.cols.info:set("Dissection error")
        return buflen
    end

    return total_len
end

----------------------------------------
-- Lifecycle callbacks (init, prefs_changed)
----------------------------------------
local current_port = 0

function iggy.init()
    -- Clear request queues to prevent memory accumulation
    stream_queues.clear_all()

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

-- Called when user changes preferences in Wireshark UI
function iggy.prefs_changed()
    local tcp_port = DissectorTable.get("tcp.port")

    -- Check if port has changed
    if current_port ~= iggy.prefs.server_port then
        -- Clear request queues when switching to different port
        -- The queues contain request-response matching data for the old port,
        -- which is no longer relevant for the new port
        stream_queues.clear_all()

        -- Remove old port registration
        if current_port > 0 then
            tcp_port:remove(current_port, iggy)
        end

        -- Register new port
        current_port = iggy.prefs.server_port
        if current_port > 0 then
            tcp_port:add(current_port, iggy)
        end
    end
end
