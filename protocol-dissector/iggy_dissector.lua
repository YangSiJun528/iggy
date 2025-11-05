-- Iggy Protocol Dissector for Wireshark
-- Supports TCP/QUIC binary protocol (excluding HTTP/JSON)

-- Protocol definition
local iggy_proto = Proto("iggy", "Iggy Protocol")

-- Fields for Request
local f_msg_type = ProtoField.string("iggy.message_type", "Message Type")
local f_req_length = ProtoField.uint32("iggy.request.length", "Length", base.DEC)
local f_req_code = ProtoField.uint32("iggy.request.code", "Code", base.DEC)
local f_req_code_name = ProtoField.string("iggy.request.code_name", "Command")
local f_req_payload = ProtoField.bytes("iggy.request.payload", "Payload")

-- Fields for Response
local f_resp_status = ProtoField.uint32("iggy.response.status", "Status", base.DEC)
local f_resp_status_name = ProtoField.string("iggy.response.status_name", "Status Name")
local f_resp_length = ProtoField.uint32("iggy.response.length", "Length", base.DEC)
local f_resp_payload = ProtoField.bytes("iggy.response.payload", "Payload")

-- Fields for LoginUser payload
local f_login_username_len = ProtoField.uint8("iggy.login.username_len", "Username Length", base.DEC)
local f_login_username = ProtoField.string("iggy.login.username", "Username")
local f_login_password_len = ProtoField.uint8("iggy.login.password_len", "Password Length", base.DEC)
local f_login_password = ProtoField.string("iggy.login.password", "Password")
local f_login_version_len = ProtoField.uint32("iggy.login.version_len", "Version Length", base.DEC)
local f_login_version = ProtoField.string("iggy.login.version", "Version")
local f_login_context_len = ProtoField.uint32("iggy.login.context_len", "Context Length", base.DEC)
local f_login_context = ProtoField.string("iggy.login.context", "Context")

-- Register all fields
iggy_proto.fields = {
    f_msg_type,
    f_req_length, f_req_code, f_req_code_name, f_req_payload,
    f_resp_status, f_resp_status_name, f_resp_length, f_resp_payload,
    f_login_username_len, f_login_username,
    f_login_password_len, f_login_password,
    f_login_version_len, f_login_version,
    f_login_context_len, f_login_context
}

-- Command code to name mapping
local command_names = {
    [1] = "Ping",
    [10] = "GetStats",
    [11] = "GetSnapshot",
    [12] = "GetClusterMetadata",
    [20] = "GetMe",
    [21] = "GetClient",
    [22] = "GetClients",
    [31] = "GetUser",
    [32] = "GetUsers",
    [33] = "CreateUser",
    [34] = "DeleteUser",
    [35] = "UpdateUser",
    [36] = "UpdatePermissions",
    [37] = "ChangePassword",
    [38] = "LoginUser",
    [39] = "LogoutUser",
}

-- Error code to name mapping (subset)
local error_names = {
    [0] = "Success",
    [1] = "Error",
    [2] = "InvalidConfiguration",
    [3] = "InvalidCommand",
    [40] = "Unauthenticated",
    [41] = "Unauthorized",
    [42] = "InvalidCredentials",
    [43] = "InvalidUsername",
    [44] = "InvalidPassword",
}

-- Parse LoginUser payload
local function parse_login_user_payload(buffer, pinfo, tree, offset)
    local payload_len = buffer:len() - offset
    if payload_len < 2 then
        return
    end

    -- Username
    local username_len = buffer(offset, 1):le_uint()
    tree:add_le(f_login_username_len, buffer(offset, 1))
    offset = offset + 1

    if payload_len < 1 + username_len then
        return
    end

    local username = buffer(offset, username_len):string()
    tree:add(f_login_username, buffer(offset, username_len))
    offset = offset + username_len

    -- Password
    if payload_len < 1 + username_len + 1 then
        return
    end

    local password_len = buffer(offset, 1):le_uint()
    tree:add_le(f_login_password_len, buffer(offset, 1))
    offset = offset + 1

    if payload_len < 1 + username_len + 1 + password_len then
        return
    end

    local password = buffer(offset, password_len):string()
    tree:add(f_login_password, buffer(offset, password_len), "******")
    offset = offset + password_len

    -- Version (optional)
    if payload_len >= offset - (1 + username_len + 1 + password_len) + 4 then
        local version_len = buffer(offset, 4):le_uint()
        tree:add_le(f_login_version_len, buffer(offset, 4))
        offset = offset + 4

        if version_len > 0 and payload_len >= offset - (1 + username_len + 1 + password_len + 4) + version_len then
            local version = buffer(offset, version_len):string()
            tree:add(f_login_version, buffer(offset, version_len))
            offset = offset + version_len
        end

        -- Context (optional)
        if payload_len >= offset - (1 + username_len + 1 + password_len + 4 + version_len) + 4 then
            local context_len = buffer(offset, 4):le_uint()
            tree:add_le(f_login_context_len, buffer(offset, 4))
            offset = offset + 4

            if context_len > 0 and payload_len >= offset - (1 + username_len + 1 + password_len + 4 + version_len + 4) + context_len then
                local context = buffer(offset, context_len):string()
                tree:add(f_login_context, buffer(offset, context_len))
            end
        end
    end

    pinfo.cols.info:append(string.format(" (User: %s)", username))
end

-- Command handlers table
local command_handlers = {
    [1] = {  -- Ping
        name = "Ping",
        parse_payload = function(buffer, pinfo, tree, offset)
            -- No payload for Ping
        end
    },
    [10] = {  -- GetStats
        name = "GetStats",
        parse_payload = function(buffer, pinfo, tree, offset)
            -- No payload for GetStats
        end
    },
    [38] = {  -- LoginUser
        name = "LoginUser",
        parse_payload = parse_login_user_payload
    },
}

-- Parse Request message
local function parse_request(buffer, pinfo, tree)
    if buffer:len() < 8 then
        return false
    end

    local length = buffer(0, 4):le_uint()
    local code = buffer(4, 4):le_uint()

    tree:add(f_msg_type, "Request")
    tree:add_le(f_req_length, buffer(0, 4))
    tree:add_le(f_req_code, buffer(4, 4))

    local code_name = command_names[code] or "Unknown"
    tree:add(f_req_code_name, code_name)

    pinfo.cols.info = string.format("Request: %s (Code: %d)", code_name, code)

    -- Parse payload if present
    if length > 4 then
        local payload_len = length - 4
        if buffer:len() >= 8 + payload_len then
            local payload_tree = tree:add(f_req_payload, buffer(8, payload_len))

            -- Use command-specific parser if available
            local handler = command_handlers[code]
            if handler and handler.parse_payload then
                handler.parse_payload(buffer, pinfo, payload_tree, 8)
            end
        end
    end

    return true
end

-- Parse Response message
local function parse_response(buffer, pinfo, tree)
    if buffer:len() < 8 then
        return false
    end

    local status = buffer(0, 4):le_uint()
    local length = buffer(4, 4):le_uint()

    tree:add(f_msg_type, "Response")
    tree:add_le(f_resp_status, buffer(0, 4))

    local status_name = error_names[status] or "Unknown"
    tree:add(f_resp_status_name, status_name)
    tree:add_le(f_resp_length, buffer(4, 4))

    pinfo.cols.info = string.format("Response: %s (Status: %d)", status_name, status)

    -- Parse payload if present (length includes status bytes)
    if length > 4 and status == 0 then
        local payload_len = length - 4
        if buffer:len() >= 8 + payload_len then
            tree:add(f_resp_payload, buffer(8, payload_len))
        end
    end

    return true
end

-- Main dissector function
function iggy_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 8 then
        return 0
    end

    pinfo.cols.protocol = iggy_proto.name

    local subtree = tree:add(iggy_proto, buffer(), "Iggy Protocol")

    -- Try to determine if it's a request or response
    -- Heuristic: First u32 is "length" in request, or "status" in response
    -- If first u32 is small (< 1000) and second u32 is also small, likely response
    -- If first u32 is larger, likely request (length field)

    local first_u32 = buffer(0, 4):le_uint()
    local second_u32 = buffer(4, 4):le_uint()

    -- Simple heuristic: if second_u32 is a known command code, it's a request
    if command_names[second_u32] then
        return parse_request(buffer, pinfo, subtree) and length or 0
    else
        -- Otherwise, try parsing as response
        return parse_response(buffer, pinfo, subtree) and length or 0
    end
end

-- Register the dissector on TCP port (default: 8090)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8090, iggy_proto)
tcp_port:add(8091, iggy_proto)
