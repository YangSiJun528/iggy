-- Iggy Protocol Dissector for Wireshark
-- Supports TCP/QUIC binary protocol (excluding HTTP/JSON)
-- Based on the structure of dns_dissector.lua example

----------------------------------------
-- Protocol definition
local iggy_proto = Proto("iggy", "Iggy Protocol")

----------------------------------------
-- Protocol fields
-- Request fields
local pf_msg_type           = ProtoField.string("iggy.message_type", "Message Type")
local pf_req_length         = ProtoField.uint32("iggy.request.length", "Length", base.DEC)
local pf_req_code           = ProtoField.uint32("iggy.request.code", "Code", base.DEC)
local pf_req_code_name      = ProtoField.string("iggy.request.code_name", "Command")
local pf_req_payload        = ProtoField.bytes("iggy.request.payload", "Payload")

-- Response fields
local pf_resp_status        = ProtoField.uint32("iggy.response.status", "Status", base.DEC)
local pf_resp_status_name   = ProtoField.string("iggy.response.status_name", "Status Name")
local pf_resp_length        = ProtoField.uint32("iggy.response.length", "Length", base.DEC)
local pf_resp_payload       = ProtoField.bytes("iggy.response.payload", "Payload")

-- LoginUser payload fields
local pf_login_username_len = ProtoField.uint8("iggy.login.username_len", "Username Length", base.DEC)
local pf_login_username     = ProtoField.string("iggy.login.username", "Username")
local pf_login_password_len = ProtoField.uint8("iggy.login.password_len", "Password Length", base.DEC)
local pf_login_password     = ProtoField.string("iggy.login.password", "Password")
local pf_login_version_len  = ProtoField.uint32("iggy.login.version_len", "Version Length", base.DEC)
local pf_login_version      = ProtoField.string("iggy.login.version", "Version")
local pf_login_context_len  = ProtoField.uint32("iggy.login.context_len", "Context Length", base.DEC)
local pf_login_context      = ProtoField.string("iggy.login.context", "Context")

-- Register all fields
iggy_proto.fields = {
    pf_msg_type,
    pf_req_length, pf_req_code, pf_req_code_name, pf_req_payload,
    pf_resp_status, pf_resp_status_name, pf_resp_length, pf_resp_payload,
    pf_login_username_len, pf_login_username,
    pf_login_password_len, pf_login_password,
    pf_login_version_len, pf_login_version,
    pf_login_context_len, pf_login_context
}

----------------------------------------
-- Expert info fields
local ef_too_short      = ProtoExpert.new("iggy.too_short.expert", "Iggy message too short",
                                          expert.group.MALFORMED, expert.severity.ERROR)
local ef_invalid_length = ProtoExpert.new("iggy.invalid_length.expert", "Iggy invalid length field",
                                          expert.group.MALFORMED, expert.severity.WARN)
local ef_request        = ProtoExpert.new("iggy.request.expert", "Iggy request message",
                                          expert.group.REQUEST_CODE, expert.severity.CHAT)
local ef_response       = ProtoExpert.new("iggy.response.expert", "Iggy response message",
                                          expert.group.RESPONSE_CODE, expert.severity.CHAT)

-- Register expert info fields
iggy_proto.experts = { ef_too_short, ef_invalid_length, ef_request, ef_response }

----------------------------------------
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

-- Error code to name mapping
local status_names = {
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

----------------------------------------
-- Constants
local IGGY_MIN_LEN = 8  -- Minimum message length (length/status + code/length fields)

----------------------------------------
-- Helper function: Parse LoginUser payload
local function parse_login_user_payload(tvbuf, tree, offset)
    local remaining = tvbuf:len() - offset
    if remaining < 2 then
        return
    end

    -- Username
    local username_len = tvbuf(offset, 1):le_uint()
    tree:add_le(pf_login_username_len, tvbuf(offset, 1))
    offset = offset + 1
    remaining = remaining - 1

    if remaining < username_len then
        return
    end

    local username = tvbuf(offset, username_len):string()
    tree:add(pf_login_username, tvbuf(offset, username_len))
    offset = offset + username_len
    remaining = remaining - username_len

    -- Password
    if remaining < 1 then
        return
    end

    local password_len = tvbuf(offset, 1):le_uint()
    tree:add_le(pf_login_password_len, tvbuf(offset, 1))
    offset = offset + 1
    remaining = remaining - 1

    if remaining < password_len then
        return
    end

    tree:add(pf_login_password, tvbuf(offset, password_len), "******")
    offset = offset + password_len
    remaining = remaining - password_len

    -- Version (optional)
    if remaining >= 4 then
        local version_len = tvbuf(offset, 4):le_uint()
        tree:add_le(pf_login_version_len, tvbuf(offset, 4))
        offset = offset + 4
        remaining = remaining - 4

        if version_len > 0 and remaining >= version_len then
            local version = tvbuf(offset, version_len):string()
            tree:add(pf_login_version, tvbuf(offset, version_len))
            offset = offset + version_len
            remaining = remaining - version_len
        end

        -- Context (optional)
        if remaining >= 4 then
            local context_len = tvbuf(offset, 4):le_uint()
            tree:add_le(pf_login_context_len, tvbuf(offset, 4))
            offset = offset + 4
            remaining = remaining - 4

            if context_len > 0 and remaining >= context_len then
                local context = tvbuf(offset, context_len):string()
                tree:add(pf_login_context, tvbuf(offset, context_len))
            end
        end
    end

    return username
end

----------------------------------------
-- Main dissector function
function iggy_proto.dissector(tvbuf, pktinfo, root)
    local pktlen = tvbuf:reported_length_remaining()

    -- Set protocol column
    pktinfo.cols.protocol:set("Iggy")

    -- Add protocol tree
    local tree = root:add(iggy_proto, tvbuf:range(0, pktlen))

    -- Check minimum length
    if pktlen < IGGY_MIN_LEN then
        tree:add_proto_expert_info(ef_too_short)
        return 0
    end

    local first_u32 = tvbuf(0, 4):le_uint()
    local second_u32 = tvbuf(4, 4):le_uint()

    -- Determine if Request or Response
    local is_request = command_names[second_u32] ~= nil

    if is_request then
        -- Parse Request
        local length = first_u32
        local code = second_u32
        local code_name = command_names[code] or "Unknown"

        tree:add(pf_msg_type, "Request")
        tree:add_le(pf_req_length, tvbuf(0, 4))
        tree:add_le(pf_req_code, tvbuf(4, 4))
        tree:add(pf_req_code_name, code_name)

        -- Add expert info
        tree:add_proto_expert_info(ef_request, "Request: " .. code_name)

        -- Set info column
        pktinfo.cols.info:set(string.format("Request: %s (Code: %d)", code_name, code))

        -- Validate length
        local expected_len = 4 + length
        if expected_len ~= pktlen then
            tree:add_proto_expert_info(ef_invalid_length,
                string.format("Length mismatch: expected %d, got %d", expected_len, pktlen))
        end

        -- Parse payload
        if length > 4 then
            local payload_len = length - 4
            if pktlen >= 8 + payload_len then
                local payload_tree = tree:add(pf_req_payload, tvbuf(8, payload_len))

                -- Parse specific command payloads
                if code == 38 then  -- LoginUser
                    local username = parse_login_user_payload(tvbuf, payload_tree, 8)
                    if username then
                        pktinfo.cols.info:append(string.format(" (User: %s)", username))
                    end
                end
            end
        end

    else
        -- Parse Response
        local status = first_u32
        local length = second_u32
        local status_name = status_names[status] or string.format("Unknown (%d)", status)

        tree:add(pf_msg_type, "Response")
        tree:add_le(pf_resp_status, tvbuf(0, 4))
        tree:add(pf_resp_status_name, status_name)
        tree:add_le(pf_resp_length, tvbuf(4, 4))

        -- Add expert info
        tree:add_proto_expert_info(ef_response, "Response: " .. status_name)

        -- Set info column
        pktinfo.cols.info:set(string.format("Response: %s (Status: %d)", status_name, status))

        -- Validate length
        local payload_len = length > 4 and (length - 4) or 0
        local expected_len = 8 + payload_len
        if length > 0 and expected_len ~= pktlen then
            tree:add_proto_expert_info(ef_invalid_length,
                string.format("Length mismatch: expected %d, got %d", expected_len, pktlen))
        end

        -- Parse payload (only for successful responses)
        if status == 0 and length > 4 then
            if pktlen >= 8 + payload_len then
                tree:add(pf_resp_payload, tvbuf(8, payload_len))
            end
        end
    end

    return pktlen
end

----------------------------------------
-- Heuristic dissector function
local function heur_dissect_iggy(tvbuf, pktinfo, root)
    local pktlen = tvbuf:len()

    -- Check minimum length
    if pktlen < IGGY_MIN_LEN then
        return false
    end

    local first_u32 = tvbuf(0, 4):le_uint()
    local second_u32 = tvbuf(4, 4):le_uint()

    -- Check if it's a Request
    if command_names[second_u32] then
        -- Verify length field
        local expected_total = 4 + first_u32
        if expected_total == pktlen then
            iggy_proto.dissector(tvbuf, pktinfo, root)
            pktinfo.conversation = iggy_proto
            return true
        end
    end

    -- Check if it's a Response
    -- Status codes should be reasonable (0-100 for common errors)
    if first_u32 <= 100 then
        local length = second_u32

        -- For error responses (status != 0), length is usually 0
        if first_u32 ~= 0 and length == 0 then
            if pktlen == 8 then
                iggy_proto.dissector(tvbuf, pktinfo, root)
                pktinfo.conversation = iggy_proto
                return true
            end
        end

        -- For success responses
        if first_u32 == 0 then
            local payload_len = length > 4 and (length - 4) or 0
            local expected_total = 8 + payload_len

            if expected_total == pktlen or length == 0 then
                iggy_proto.dissector(tvbuf, pktinfo, root)
                pktinfo.conversation = iggy_proto
                return true
            end
        end
    end

    return false
end

----------------------------------------
-- Register heuristic dissector for TCP
iggy_proto:register_heuristic("tcp", heur_dissect_iggy)

-- Protocol is automatically registered when script finishes loading
