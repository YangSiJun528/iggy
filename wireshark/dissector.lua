local iggy = Proto("iggy", "Iggy Protocol")

----------------------------------------
-- Preferences
----------------------------------------
iggy.prefs.server_port = Pref.uint("Server Port", 8090, "Target TCP server port")

----------------------------------------
-- Fields
----------------------------------------
-- Common fields
local f_message_type = ProtoField.string("iggy.message_type", "Message Type")

-- Request fields
local f_req_length = ProtoField.uint32("iggy.request.length", "Length", base.DEC, nil, nil, "Length of command code + payload")
local f_req_command = ProtoField.uint32("iggy.request.command", "Command Code", base.DEC)
local f_req_command_name = ProtoField.string("iggy.request.command_name", "Command Name")
local f_req_payload = ProtoField.bytes("iggy.request.payload", "Payload")

-- Response fields
local f_resp_status = ProtoField.uint32("iggy.response.status", "Status Code", base.DEC)
local f_resp_status_name = ProtoField.string("iggy.response.status_name", "Status Name")
local f_resp_length = ProtoField.uint32("iggy.response.length", "Length", base.DEC, nil, nil, "Length of payload")
local f_resp_payload = ProtoField.bytes("iggy.response.payload", "Payload")

iggy.fields = {
    f_message_type,
    f_req_length, f_req_command, f_req_command_name, f_req_payload,
    f_resp_status, f_resp_status_name, f_resp_length, f_resp_payload
}

----------------------------------------
-- Command Registry
----------------------------------------
local COMMANDS = {
    [1] = {
        name = "Ping",
        dissect_request = nil,  -- No payload
    },
    [10] = {
        name = "GetStats",
        dissect_response = nil,
    },
}

----------------------------------------
-- Status Code Registry
----------------------------------------
local STATUS_CODES = {
    [0] = "OK",
    [1] = "InvalidCommand",
    [2] = "Unauthenticated",
    [3] = "Unauthorized",
    [10] = "InvalidFormat",
    [11] = "InvalidRequest",
    -- Add more status codes as needed
}

----------------------------------------
-- Expert Info
----------------------------------------
local ef_too_short = ProtoExpert.new("iggy.too_short", "Packet too short", expert.group.MALFORMED, expert.severity.ERROR)
local ef_invalid_length = ProtoExpert.new("iggy.invalid_length", "Invalid length field", expert.group.MALFORMED, expert.severity.WARN)
local ef_error_status = ProtoExpert.new("iggy.error_status", "Error response", expert.group.RESPONSE_CODE, expert.severity.WARN)

iggy.experts = { ef_too_short, ef_invalid_length, ef_error_status }

----------------------------------------
-- Helper: Detect message type
----------------------------------------
local function detect_message_type(buffer)
    local buflen = buffer:len()
    if buflen < 8 then
        return nil
    end

    local first_field = buffer(0, 4):le_uint()
    local second_field = buffer(4, 4):le_uint()

    -- Try to detect as Request
    -- Request format: LENGTH(4) + CODE(4) + PAYLOAD(N)
    -- where LENGTH = CODE(4) + PAYLOAD(N)
    -- Total packet size = 4 + LENGTH
    if COMMANDS[second_field] then
        local expected_total = 4 + first_field
        if expected_total == buflen and first_field >= 4 then
            return "request"
        end
    end

    -- Try to detect as Response
    -- Response format: STATUS(4) + LENGTH(4) + PAYLOAD(N)
    -- Total packet size = 8 + LENGTH

    -- For error responses: STATUS != 0, LENGTH = 0
    if first_field ~= 0 and second_field == 0 and buflen == 8 then
        return "response"
    end

    -- For success responses: STATUS = 0, LENGTH >= 0
    if first_field == 0 then
        local expected_total = 8 + second_field
        if expected_total == buflen then
            return "response"
        end
    end

    return nil
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

        -- Use command-specific dissector if available
        if command_info and command_info.dissect_request then
            command_info.dissect_request(buffer, payload_tree, 8, payload_len)
        end
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

    -- Payload
    local payload_len = total_len - 8
    if payload_len > 0 then
        subtree:add(f_resp_payload, buffer(8, payload_len))
    end

    -- Update info column
    if status == 0 then
        pinfo.cols.info:set(string.format("Response: OK (length=%d)", length))
    else
        pinfo.cols.info:set(string.format("Response: %s (status=%d, length=%d)", status_name, status, length))
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
local TCP_PORT = iggy.prefs.server_port

function iggy.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("IGGY")

    local buflen = buffer:len()
    if buflen < 8 then
        local subtree = tree:add(iggy, buffer(), "Iggy Protocol (Malformed)")
        subtree:add_proto_expert_info(ef_too_short)
        pinfo.cols.info:set("Malformed packet (too short)")
        return 0
    end

    -- Detect message type
    local msg_type = detect_message_type(buffer)

    if msg_type == "request" then
        return dissect_request(buffer, pinfo, tree)
    elseif msg_type == "response" then
        return dissect_response(buffer, pinfo, tree)
    else
        -- Unknown format
        local subtree = tree:add(iggy, buffer(), "Iggy Protocol (Unknown)")
        pinfo.cols.info:set("Unknown packet format")
        return 0
    end
end

----------------------------------------
-- Register dissector via preferences
----------------------------------------
function iggy.prefs_changed()
    local new_port = iggy.prefs.server_port

    if TCP_PORT ~= new_port then
        if TCP_PORT ~= 0 then
            DissectorTable.get("tcp.port"):remove(TCP_PORT, iggy)
        end
        TCP_PORT = new_port

        if TCP_PORT ~= 0 then
            DissectorTable.get("tcp.port"):add(TCP_PORT, iggy)
        end
    end
end

----------------------------------------
-- Initial registration
----------------------------------------
if TCP_PORT ~= 0 then
    DissectorTable.get("tcp.port"):add(TCP_PORT, iggy)
end
