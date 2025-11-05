-- Iggy Protocol Dissector
-- Supports Request/Response detection with extensible command registry

local iggy = Proto("iggy", "Iggy Protocol")

----------------------------------------
-- Protocol fields
----------------------------------------
-- Common
local pf_message_type   = ProtoField.string("iggy.message_type", "Message Type")

-- Request fields
local pf_req_length     = ProtoField.uint32("iggy.request.length", "Length", base.DEC)
local pf_req_code       = ProtoField.uint32("iggy.request.code", "Command Code", base.DEC)
local pf_req_code_name  = ProtoField.string("iggy.request.code_name", "Command Name")
local pf_req_payload    = ProtoField.bytes("iggy.request.payload", "Payload")

-- Response fields
local pf_resp_status    = ProtoField.uint32("iggy.response.status", "Status", base.DEC)
local pf_resp_status_name = ProtoField.string("iggy.response.status_name", "Status Name")
local pf_resp_length    = ProtoField.uint32("iggy.response.length", "Length", base.DEC)
local pf_resp_payload   = ProtoField.bytes("iggy.response.payload", "Payload")

iggy.fields = {
    pf_message_type,
    pf_req_length, pf_req_code, pf_req_code_name, pf_req_payload,
    pf_resp_status, pf_resp_status_name, pf_resp_length, pf_resp_payload
}

----------------------------------------
-- Command code registry (extensible)
----------------------------------------
local request_codes = {
    [1] = "Ping",
    [11] = "GetMe",
}

-- Status code mappings
local status_codes = {
    [0] = "OK",
    [1] = "Error",
    -- Add more status codes as needed
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
-- Helper: Detect if packet is request or response
----------------------------------------
local function detect_message_type(tvbuf)
    if tvbuf:len() < 8 then
        return nil
    end

    -- Try to parse as request first
    local first_field = tvbuf:range(0, 4):le_uint()
    local second_field = tvbuf:range(4, 4):le_uint()

    -- Heuristic: If first field looks like reasonable length
    -- and second field is a known request code, it's likely a request
    if first_field >= 4 and first_field <= 1000000 then
        if request_codes[second_field] then
            return "request"
        end
    end

    -- Heuristic: If first field is small (status code 0-100)
    -- it's likely a response
    if first_field <= 100 then
        return "response"
    end

    return nil
end

----------------------------------------
-- Request dissector
----------------------------------------
local function dissect_request(tvbuf, pktinfo, tree)
    local pktlen = tvbuf:len()

    if pktlen < 8 then
        tree:add_proto_expert_info(ef_too_short)
        return 0
    end

    local subtree = tree:add(iggy, tvbuf:range(0, pktlen), "Iggy Request")
    subtree:add(pf_message_type, "Request"):set_generated()

    -- LENGTH field
    local msg_length = tvbuf:range(0, 4):le_uint()
    subtree:add_le(pf_req_length, tvbuf:range(0, 4))

    -- CODE field
    local command_code = tvbuf:range(4, 4):le_uint()
    subtree:add_le(pf_req_code, tvbuf:range(4, 4))

    -- Command name
    local command_name = request_codes[command_code] or string.format("Unknown(0x%x)", command_code)
    subtree:add(pf_req_code_name, command_name):set_generated()

    -- PAYLOAD
    local payload_len = pktlen - 8
    if payload_len > 0 then
        subtree:add(pf_req_payload, tvbuf:range(8, payload_len))
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

    return pktlen
end

----------------------------------------
-- Response dissector
----------------------------------------
local function dissect_response(tvbuf, pktinfo, tree)
    local pktlen = tvbuf:len()

    if pktlen < 8 then
        tree:add_proto_expert_info(ef_too_short)
        return 0
    end

    local subtree = tree:add(iggy, tvbuf:range(0, pktlen), "Iggy Response")
    subtree:add(pf_message_type, "Response"):set_generated()

    -- STATUS field
    local status = tvbuf:range(0, 4):le_uint()
    subtree:add_le(pf_resp_status, tvbuf:range(0, 4))

    -- Status name
    local status_name = status_codes[status] or (status == 0 and "OK" or "Error")
    subtree:add(pf_resp_status_name, status_name):set_generated()

    -- LENGTH field
    local msg_length = tvbuf:range(4, 4):le_uint()
    subtree:add_le(pf_resp_length, tvbuf:range(4, 4))

    -- PAYLOAD
    local payload_len = pktlen - 8
    if payload_len > 0 then
        subtree:add(pf_resp_payload, tvbuf:range(8, payload_len))
    end

    -- Update info column
    if status == 0 then
        pktinfo.cols.info:set(string.format("Response: OK (length=%d)", msg_length))
    else
        pktinfo.cols.info:set(string.format("Response: Error (status=%d, length=%d)",
                                            status, msg_length))
        subtree:add_proto_expert_info(ef_error_status,
            string.format("Error status: %d", status))
    end

    -- Validate: error responses should have length=0
    if status ~= 0 and msg_length ~= 0 then
        subtree:add_proto_expert_info(ef_invalid_length,
            "Error response should have length=0")
    end

    return pktlen
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
