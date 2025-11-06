-- Protocol dissection logic module for Iggy Protocol Dissector

local dissectorr = {}

-- Dependencies
local constants = require("iggy.constants")
local fields = require("iggy.fields")
local commands = require("iggy.commands")
local types = require("iggy.types")

----------------------------------------
-- Expert info
----------------------------------------
dissectorr.ef_invalid_length = ProtoExpert.new("iggy.invalid_length.expert",
                                             "Invalid length field",
                                             expert.group.MALFORMED, expert.severity.WARN)
dissectorr.ef_error_status   = ProtoExpert.new("iggy.error_status.expert",
                                             "Error response",
                                             expert.group.RESPONSE_CODE, expert.severity.WARN)

----------------------------------------
-- Helper: Detect if packet is request or response
----------------------------------------
function dissectorr.detect_message_type(tvbuf)
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
    if commands.registry[second_field] then
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
function dissectorr.dissect_request(tvbuf, pktinfo, tree, iggy_proto)
    local pktlen = tvbuf:len()

    -- Check minimum length
    if pktlen < constants.IGGY_MIN_HEADER_LEN then
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

    local subtree = tree:add(iggy_proto, tvbuf:range(0, total_len), "Iggy Request")
    subtree:add(fields.pf_message_type, "Request"):set_generated()

    -- LENGTH field
    subtree:add_le(fields.pf_req_length, tvbuf:range(0, 4))

    -- CODE field
    local command_code = tvbuf:range(4, 4):le_uint()
    subtree:add_le(fields.pf_req_code, tvbuf:range(4, 4))

    -- Get command info from registry
    local command_info = commands.registry[command_code]
    local command_name = command_info and command_info.name or string.format("Unknown(0x%x)", command_code)
    subtree:add(fields.pf_req_code_name, command_name):set_generated()

    -- PAYLOAD
    local payload_len = total_len - 8
    if payload_len > 0 then
        local payload_tree = subtree:add(fields.pf_req_payload, tvbuf:range(8, payload_len))

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
        subtree:add_proto_expert_info(dissectorr.ef_invalid_length,
            string.format("Length mismatch: field=%d, expected=%d", msg_length, expected_length))
    end

    return total_len
end

----------------------------------------
-- Response dissector
----------------------------------------
function dissectorr.dissect_response(tvbuf, pktinfo, tree, iggy_proto)
    local pktlen = tvbuf:len()

    -- Check minimum length
    if pktlen < constants.IGGY_MIN_HEADER_LEN then
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

    local subtree = tree:add(iggy_proto, tvbuf:range(0, total_len), "Iggy Response")
    subtree:add(fields.pf_message_type, "Response"):set_generated()

    -- STATUS field
    local status = tvbuf:range(0, 4):le_uint()
    subtree:add_le(fields.pf_resp_status, tvbuf:range(0, 4))

    -- Status name
    local status_name = constants.status_codes[status] or (status == 0 and "OK" or string.format("Error(%d)", status))
    subtree:add(fields.pf_resp_status_name, status_name):set_generated()

    -- LENGTH field
    subtree:add_le(fields.pf_resp_length, tvbuf:range(4, 4))

    -- PAYLOAD
    local payload_len = total_len - 8
    if payload_len > 0 then
        subtree:add(fields.pf_resp_payload, tvbuf:range(8, payload_len))
    end

    -- Update info column
    if status == 0 then
        pktinfo.cols.info:set(string.format("Response: OK (length=%d)", msg_length))
    else
        pktinfo.cols.info:set(string.format("Response: %s (status=%d, length=%d)",
                                            status_name, status, msg_length))
        subtree:add_proto_expert_info(dissectorr.ef_error_status,
            string.format("Error status: %d", status))
    end

    -- Validate: error responses should have length=0
    if status ~= 0 and msg_length ~= 0 then
        subtree:add_proto_expert_info(dissectorr.ef_invalid_length,
            "Error response should have length=0")
    end

    return total_len
end

return dissectorr
