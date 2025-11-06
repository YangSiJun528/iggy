-- Iggy Protocol Dissector Main Module

local iggy = {}

-- Dependencies
local fields = require("iggy.fields")
local utils = require("iggy.utils")
local status_codes = require("iggy.status_codes")

----------------------------------------
-- Protocol constants
----------------------------------------
local IGGY_MIN_HEADER_LEN = 8  -- Minimum: LENGTH(4) + CODE/STATUS(4)

----------------------------------------
-- Expert info
----------------------------------------
iggy.ef_too_short = ProtoExpert.new("iggy.too_short.expert",
                                    "Iggy packet too short",
                                    expert.group.MALFORMED, expert.severity.ERROR)
iggy.ef_invalid_length = ProtoExpert.new("iggy.invalid_length.expert",
                                         "Invalid length field",
                                         expert.group.MALFORMED, expert.severity.WARN)
iggy.ef_error_status   = ProtoExpert.new("iggy.error_status.expert",
                                         "Error response",
                                         expert.group.RESPONSE_CODE, expert.severity.WARN)

----------------------------------------
-- Protocol-specific data type dissectors
----------------------------------------

-- Dissect Identifier (kind + length + value)
-- id_fields: required table with { kind, length, value_num, value_str }
-- Returns: offset after parsing, or nil on failure
local function dissect_identifier(tvbuf, tree, offset, pktlen, label, id_fields)
    -- Identifier constants
    local ID_KIND_NUMERIC = 1
    local ID_KIND_STRING  = 2
    local ID_HEADER_SIZE = 2  -- kind(1) + length(1)
    local ID_MIN_SIZE    = 3  -- kind(1) + length(1) + min_value(1)
    local ID_NUMERIC_VALUE_SIZE = 4  -- u32 for numeric identifiers

    local remaining = pktlen - offset
    if remaining < ID_MIN_SIZE then
        tree:add_proto_expert_info(iggy.ef_too_short,
            string.format("%s: insufficient data for identifier header", label))
        return nil
    end

    local kind = utils.read_u8(tvbuf, offset)
    local length = utils.read_u8(tvbuf, offset + 1)

    if remaining < ID_HEADER_SIZE + length then
        tree:add_proto_expert_info(iggy.ef_too_short,
            string.format("%s: insufficient data for identifier value (need %d bytes)", label, ID_HEADER_SIZE + length))
        return nil
    end

    local kind_name = (kind == ID_KIND_NUMERIC) and "Numeric" or (kind == ID_KIND_STRING) and "String" or "Unknown"
    local id_tree = tree:add(string.format("%s: %s (%d bytes)", label, kind_name, length))

    id_tree:add(id_fields.kind, tvbuf:range(offset, 1))
    id_tree:add(id_fields.length, tvbuf:range(offset + 1, 1))

    if kind == ID_KIND_NUMERIC and length == ID_NUMERIC_VALUE_SIZE then
        -- Numeric identifier (u32 little-endian)
        id_tree:add_le(id_fields.value_num, tvbuf:range(offset + ID_HEADER_SIZE, ID_NUMERIC_VALUE_SIZE))
    elseif kind == ID_KIND_STRING then
        -- String identifier
        id_tree:add(id_fields.value_str, tvbuf:range(offset + ID_HEADER_SIZE, length))
    else
        id_tree:add("Value: (raw)", tvbuf:range(offset + ID_HEADER_SIZE, length))
    end

    return offset + ID_HEADER_SIZE + length
end

-- Dissect Consumer (kind + Identifier)
-- consumer_fields: required table with { kind, id_fields }
-- Returns: offset after parsing, or nil on failure
local function dissect_consumer(tvbuf, tree, offset, pktlen, label, consumer_fields)
    -- Consumer constants
    local CONSUMER_KIND_CONSUMER       = 1
    local CONSUMER_KIND_CONSUMER_GROUP = 2
    local CONSUMER_MIN_SIZE = 4  -- kind(1) + id_min_size(3)

    local remaining = pktlen - offset
    if remaining < CONSUMER_MIN_SIZE then
        tree:add_proto_expert_info(iggy.ef_too_short,
            string.format("%s: insufficient data for consumer", label))
        return nil
    end

    local consumer_kind = utils.read_u8(tvbuf, offset)
    local consumer_kind_name = (consumer_kind == CONSUMER_KIND_CONSUMER) and "Consumer" or (consumer_kind == CONSUMER_KIND_CONSUMER_GROUP) and "ConsumerGroup" or "Unknown"

    local consumer_tree = tree:add(string.format("%s: %s", label, consumer_kind_name))
    consumer_tree:add(consumer_fields.kind, tvbuf:range(offset, 1))

    local new_offset = dissect_identifier(tvbuf, consumer_tree, offset + 1, pktlen, "ID", consumer_fields.id_fields)
    if not new_offset then
        return nil
    end

    return new_offset
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
    [38] = {
        name = "LoginUser",
        fields = {
            username_len = fields.pf_login_username_len,
            username     = fields.pf_login_username,
            password_len = fields.pf_login_password_len,
            password     = fields.pf_login_password,
            version_len  = fields.pf_login_version_len,
            version      = fields.pf_login_version,
            context_len  = fields.pf_login_context_len,
            context      = fields.pf_login_context,
        },
        dissect_payload = function(self, tvbuf, payload_tree, offset, payload_len)
            local pktlen = offset + payload_len

            -- Username (u8 length + string)
            offset = utils.dissect_string_with_u8_len(tvbuf, payload_tree, offset, pktlen,
                self.fields.username_len, self.fields.username)
            if not offset then return end

            -- Password (u8 length + string)
            offset = utils.dissect_string_with_u8_len(tvbuf, payload_tree, offset, pktlen,
                self.fields.password_len, self.fields.password)
            if not offset then return end

            -- Version (u32 length + string)
            offset = utils.dissect_string_with_u32_le_len(tvbuf, payload_tree, offset, pktlen,
                self.fields.version_len, self.fields.version)
            if not offset then return end

            -- Context (u32 length + string)
            offset = utils.dissect_string_with_u32_le_len(tvbuf, payload_tree, offset, pktlen,
                self.fields.context_len, self.fields.context)
            if not offset then return end
        end,
    },
    [121] = {
        name = "StoreConsumerOffset",
        fields = {
            consumer     = fields.make_consumer_fields(),
            stream_id    = fields.make_identifier_fields(),
            topic_id     = fields.make_identifier_fields(),
            partition_id = fields.pf_store_offset_partition_id,
            offset       = fields.pf_store_offset_offset,
        },
        dissect_payload = function(self, tvbuf, payload_tree, offset, payload_len)
            local pktlen = offset + payload_len

            -- Consumer (common data type)
            offset = dissect_consumer(tvbuf, payload_tree, offset, pktlen, "Consumer", self.fields.consumer)
            if not offset then return end

            -- Stream ID (common data type)
            offset = dissect_identifier(tvbuf, payload_tree, offset, pktlen, "Stream ID", self.fields.stream_id)
            if not offset then return end

            -- Topic ID (common data type)
            offset = dissect_identifier(tvbuf, payload_tree, offset, pktlen, "Topic ID", self.fields.topic_id)
            if not offset then return end

            -- Partition ID (u32, 0 = None)
            offset = utils.dissect_u32_le(tvbuf, payload_tree, offset, self.fields.partition_id, pktlen)
            if not offset then return end

            -- Offset (u64)
            offset = utils.dissect_u64_le(tvbuf, payload_tree, offset, self.fields.offset, pktlen)
            if not offset then return end
        end,
    },
}

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
local function dissect_request(tvbuf, pktinfo, tree, iggy_proto)
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

    local subtree = tree:add(iggy_proto, tvbuf:range(0, total_len), "Iggy Request")
    subtree:add(fields.pf_message_type, "Request"):set_generated()

    -- LENGTH field
    subtree:add_le(fields.pf_req_length, tvbuf:range(0, 4))

    -- CODE field
    local command_code = tvbuf:range(4, 4):le_uint()
    subtree:add_le(fields.pf_req_code, tvbuf:range(4, 4))

    -- Get command info from registry
    local command_info = commands[command_code]
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
        subtree:add_proto_expert_info(iggy.ef_invalid_length,
            string.format("Length mismatch: field=%d, expected=%d", msg_length, expected_length))
    end

    return total_len
end

----------------------------------------
-- Response dissector
----------------------------------------
local function dissect_response(tvbuf, pktinfo, tree, iggy_proto)
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

    local subtree = tree:add(iggy_proto, tvbuf:range(0, total_len), "Iggy Response")
    subtree:add(fields.pf_message_type, "Response"):set_generated()

    -- STATUS field
    local status = tvbuf:range(0, 4):le_uint()
    subtree:add_le(fields.pf_resp_status, tvbuf:range(0, 4))

    -- Status name
    local status_name = status_codes[status] or (status == 0 and "OK" or string.format("Error(%d)", status))
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
        subtree:add_proto_expert_info(iggy.ef_error_status,
            string.format("Error status: %d", status))
    end

    -- Validate: error responses should have length=0
    if status ~= 0 and msg_length ~= 0 then
        subtree:add_proto_expert_info(iggy.ef_invalid_length,
            "Error response should have length=0")
    end

    return total_len
end

----------------------------------------
-- Exported functions
----------------------------------------
iggy.detect_message_type = detect_message_type
iggy.dissect_request = dissect_request
iggy.dissect_response = dissect_response

return iggy
