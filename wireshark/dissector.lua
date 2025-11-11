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
-- Used only for dissection errors caught by pcall
local ef_dissection_error = ProtoExpert.new("iggy.dissection_error", "Dissection error", expert.group.MALFORMED, expert.severity.ERROR)

iggy.experts = {
    ef_dissection_error,
}

----------------------------------------
-- Common Fields
-- These fields are used across all commands
-- Reference: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField
----------------------------------------
local common_fields = {
    message_type = ProtoField.string("iggy.message_type", "Message Type"),
    -- Request common fields
    req_length = ProtoField.uint32("iggy.request.length", "Length", base.DEC, nil, nil, "Length of command code + payload"),
    req_command = ProtoField.uint32("iggy.request.command", "Command Code", base.DEC),
    req_command_name = ProtoField.string("iggy.request.command_name", "Command Name"),
    req_payload = ProtoField.bytes("iggy.request.payload", "Payload"),
    -- Response common fields
    resp_status = ProtoField.uint32("iggy.response.status", "Status Code", base.DEC),
    resp_status_name = ProtoField.string("iggy.response.status_name", "Status Name"),
    resp_length = ProtoField.uint32("iggy.response.length", "Length", base.DEC, nil, nil, "Length of payload"),
    resp_payload = ProtoField.bytes("iggy.response.payload", "Payload"),
}

----------------------------------------
-- Command Registry
----------------------------------------
local COMMANDS = {
    [1] = {
        name = "Ping",
        fields = { request = {}, response = {},},
        request_payload_dissector = function(self, buffer, tree, offset)
            -- No request payload
        end,
        response_payload_dissector = function(self, buffer, tree, offset)
            -- No response payload
        end,
    },
    [38] = {
        name = "LoginUser",
        fields = {
            request = {
                username_len = ProtoField.uint8("iggy.login_user.req.username_len", "Username Length", base.DEC),
                username = ProtoField.string("iggy.login_user.req.username", "Username"),
                password_len = ProtoField.uint8("iggy.login_user.req.password_len", "Password Length", base.DEC),
                password = ProtoField.string("iggy.login_user.req.password", "Password"),
                version_len = ProtoField.uint32("iggy.login_user.req.version_len", "Version Length", base.DEC),
                version = ProtoField.string("iggy.login_user.req.version", "Version"),
                context_len = ProtoField.uint32("iggy.login_user.req.context_len", "Context Length", base.DEC),
                context = ProtoField.string("iggy.login_user.req.context", "Context"),
            },
            response = {
                user_id = ProtoField.uint32("iggy.login_user.resp.user_id", "User ID", base.DEC),
            },
        },
        request_payload_dissector = function(self, buffer, tree, offset)
            -- Username & Password at least 3 bytes: core/common/src/commands/users/defaults.rs
            local f = self.fields.request

            -- Username (u8 length + string)
            local username_len = buffer(offset, 1):uint()
            tree:add(f.username_len, buffer(offset, 1))
            offset = offset + 1
            tree:add(f.username, buffer(offset, username_len))
            offset = offset + username_len

            -- Password (u8 length + string)
            local password_len = buffer(offset, 1):uint()
            tree:add(f.password_len, buffer(offset, 1))
            offset = offset + 1
            tree:add(f.password, buffer(offset, password_len))
            offset = offset + password_len

            -- Version (u32 length + string, optional)
            local version_len = buffer(offset, 4):le_uint()
            tree:add_le(f.version_len, buffer(offset, 4))
            offset = offset + 4
            if version_len > 0 then
                tree:add(f.version, buffer(offset, version_len))
                offset = offset + version_len
            end

            -- Context (u32 length + string, optional)
            local context_len = buffer(offset, 4):le_uint()
            tree:add_le(f.context_len, buffer(offset, 4))
            offset = offset + 4
            if context_len > 0 then
                tree:add(f.context, buffer(offset, context_len))
            end
        end,
        response_payload_dissector = function(self, buffer, tree, offset)
            -- see: core/binary_protocol/src/utils/mapper.rs:455
            local f = self.fields.response
            tree:add_le(f.user_id, buffer(offset, 4))
        end,
    },
    [302] = {
        name = "CreateTopic",
        fields = {
            request = {
                stream_id_kind = ProtoField.uint8("iggy.create_topic.req.stream_id_kind", "Stream ID Kind", base.DEC),
                stream_id_length = ProtoField.uint8("iggy.create_topic.req.stream_id_length", "Stream ID Length", base.DEC),
                stream_id_value = ProtoField.string("iggy.create_topic.req.stream_id_value", "Stream ID Value"),
                topic_id = ProtoField.uint32("iggy.create_topic.req.topic_id", "Topic ID", base.DEC),
                partitions_count = ProtoField.uint32("iggy.create_topic.req.partitions_count", "Partitions Count", base.DEC),
                compression_algorithm = ProtoField.uint8("iggy.create_topic.req.compression_algorithm", "Compression Algorithm", base.DEC),
                message_expiry = ProtoField.uint64("iggy.create_topic.req.message_expiry", "Message Expiry (μs)", base.DEC),
                max_topic_size = ProtoField.uint64("iggy.create_topic.req.max_topic_size", "Max Topic Size (bytes)", base.DEC),
                replication_factor = ProtoField.uint8("iggy.create_topic.req.replication_factor", "Replication Factor", base.DEC),
                name_len = ProtoField.uint8("iggy.create_topic.req.name_len", "Name Length", base.DEC),
                name = ProtoField.string("iggy.create_topic.req.name", "Name"),
            },
            response = {
                topic_id = ProtoField.uint32("iggy.create_topic.resp.topic_id", "Topic ID", base.DEC),
                created_at = ProtoField.uint64("iggy.create_topic.resp.created_at", "Created At (μs)", base.DEC),
                partitions_count = ProtoField.uint32("iggy.create_topic.resp.partitions_count", "Partitions Count", base.DEC),
                message_expiry = ProtoField.uint64("iggy.create_topic.resp.message_expiry", "Message Expiry (μs)", base.DEC),
                compression_algorithm = ProtoField.uint8("iggy.create_topic.resp.compression_algorithm", "Compression Algorithm", base.DEC),
                max_topic_size = ProtoField.uint64("iggy.create_topic.resp.max_topic_size", "Max Topic Size (bytes)", base.DEC),
                replication_factor = ProtoField.uint8("iggy.create_topic.resp.replication_factor", "Replication Factor", base.DEC),
                size = ProtoField.uint64("iggy.create_topic.resp.size", "Size (bytes)", base.DEC),
                messages_count = ProtoField.uint64("iggy.create_topic.resp.messages_count", "Messages Count", base.DEC),
                name_len = ProtoField.uint8("iggy.create_topic.resp.name_len", "Name Length", base.DEC),
                name = ProtoField.string("iggy.create_topic.resp.name", "Name"),
            },
        },
        request_payload_dissector = function(self, buffer, tree, offset)
            -- core/common/src/commands/topics/create_topic.rs:114
            local f = self.fields.request

            -- Stream ID (Identifier: kind + length + value)
            local stream_id_kind = buffer(offset, 1):uint()
            tree:add(f.stream_id_kind, buffer(offset, 1))
            offset = offset + 1

            local stream_id_length = buffer(offset, 1):uint()
            tree:add(f.stream_id_length, buffer(offset, 1))
            offset = offset + 1

            tree:add(f.stream_id_value, buffer(offset, stream_id_length))
            offset = offset + stream_id_length

            -- Topic ID (u32 le, 0 if None)
            tree:add_le(f.topic_id, buffer(offset, 4))
            offset = offset + 4

            -- Partitions Count (u32 le)
            tree:add_le(f.partitions_count, buffer(offset, 4))
            offset = offset + 4

            -- Compression Algorithm (u8)
            tree:add(f.compression_algorithm, buffer(offset, 1))
            offset = offset + 1

            -- Message Expiry (u64 le)
            tree:add_le(f.message_expiry, buffer(offset, 8))
            offset = offset + 8

            -- Max Topic Size (u64 le)
            tree:add_le(f.max_topic_size, buffer(offset, 8))
            offset = offset + 8

            -- Replication Factor (u8, 0 if None)
            tree:add(f.replication_factor, buffer(offset, 1))
            offset = offset + 1

            -- Name (u8 length + string)
            local name_len = buffer(offset, 1):uint()
            tree:add(f.name_len, buffer(offset, 1))
            offset = offset + 1
            tree:add(f.name, buffer(offset, name_len))
        end,
        response_payload_dissector = function(self, buffer, tree, offset)
            -- core/binary_protocol/src/utils/mapper.rs:638
            local f = self.fields.response

            -- Topic ID (u32 le)
            tree:add_le(f.topic_id, buffer(offset, 4))
            offset = offset + 4

            -- Created At (u64 le)
            tree:add_le(f.created_at, buffer(offset, 8))
            offset = offset + 8

            -- Partitions Count (u32 le)
            tree:add_le(f.partitions_count, buffer(offset, 4))
            offset = offset + 4

            -- Message Expiry (u64 le)
            tree:add_le(f.message_expiry, buffer(offset, 8))
            offset = offset + 8

            -- Compression Algorithm (u8)
            tree:add(f.compression_algorithm, buffer(offset, 1))
            offset = offset + 1

            -- Max Topic Size (u64 le)
            tree:add_le(f.max_topic_size, buffer(offset, 8))
            offset = offset + 8

            -- Replication Factor (u8)
            tree:add(f.replication_factor, buffer(offset, 1))
            offset = offset + 1

            -- Size (u64 le)
            tree:add_le(f.size, buffer(offset, 8))
            offset = offset + 8

            -- Messages Count (u64 le)
            tree:add_le(f.messages_count, buffer(offset, 8))
            offset = offset + 8

            -- Name (u8 length + string)
            local name_len = buffer(offset, 1):uint()
            tree:add(f.name_len, buffer(offset, 1))
            offset = offset + 1
            tree:add(f.name, buffer(offset, name_len))
        end,
    },
}

for code, cmd in pairs(COMMANDS) do
    assert(type(code) == "number", "Command code must be number")
    assert(type(cmd.name) == "string" and cmd.name:match("%S"),
        string.format("Command %d: name must be non-empty string", code))
    assert(type(cmd.request_payload_dissector) == "function",
        string.format(
            "Command %d (%s): request_payload_dissector must be function (found %s); use empty fn if no payload",
            code, cmd.name, type(cmd.request_payload_dissector)))
    assert(type(cmd.response_payload_dissector) == "function",
        string.format(
            "Command %d (%s): response_payload_dissector must be function (found %s); use empty fn if no payload",
            code, cmd.name, type(cmd.response_payload_dissector)))
    assert(type(cmd.fields) == "table",
        string.format("Command %d (%s): fields must be table (found %s); use {} if no fields",
            code, cmd.name, type(cmd.fields)))
    assert(type(cmd.fields.request) == "table",
        string.format("Command %d (%s): fields.request must be table (found %s); use {} if none",
            code, cmd.name, type(cmd.fields.request)))
    assert(type(cmd.fields.response) == "table",
        string.format("Command %d (%s): fields.response must be table (found %s); use {} if none",
            code, cmd.name, type(cmd.fields.response)))
end

----------------------------------------
-- Auto-generate iggy.fields from common_fields + command-specific fields
----------------------------------------
local all_fields = {}

-- Helper function to recursively collect ProtoField objects
local function collect_fields(tbl, result)
    for _, value in pairs(tbl) do
        if type(value) == "table" then
            -- Recursively collect from nested tables
            collect_fields(value, result)
        else
            -- Assume it's a ProtoField object
            table.insert(result, value)
        end
    end
end

-- Add common fields
for _, field in pairs(common_fields) do
    table.insert(all_fields, field)
end

-- Add command-specific fields (recursively handles request/response nesting)
for _code, cmd in pairs(COMMANDS) do
    if cmd.fields then
        collect_fields(cmd.fields, all_fields)
    end
end

iggy.fields = all_fields

----------------------------------------
-- Status Code Registry
----------------------------------------
local STATUS_CODES = {
    [0] = "OK",
    [2] = "Unauthenticated",
    -- Add more status codes as needed
}

----------------------------------------
-- Request-Response Tracker Module
-- Handles request-response matching for pipelined protocols using Wireshark's Conversation API
-- Requires Wireshark 4.6+ with Conversation API support
----------------------------------------
local ReqRespTracker = {}
ReqRespTracker.__index = ReqRespTracker

-- Constructor: Create a new request-response tracker
-- @param proto: Protocol object for storing conversation data
-- @return: New tracker instance
function ReqRespTracker.new(proto)
    local self = setmetatable({}, ReqRespTracker)
    self.proto = proto
    return self
end

-- Record a request
-- @param pinfo: Wireshark packet info object
-- @param request_data: Data to associate with this request (e.g., command code)
-- @return: true if recorded successfully, false otherwise
function ReqRespTracker:record_request(pinfo, request_data)
    if not pinfo.conversation then
        return false
    end

    local conv = pinfo.conversation
    local conv_data = conv[self.proto]

    if not conv_data then
        conv_data = {
            queue = {first = 0, last = -1},  -- FIFO queue
            matched = {}  -- [resp_frame_num] = request_data (cache)
        }
    end

    -- Only enqueue on first pass
    if not pinfo.visited then
        local last = conv_data.queue.last + 1
        conv_data.queue.last = last
        conv_data.queue[last] = request_data
    end

    conv[self.proto] = conv_data
    return true
end

-- Find matching request for a response
-- @param pinfo: Wireshark packet info object
-- @return: request_data if found, nil otherwise
function ReqRespTracker:find_request(pinfo)
    if not pinfo.conversation then
        return nil
    end

    local conv = pinfo.conversation
    local conv_data = conv[self.proto]

    if not conv_data then
        return nil
    end

    local resp_frame_num = pinfo.number

    -- Check cache
    if conv_data.matched[resp_frame_num] then
        return conv_data.matched[resp_frame_num]
    end

    -- Dequeue on first pass
    if not pinfo.visited then
        local queue = conv_data.queue
        local first = queue.first

        if first > queue.last then
            return nil  -- Queue empty
        end

        local request_data = queue[first]
        queue[first] = nil  -- Allow garbage collection
        queue.first = first + 1

        -- Cache the result
        conv_data.matched[resp_frame_num] = request_data
        conv[self.proto] = conv_data

        return request_data
    else
        -- Subsequent passes: use cache only
        return conv_data.matched[resp_frame_num]
    end
end
----------------------------------------
-- Create tracker instance for Iggy protocol
----------------------------------------
local request_tracker = ReqRespTracker.new(iggy)

----------------------------------------
-- Main dissector
----------------------------------------
function iggy.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("IGGY")

    local buflen = buffer:len()
    local server_port = iggy.prefs.server_port
    local is_request = (pinfo.dst_port == server_port)
    local is_response = (pinfo.src_port == server_port)
    local cf = common_fields -- Shorthand for common fields

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
            subtree:add(cf.message_type, "Request"):set_generated()

            -- Length and command code
            subtree:add_le(cf.req_length, buffer(0, 4))
            subtree:add_le(cf.req_command, buffer(4, 4))

            -- Early return for unknown commands
            local command_info = COMMANDS[command_code]
            if not command_info then
                local unknown_name = "Unknown"
                subtree:add(cf.req_command_name, unknown_name):set_generated()

                if payload_len > 0 then
                    subtree:add(cf.req_payload, buffer(payload_offset, payload_len))
                end

                pinfo.cols.info:set(string.format("Request: %s (code=%d, length=%d)", unknown_name, command_code, length))
                return
            end

            -- After this point, command_info is guaranteed to exist
            local command_name = command_info.name
            subtree:add(cf.req_command_name, command_name):set_generated()

            -- Payload
            if payload_len > 0 then
                local payload_tree = subtree:add(cf.req_payload, buffer(payload_offset, payload_len))
                command_info.request_payload_dissector(command_info, buffer, payload_tree, payload_offset)
            end

            -- Track request code for request-response matching
            request_tracker:record_request(pinfo, command_code)

            -- Update info column
            pinfo.cols.info:set(string.format("Request: %s (code=%d, length=%d)", command_name, command_code, length))
        elseif is_response then
            -- Response dissection
            local status_code = buffer(0, 4):le_uint()
            local length = buffer(4, 4):le_uint()

            local subtree = tree:add(iggy, buffer(0, total_len), "Iggy Protocol - Response")
            subtree:add(cf.message_type, "Response"):set_generated()

            -- Status code and length
            subtree:add_le(cf.resp_status, buffer(0, 4))
            subtree:add_le(cf.resp_length, buffer(4, 4))

            -- Status name
            local status_name = STATUS_CODES[status_code] or (status_code == 0 and "OK" or string.format("Error(%d)", status_code))
            subtree:add(cf.resp_status_name, status_name):set_generated()

            -- Get matching request code for this TCP stream
            local command_code = request_tracker:find_request(pinfo)
            local command_info = command_code and COMMANDS[command_code]

            -- Early return for unknown commands (no matching request or unimplemented command)
            if not command_info then
                local unknown_name = "Unknown"
                if payload_len > 0 then
                    subtree:add(cf.resp_payload, buffer(payload_offset, payload_len))
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
            subtree:add(cf.req_command_name, command_name):set_generated()

            -- Payload (only for status_code is 0(OK))
            if payload_len > 0 and status_code == 0 then
                local payload_tree = subtree:add(cf.resp_payload, buffer(payload_offset, payload_len))
                command_info.response_payload_dissector(command_info, buffer, payload_tree, payload_offset)
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
-- Lifecycle management
----------------------------------------
local current_port = 0

-- Called when protocol preferences are changed
-- This is where we update port registration
function iggy.prefs_changed()
    local tcp_port = DissectorTable.get("tcp.port")

    if current_port ~= iggy.prefs.server_port then
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
end

----------------------------------------
-- Initial port registration
----------------------------------------
DissectorTable.get("tcp.port"):add(iggy.prefs.server_port, iggy)
current_port = iggy.prefs.server_port
