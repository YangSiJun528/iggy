-- Iggy Protocol Dissector (Simple Version - Ping & GetStats only)
-- This is a simple test dissector for learning and testing purposes

local iggy_proto = Proto("iggy", "Iggy Protocol")

-- Protocol fields
local f_length = ProtoField.uint32("iggy.length", "Length", base.DEC)
local f_code = ProtoField.uint32("iggy.code", "Command Code", base.DEC)
local f_code_name = ProtoField.string("iggy.code_name", "Command Name", base.ASCII)

iggy_proto.fields = { f_length, f_code, f_code_name }

-- Command codes
local COMMAND_CODES = {
    [1] = "Ping",
    [10] = "GetStats"
}

-- Dissector function
function iggy_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = iggy_proto.name

    local subtree = tree:add(iggy_proto, buffer(), "Iggy Protocol Data")

    -- Parse LENGTH field (4 bytes, little-endian)
    if length < 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for LENGTH field")
        return
    end
    local msg_length = buffer(0, 4):le_uint()
    subtree:add_le(f_length, buffer(0, 4))

    -- Parse CODE field (4 bytes, little-endian)
    if length < 8 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for CODE field")
        return
    end
    local command_code = buffer(4, 4):le_uint()
    subtree:add_le(f_code, buffer(4, 4))

    -- Add command name
    local command_name = COMMAND_CODES[command_code] or "Unknown"
    subtree:add(f_code_name, command_name)

    -- Update info column
    pinfo.cols.info = string.format("Command: %s (code=%d, length=%d)",
                                    command_name, command_code, msg_length)

    -- Validate: for Ping and GetStats, payload should be empty
    if command_code == 1 or command_code == 10 then
        if msg_length ~= 4 then
            subtree:add_expert_info(PI_PROTOCOL, PI_WARN,
                string.format("%s should have empty payload (length=4), but got length=%d",
                              command_name, msg_length))
        end

        if length > 8 then
            subtree:add_expert_info(PI_PROTOCOL, PI_WARN,
                string.format("%s has unexpected extra data after header", command_name))
        end
    end
end

-- Register the dissector for TCP port 8090 (default Iggy port)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8090, iggy_proto)
