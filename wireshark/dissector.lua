local iggy = Proto("iggy", "Iggy Protocol")

local f_length = ProtoField.uint32("iggy.length", "Length", base.DEC_LE)
local f_command = ProtoField.uint32("iggy.command", "Command", base.DEC_LE)
local f_payload = ProtoField.bytes("iggy.payload", "Payload")

iggy.fields = { f_length, f_command, f_payload }

local COMMAND_NAMES = {
    [1] = "PING",
}

function iggy.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("IGGY")

    if buffer:len() < 8 then
        return 0
    end

    local subtree = tree:add(iggy, buffer(), "Iggy Protocol")

    local length = buffer(0, 4):le_uint()
    subtree:add(f_length, buffer(0, 4)):append_text(" (" .. length .. " bytes)")

    local command_code = buffer(4, 4):le_uint()
    local command_name = COMMAND_NAMES[command_code] or "UNKNOWN"
    local command_field = subtree:add(f_command, buffer(4, 4))
    command_field:append_text(" (" .. command_name .. ")")

    if length > 4 and buffer:len() >= 8 + (length - 4) then
        local payload_length = length - 4
        subtree:add(f_payload, buffer(8, payload_length))
    end

    pinfo.cols.info:set(string.format("%s (Length: %d)", command_name, length))

    return buffer:len()
end

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(8091, iggy)
tcp_table:add(8092, iggy)
tcp_table:add(8093, iggy)
tcp_table:add(8094, iggy)
