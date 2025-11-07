-- Iggy Protocol Dissector
-- Supports Request/Response detection with extensible command registry

----------------------------------------
-- Load modules
----------------------------------------
local fields = require("iggy.fields")
local iggy_module = require("iggy.iggy")

----------------------------------------
-- Protocol definition
----------------------------------------
local iggy = Proto("iggy", "Iggy Protocol")

----------------------------------------
-- Preferences
----------------------------------------
iggy.prefs.port = Pref.uint("TCP Port", 8090, "IGGY server port number")

----------------------------------------
-- Register all protocol fields
----------------------------------------
iggy.fields = fields.get_all()

----------------------------------------
-- Register expert info
----------------------------------------
iggy.experts = {
    iggy_module.ef_too_short,
    iggy_module.ef_invalid_length,
    iggy_module.ef_error_status,
}

----------------------------------------
-- Port registration tracking
----------------------------------------
local current_port = 0

----------------------------------------
-- Main dissector
----------------------------------------
function iggy.dissector(tvbuf, pktinfo, root)
    pktinfo.cols.protocol:set("IGGY")

    local msg_type = iggy_module.detect_message_type(tvbuf)

    if msg_type == "request" then
        return iggy_module.dissect_request(tvbuf, pktinfo, root, iggy)
    elseif msg_type == "response" then
        return iggy_module.dissect_response(tvbuf, pktinfo, root, iggy)
    else
        local tree = root:add(iggy, tvbuf(), "Iggy Protocol (Unknown)")
        tree:add_proto_expert_info(iggy_module.ef_too_short, "Cannot determine message type")
        return 0
    end
end

----------------------------------------
-- Initialization function (called when preferences change)
----------------------------------------
function iggy.init()
    local tcp_port = DissectorTable.get("tcp.port")

    -- Remove old port registration if exists
    if current_port > 0 then
        tcp_port:remove(current_port, iggy)
    end

    -- Register new port
    current_port = iggy.prefs.port
    tcp_port:add(current_port, iggy)
end
