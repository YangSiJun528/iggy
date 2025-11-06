-- Iggy Protocol Dissector
-- Supports Request/Response detection with extensible command registry

----------------------------------------
-- Setup module path
----------------------------------------
-- Get the directory where this script is located
local script_path = debug.getinfo(1, "S").source:sub(2)
local script_dir = script_path:match("(.*/)")
if script_dir then
    package.path = script_dir .. "?.lua;" .. script_dir .. "?/init.lua;" .. package.path
end

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
-- Heuristic dissector
----------------------------------------
local function heur_dissect_iggy(tvbuf, pktinfo, root)
    if tvbuf:len() < 8 then
        return false
    end

    local msg_type = iggy_module.detect_message_type(tvbuf)

    if not msg_type then
        return false
    end

    iggy.dissector(tvbuf, pktinfo, root)
    pktinfo.conversation = iggy

    return true
end

iggy:register_heuristic("tcp", heur_dissect_iggy)
