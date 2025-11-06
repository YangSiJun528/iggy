-- Common data type dissectors module for Iggy Protocol Dissector

local types = {}

-- Dependencies
local utils = require("iggy.utils")

----------------------------------------
-- Expert info
----------------------------------------
types.ef_too_short = ProtoExpert.new("iggy.too_short.expert",
                                      "Iggy packet too short",
                                      expert.group.MALFORMED, expert.severity.ERROR)

----------------------------------------
-- Common data type dissectors
----------------------------------------

-- Dissect Identifier (kind + length + value)
-- id_fields: required table with { kind, length, value_num, value_str }
-- Returns: offset after parsing, or nil on failure
function types.dissect_identifier(tvbuf, tree, offset, pktlen, label, id_fields)
    -- Identifier constants
    local ID_KIND_NUMERIC = 1
    local ID_KIND_STRING  = 2
    local ID_HEADER_SIZE = 2  -- kind(1) + length(1)
    local ID_MIN_SIZE    = 3  -- kind(1) + length(1) + min_value(1)
    local ID_NUMERIC_VALUE_SIZE = 4  -- u32 for numeric identifiers

    local remaining = pktlen - offset
    if remaining < ID_MIN_SIZE then
        tree:add_proto_expert_info(types.ef_too_short,
            string.format("%s: insufficient data for identifier header", label))
        return nil
    end

    local kind = utils.read_u8(tvbuf, offset)
    local length = utils.read_u8(tvbuf, offset + 1)

    if remaining < ID_HEADER_SIZE + length then
        tree:add_proto_expert_info(types.ef_too_short,
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
function types.dissect_consumer(tvbuf, tree, offset, pktlen, label, consumer_fields)
    -- Consumer constants
    local CONSUMER_KIND_CONSUMER       = 1
    local CONSUMER_KIND_CONSUMER_GROUP = 2
    local CONSUMER_MIN_SIZE = 4  -- kind(1) + id_min_size(3)

    local remaining = pktlen - offset
    if remaining < CONSUMER_MIN_SIZE then
        tree:add_proto_expert_info(types.ef_too_short,
            string.format("%s: insufficient data for consumer", label))
        return nil
    end

    local consumer_kind = utils.read_u8(tvbuf, offset)
    local consumer_kind_name = (consumer_kind == CONSUMER_KIND_CONSUMER) and "Consumer" or (consumer_kind == CONSUMER_KIND_CONSUMER_GROUP) and "ConsumerGroup" or "Unknown"

    local consumer_tree = tree:add(string.format("%s: %s", label, consumer_kind_name))
    consumer_tree:add(consumer_fields.kind, tvbuf:range(offset, 1))

    local new_offset = types.dissect_identifier(tvbuf, consumer_tree, offset + 1, pktlen, "ID", consumer_fields.id_fields)
    if not new_offset then
        return nil
    end

    return new_offset
end

return types
