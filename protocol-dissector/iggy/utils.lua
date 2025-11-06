-- Basic type helpers module for Iggy Protocol Dissector
-- Pure utility functions with no protocol-specific logic

local utils = {}

----------------------------------------
-- Basic type helpers (for reusability)
----------------------------------------

-- Read basic types (returns value only)
function utils.read_u8(tvbuf, offset)
    return tvbuf:range(offset, 1):uint()
end

function utils.read_u32_le(tvbuf, offset)
    return tvbuf:range(offset, 4):le_uint()
end

function utils.read_u64_le(tvbuf, offset)
    return tvbuf:range(offset, 8):le_uint64()
end

-- Dissect basic types (adds to tree, returns new offset or nil on bounds check failure)
function utils.dissect_u8(tvbuf, tree, offset, field, pktlen)
    if offset + 1 > pktlen then
        return nil
    end
    tree:add(field, tvbuf:range(offset, 1))
    return offset + 1
end

function utils.dissect_u32_le(tvbuf, tree, offset, field, pktlen)
    if offset + 4 > pktlen then
        return nil
    end
    tree:add_le(field, tvbuf:range(offset, 4))
    return offset + 4
end

function utils.dissect_u64_le(tvbuf, tree, offset, field, pktlen)
    if offset + 8 > pktlen then
        return nil
    end
    tree:add_le(field, tvbuf:range(offset, 8))
    return offset + 8
end

----------------------------------------
-- String dissection helpers
----------------------------------------

-- Generic string dissector with length prefix
-- len_size: size of length field in bytes (1 for u8, 4 for u32)
-- read_len_fn: function(tvbuf, offset) -> length_value
-- add_len_fn: function(t, f, r) -> void (tree.add or tree.add_le)
function utils.dissect_string_with_len(tvbuf, tree, offset, pktlen, len_field, str_field, len_size, read_len_fn, add_len_fn)
    if offset + len_size > pktlen then
        return nil
    end

    local len = read_len_fn(tvbuf, offset)
    add_len_fn(tree, len_field, tvbuf:range(offset, len_size))
    offset = offset + len_size

    if len > 0 then
        if offset + len > pktlen then
            return nil
        end
        tree:add(str_field, tvbuf:range(offset, len))
        offset = offset + len
    end

    return offset
end

-- Convenience wrapper for u8 length prefix
function utils.dissect_string_with_u8_len(tvbuf, tree, offset, pktlen, len_field, str_field)
    return utils.dissect_string_with_len(tvbuf, tree, offset, pktlen, len_field, str_field,
        1, utils.read_u8, function(t, f, r) t:add(f, r) end)
end

-- Convenience wrapper for u32 little-endian length prefix
function utils.dissect_string_with_u32_le_len(tvbuf, tree, offset, pktlen, len_field, str_field)
    return utils.dissect_string_with_len(tvbuf, tree, offset, pktlen, len_field, str_field,
        4, utils.read_u32_le, function(t, f, r) t:add_le(f, r) end)
end

return utils
