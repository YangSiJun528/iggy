-- IGGY Protocol Dissector for Wireshark
-- Version: 0.1.0
-- Author: IGGY Wireshark Dissector Project
-- Description: Dissector for IGGY messaging protocol over TCP

-- Create protocol
local iggy_proto = Proto("iggy", "IGGY Messaging Protocol")

-- Protocol fields
local f = iggy_proto.fields

-- Common header fields
f.length = ProtoField.uint32("iggy.length", "Length", base.DEC)
f.command = ProtoField.uint32("iggy.command", "Command Code", base.DEC)
f.command_name = ProtoField.string("iggy.command_name", "Command Name")
f.status = ProtoField.uint32("iggy.status", "Status", base.DEC)
f.status_text = ProtoField.string("iggy.status_text", "Status Text")
f.payload_length = ProtoField.uint32("iggy.payload_length", "Payload Length", base.DEC)

-- Identifier fields
f.identifier_kind = ProtoField.uint8("iggy.identifier.kind", "Identifier Kind", base.DEC)
f.identifier_length = ProtoField.uint8("iggy.identifier.length", "Identifier Length", base.DEC)
f.identifier_value_numeric = ProtoField.uint32("iggy.identifier.value.numeric", "Identifier (Numeric)", base.DEC)
f.identifier_value_string = ProtoField.string("iggy.identifier.value.string", "Identifier (String)")

-- Partitioning fields
f.partitioning_kind = ProtoField.uint8("iggy.partitioning.kind", "Partitioning Kind", base.DEC)
f.partitioning_length = ProtoField.uint8("iggy.partitioning.length", "Partitioning Length", base.DEC)
f.partitioning_value = ProtoField.uint32("iggy.partitioning.partition_id", "Partition ID", base.DEC)

-- Consumer fields
f.consumer_kind = ProtoField.uint8("iggy.consumer.kind", "Consumer Kind", base.DEC)

-- Polling strategy fields
f.strategy_kind = ProtoField.uint8("iggy.strategy.kind", "Strategy Kind", base.DEC)
f.strategy_value = ProtoField.uint64("iggy.strategy.value", "Strategy Value", base.DEC)

-- Message fields
f.message_count = ProtoField.uint32("iggy.messages.count", "Message Count", base.DEC)
f.partition_id = ProtoField.uint32("iggy.partition_id", "Partition ID", base.DEC)
f.auto_commit = ProtoField.uint8("iggy.auto_commit", "Auto Commit", base.DEC)
f.offset = ProtoField.uint64("iggy.offset", "Offset", base.DEC)

-- String fields
f.string_u8 = ProtoField.string("iggy.string_u8", "String (u8 length)")
f.string_u32 = ProtoField.string("iggy.string_u32", "String (u32 length)")

-- User fields
f.username = ProtoField.string("iggy.username", "Username")
f.password = ProtoField.string("iggy.password", "Password")
f.version = ProtoField.string("iggy.version", "Version")
f.context = ProtoField.string("iggy.context", "Context")

-- Stream/Topic fields
f.stream_id = ProtoField.uint32("iggy.stream_id", "Stream ID", base.DEC)
f.topic_id = ProtoField.uint32("iggy.topic_id", "Topic ID", base.DEC)
f.name = ProtoField.string("iggy.name", "Name")

-- Command code to name mapping
local command_names = {
    -- System (1-22)
    [1] = "PING",
    [10] = "GET_STATS",
    [11] = "GET_SNAPSHOT_FILE",
    [12] = "GET_CLUSTER_METADATA",
    [20] = "GET_ME",
    [21] = "GET_CLIENT",
    [22] = "GET_CLIENTS",

    -- User Management (31-44)
    [31] = "GET_USER",
    [32] = "GET_USERS",
    [33] = "CREATE_USER",
    [34] = "DELETE_USER",
    [35] = "UPDATE_USER",
    [36] = "UPDATE_PERMISSIONS",
    [37] = "CHANGE_PASSWORD",
    [38] = "LOGIN_USER",
    [39] = "LOGOUT_USER",
    [41] = "GET_PERSONAL_ACCESS_TOKENS",
    [42] = "CREATE_PERSONAL_ACCESS_TOKEN",
    [43] = "DELETE_PERSONAL_ACCESS_TOKEN",
    [44] = "LOGIN_WITH_PERSONAL_ACCESS_TOKEN",

    -- Messages (100-122)
    [100] = "POLL_MESSAGES",
    [101] = "SEND_MESSAGES",
    [102] = "FLUSH_UNSAVED_BUFFER",
    [120] = "GET_CONSUMER_OFFSET",
    [121] = "STORE_CONSUMER_OFFSET",
    [122] = "DELETE_CONSUMER_OFFSET",

    -- Streams (200-205)
    [200] = "GET_STREAM",
    [201] = "GET_STREAMS",
    [202] = "CREATE_STREAM",
    [203] = "DELETE_STREAM",
    [204] = "UPDATE_STREAM",
    [205] = "PURGE_STREAM",

    -- Topics (300-305)
    [300] = "GET_TOPIC",
    [301] = "GET_TOPICS",
    [302] = "CREATE_TOPIC",
    [303] = "DELETE_TOPIC",
    [304] = "UPDATE_TOPIC",
    [305] = "PURGE_TOPIC",

    -- Partitions (402-403)
    [402] = "CREATE_PARTITIONS",
    [403] = "DELETE_PARTITIONS",

    -- Segments (503)
    [503] = "DELETE_SEGMENTS",

    -- Consumer Groups (600-605)
    [600] = "GET_CONSUMER_GROUP",
    [601] = "GET_CONSUMER_GROUPS",
    [602] = "CREATE_CONSUMER_GROUP",
    [603] = "DELETE_CONSUMER_GROUP",
    [604] = "JOIN_CONSUMER_GROUP",
    [605] = "LEAVE_CONSUMER_GROUP",
}

-- Identifier kind names
local identifier_kind_names = {
    [1] = "Numeric",
    [2] = "String",
}

-- Partitioning kind names
local partitioning_kind_names = {
    [1] = "Balanced",
    [2] = "PartitionId",
    [3] = "MessagesKey",
}

-- Consumer kind names
local consumer_kind_names = {
    [1] = "Consumer",
    [2] = "ConsumerGroup",
}

-- Strategy kind names
local strategy_kind_names = {
    [1] = "Offset",
    [2] = "Timestamp",
    [3] = "First",
    [4] = "Last",
    [5] = "Next",
}

-- Helper function: Get command name
local function get_command_name(code)
    return command_names[code] or string.format("UNKNOWN (0x%04X)", code)
end

-- Helper function: Parse identifier
-- Returns: (size consumed, numeric_value or string_value, display_text)
local function parse_identifier(buffer, offset, tree, label)
    local start_offset = offset

    -- Check if we have enough data for kind and length
    if buffer:len() < offset + 2 then
        return 0, nil, nil
    end

    local kind = buffer(offset, 1):le_uint()
    local length = buffer(offset + 1, 1):le_uint()
    offset = offset + 2

    -- Check if we have enough data for the value
    if buffer:len() < offset + length then
        return 0, nil, nil
    end

    local subtree = tree:add(iggy_proto, buffer(start_offset, 2 + length), label)
    subtree:add_le(f.identifier_kind, buffer(start_offset, 1)):append_text(" (" .. (identifier_kind_names[kind] or "Unknown") .. ")")
    subtree:add_le(f.identifier_length, buffer(start_offset + 1, 1))

    local value = nil
    local display = nil

    if kind == 1 then
        -- Numeric (u32)
        if length == 4 then
            value = buffer(offset, 4):le_uint()
            subtree:add_le(f.identifier_value_numeric, buffer(offset, 4))
            display = tostring(value)
        end
    elseif kind == 2 then
        -- String
        value = buffer(offset, length):string()
        subtree:add(f.identifier_value_string, buffer(offset, length))
        display = value
    end

    if display then
        subtree:append_text(": " .. display)
    end

    return 2 + length, value, display
end

-- Helper function: Parse string with u8 length
local function parse_string_u8(buffer, offset, tree, field, label)
    if buffer:len() < offset + 1 then
        return 0, nil
    end

    local length = buffer(offset, 1):le_uint()

    if buffer:len() < offset + 1 + length then
        return 0, nil
    end

    local value = buffer(offset + 1, length):string()
    local item = tree:add(field, buffer(offset + 1, length), value)
    if label then
        item:set_text(label .. ": " .. value)
    end

    return 1 + length, value
end

-- Helper function: Parse string with u32 length
local function parse_string_u32(buffer, offset, tree, field, label)
    if buffer:len() < offset + 4 then
        return 0, nil
    end

    local length = buffer(offset, 4):le_uint()

    if length == 0 then
        return 4, nil
    end

    if buffer:len() < offset + 4 + length then
        return 0, nil
    end

    local value = buffer(offset + 4, length):string()
    local item = tree:add(field, buffer(offset + 4, length), value)
    if label then
        item:set_text(label .. ": " .. value)
    end

    return 4 + length, value
end

-- Helper function: Parse partitioning
local function parse_partitioning(buffer, offset, tree)
    local start_offset = offset

    if buffer:len() < offset + 2 then
        return 0
    end

    local kind = buffer(offset, 1):le_uint()
    local length = buffer(offset + 1, 1):le_uint()
    offset = offset + 2

    if buffer:len() < offset + length then
        return 0
    end

    local subtree = tree:add(iggy_proto, buffer(start_offset, 2 + length), "Partitioning")
    subtree:add_le(f.partitioning_kind, buffer(start_offset, 1)):append_text(" (" .. (partitioning_kind_names[kind] or "Unknown") .. ")")
    subtree:add_le(f.partitioning_length, buffer(start_offset + 1, 1))

    if kind == 2 and length == 4 then
        -- PartitionId
        local partition_id = buffer(offset, 4):le_uint()
        subtree:add_le(f.partitioning_value, buffer(offset, 4))
        subtree:append_text(": " .. tostring(partition_id))
    elseif kind == 3 then
        -- MessagesKey
        subtree:append_text(": Key (" .. length .. " bytes)")
    elseif kind == 1 then
        -- Balanced
        subtree:append_text(": Balanced (Round-robin)")
    end

    return 2 + length
end

-- Command parsers
local command_parsers = {}

-- PING (1) - No payload
command_parsers[1] = function(buffer, pinfo, tree, offset)
    tree:add(iggy_proto, buffer(offset, 0), "PING: No payload")
    return 0
end

-- LOGIN_USER (38)
command_parsers[38] = function(buffer, pinfo, tree, offset)
    local start_offset = offset
    local consumed

    -- Username
    consumed = parse_string_u8(buffer, offset, tree, f.username, "Username")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Password
    consumed = parse_string_u8(buffer, offset, tree, f.password, "Password")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Version (optional, u32 length)
    consumed = parse_string_u32(buffer, offset, tree, f.version, "Version")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Context (optional, u32 length)
    consumed = parse_string_u32(buffer, offset, tree, f.context, "Context")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- CREATE_STREAM (202)
command_parsers[202] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream ID
    if buffer:len() < offset + 4 then return -1 end
    tree:add_le(f.stream_id, buffer(offset, 4)):append_text(" (0 = auto-assign)")
    offset = offset + 4

    -- Name
    local consumed = parse_string_u8(buffer, offset, tree, f.name, "Stream Name")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- POLL_MESSAGES (100)
command_parsers[100] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Consumer kind
    if buffer:len() < offset + 1 then return -1 end
    local consumer_kind = buffer(offset, 1):le_uint()
    tree:add_le(f.consumer_kind, buffer(offset, 1)):append_text(" (" .. (consumer_kind_names[consumer_kind] or "Unknown") .. ")")
    offset = offset + 1

    -- Consumer identifier
    local consumed = parse_identifier(buffer, offset, tree, "Consumer ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Stream identifier
    consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Partition ID
    if buffer:len() < offset + 4 then return -1 end
    tree:add_le(f.partition_id, buffer(offset, 4))
    offset = offset + 4

    -- Polling strategy
    if buffer:len() < offset + 9 then return -1 end
    local strategy_kind = buffer(offset, 1):le_uint()
    tree:add_le(f.strategy_kind, buffer(offset, 1)):append_text(" (" .. (strategy_kind_names[strategy_kind] or "Unknown") .. ")")
    tree:add_le(f.strategy_value, buffer(offset + 1, 8))
    offset = offset + 9

    -- Count
    if buffer:len() < offset + 4 then return -1 end
    tree:add_le(f.message_count, buffer(offset, 4))
    offset = offset + 4

    -- Auto commit
    if buffer:len() < offset + 1 then return -1 end
    local auto_commit = buffer(offset, 1):le_uint()
    tree:add_le(f.auto_commit, buffer(offset, 1)):append_text(auto_commit == 1 and " (true)" or " (false)")
    offset = offset + 1

    return offset - start_offset
end

-- SEND_MESSAGES (101)
command_parsers[101] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Metadata length
    if buffer:len() < offset + 4 then return -1 end
    local metadata_length = buffer(offset, 4):le_uint()
    tree:add_le(iggy_proto, buffer(offset, 4), "Metadata Length: " .. metadata_length)
    offset = offset + 4

    local metadata_start = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Partitioning
    consumed = parse_partitioning(buffer, offset, tree)
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Messages count
    if buffer:len() < offset + 4 then return -1 end
    local msg_count = buffer(offset, 4):le_uint()
    tree:add_le(f.message_count, buffer(offset, 4))
    offset = offset + 4

    -- Index table (16 bytes per message)
    local index_table_size = msg_count * 16
    if buffer:len() < offset + index_table_size then return -1 end
    tree:add(iggy_proto, buffer(offset, index_table_size), "Index Table (" .. msg_count .. " entries)")
    offset = offset + index_table_size

    -- Messages data (rest of payload)
    local remaining = buffer:len() - offset
    if remaining > 0 then
        tree:add(iggy_proto, buffer(offset, remaining), "Messages Data (" .. remaining .. " bytes)")
        offset = offset + remaining
    end

    return offset - start_offset
end

-- STORE_CONSUMER_OFFSET (121)
command_parsers[121] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Consumer kind
    if buffer:len() < offset + 1 then return -1 end
    local consumer_kind = buffer(offset, 1):le_uint()
    tree:add_le(f.consumer_kind, buffer(offset, 1)):append_text(" (" .. (consumer_kind_names[consumer_kind] or "Unknown") .. ")")
    offset = offset + 1

    -- Consumer identifier
    local consumed = parse_identifier(buffer, offset, tree, "Consumer ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Stream identifier
    consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Partition ID
    if buffer:len() < offset + 4 then return -1 end
    tree:add_le(f.partition_id, buffer(offset, 4))
    offset = offset + 4

    -- Offset
    if buffer:len() < offset + 8 then return -1 end
    tree:add_le(f.offset, buffer(offset, 8))
    offset = offset + 8

    return offset - start_offset
end

-- GET_STREAM (200) / GET_TOPIC (300) - Similar pattern
command_parsers[200] = function(buffer, pinfo, tree, offset)
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    return consumed
end

-- GET_STATS (10) - No payload
command_parsers[10] = function(buffer, pinfo, tree, offset)
    tree:add(iggy_proto, buffer(offset, 0), "GET_STATS: No payload")
    return 0
end

-- GET_STREAMS (201) - No payload
command_parsers[201] = function(buffer, pinfo, tree, offset)
    tree:add(iggy_proto, buffer(offset, 0), "GET_STREAMS: No payload")
    return 0
end

-- DELETE_STREAM (203)
command_parsers[203] = function(buffer, pinfo, tree, offset)
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    return consumed
end

-- UPDATE_STREAM (204)
command_parsers[204] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Name
    consumed = parse_string_u8(buffer, offset, tree, f.name, "New Stream Name")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- PURGE_STREAM (205)
command_parsers[205] = function(buffer, pinfo, tree, offset)
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    return consumed
end

-- GET_TOPIC (300)
command_parsers[300] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- GET_TOPICS (301)
command_parsers[301] = function(buffer, pinfo, tree, offset)
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    return consumed
end

-- CREATE_TOPIC (302)
command_parsers[302] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic ID
    if buffer:len() < offset + 4 then return -1 end
    tree:add_le(f.topic_id, buffer(offset, 4)):append_text(" (0 = auto-assign)")
    offset = offset + 4

    -- Partitions count
    if buffer:len() < offset + 4 then return -1 end
    tree:add_le(iggy_proto, buffer(offset, 4), "Partitions Count: " .. buffer(offset, 4):le_uint())
    offset = offset + 4

    -- Name
    consumed = parse_string_u8(buffer, offset, tree, f.name, "Topic Name")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Message expiry (optional fields may follow, parse what we can)
    if buffer:len() >= offset + 4 then
        tree:add_le(iggy_proto, buffer(offset, 4), "Message Expiry (seconds): " .. buffer(offset, 4):le_uint())
        offset = offset + 4
    end

    return offset - start_offset
end

-- DELETE_TOPIC (303)
command_parsers[303] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- UPDATE_TOPIC (304)
command_parsers[304] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Name
    consumed = parse_string_u8(buffer, offset, tree, f.name, "New Topic Name")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- PURGE_TOPIC (305)
command_parsers[305] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- GET_CONSUMER_OFFSET (120)
command_parsers[120] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Consumer kind
    if buffer:len() < offset + 1 then return -1 end
    local consumer_kind = buffer(offset, 1):le_uint()
    tree:add_le(f.consumer_kind, buffer(offset, 1)):append_text(" (" .. (consumer_kind_names[consumer_kind] or "Unknown") .. ")")
    offset = offset + 1

    -- Consumer identifier
    local consumed = parse_identifier(buffer, offset, tree, "Consumer ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Stream identifier
    consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Partition ID
    if buffer:len() < offset + 4 then return -1 end
    tree:add_le(f.partition_id, buffer(offset, 4))
    offset = offset + 4

    return offset - start_offset
end

-- LOGOUT_USER (39) - No payload
command_parsers[39] = function(buffer, pinfo, tree, offset)
    tree:add(iggy_proto, buffer(offset, 0), "LOGOUT_USER: No payload")
    return 0
end

-- GET_USER (31)
command_parsers[31] = function(buffer, pinfo, tree, offset)
    local consumed = parse_identifier(buffer, offset, tree, "User ID")
    if consumed == 0 then return -1 end
    return consumed
end

-- GET_USERS (32) - No payload
command_parsers[32] = function(buffer, pinfo, tree, offset)
    tree:add(iggy_proto, buffer(offset, 0), "GET_USERS: No payload")
    return 0
end

-- CREATE_USER (33)
command_parsers[33] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Username
    local consumed = parse_string_u8(buffer, offset, tree, f.username, "Username")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Password
    consumed = parse_string_u8(buffer, offset, tree, f.password, "Password")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Status
    if buffer:len() < offset + 1 then return -1 end
    local status = buffer(offset, 1):le_uint()
    tree:add_le(iggy_proto, buffer(offset, 1), "User Status: " .. status .. (status == 1 and " (Active)" or " (Inactive)"))
    offset = offset + 1

    -- Has Permissions flag
    if buffer:len() < offset + 1 then return -1 end
    local has_permissions = buffer(offset, 1):le_uint()
    tree:add_le(iggy_proto, buffer(offset, 1), "Has Permissions: " .. (has_permissions == 1 and "Yes" or "No"))
    offset = offset + 1

    -- Permissions (if present)
    if has_permissions == 1 then
        if buffer:len() < offset + 4 then return -1 end
        local perm_length = buffer(offset, 4):le_uint()
        tree:add_le(iggy_proto, buffer(offset, 4), "Permissions Length: " .. perm_length)
        offset = offset + 4

        if buffer:len() < offset + perm_length then return -1 end
        tree:add(iggy_proto, buffer(offset, perm_length), "Permissions Data (" .. perm_length .. " bytes)")
        offset = offset + perm_length
    end

    return offset - start_offset
end

-- DELETE_USER (34)
command_parsers[34] = function(buffer, pinfo, tree, offset)
    local consumed = parse_identifier(buffer, offset, tree, "User ID")
    if consumed == 0 then return -1 end
    return consumed
end

-- UPDATE_USER (35)
command_parsers[35] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- User identifier
    local consumed = parse_identifier(buffer, offset, tree, "User ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Has Username flag
    if buffer:len() < offset + 1 then return -1 end
    local has_username = buffer(offset, 1):le_uint()
    tree:add_le(iggy_proto, buffer(offset, 1), "Has Username: " .. (has_username == 1 and "Yes" or "No"))
    offset = offset + 1

    -- Username (if present)
    if has_username == 1 then
        consumed = parse_string_u8(buffer, offset, tree, f.username, "New Username")
        if consumed == 0 then return -1 end
        offset = offset + consumed
    end

    -- Has Status flag
    if buffer:len() < offset + 1 then return -1 end
    local has_status = buffer(offset, 1):le_uint()
    tree:add_le(iggy_proto, buffer(offset, 1), "Has Status: " .. (has_status == 1 and "Yes" or "No"))
    offset = offset + 1

    -- Status (if present)
    if has_status == 1 then
        if buffer:len() < offset + 1 then return -1 end
        local status = buffer(offset, 1):le_uint()
        tree:add_le(iggy_proto, buffer(offset, 1), "New Status: " .. status .. (status == 1 and " (Active)" or " (Inactive)"))
        offset = offset + 1
    end

    return offset - start_offset
end

-- UPDATE_PERMISSIONS (36)
command_parsers[36] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- User identifier
    local consumed = parse_identifier(buffer, offset, tree, "User ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Has Permissions flag
    if buffer:len() < offset + 1 then return -1 end
    local has_permissions = buffer(offset, 1):le_uint()
    tree:add_le(iggy_proto, buffer(offset, 1), "Has Permissions: " .. (has_permissions == 1 and "Yes" or "No"))
    offset = offset + 1

    -- Permissions (if present)
    if has_permissions == 1 then
        if buffer:len() < offset + 4 then return -1 end
        local perm_length = buffer(offset, 4):le_uint()
        tree:add_le(iggy_proto, buffer(offset, 4), "Permissions Length: " .. perm_length)
        offset = offset + 4

        if buffer:len() < offset + perm_length then return -1 end
        tree:add(iggy_proto, buffer(offset, perm_length), "Permissions Data (" .. perm_length .. " bytes)")
        offset = offset + perm_length
    end

    return offset - start_offset
end

-- CHANGE_PASSWORD (37)
command_parsers[37] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- User identifier
    local consumed = parse_identifier(buffer, offset, tree, "User ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Current password
    consumed = parse_string_u8(buffer, offset, tree, f.password, "Current Password")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- New password
    consumed = parse_string_u8(buffer, offset, tree, f.password, "New Password")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- GET_PERSONAL_ACCESS_TOKENS (41) - No payload
command_parsers[41] = function(buffer, pinfo, tree, offset)
    tree:add(iggy_proto, buffer(offset, 0), "GET_PERSONAL_ACCESS_TOKENS: No payload")
    return 0
end

-- CREATE_PERSONAL_ACCESS_TOKEN (42)
command_parsers[42] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Token name
    local consumed = parse_string_u8(buffer, offset, tree, f.name, "Token Name")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Expiry (u64)
    if buffer:len() < offset + 8 then return -1 end
    tree:add_le(iggy_proto, buffer(offset, 8), "Expiry (u64): " .. buffer(offset, 8):le_uint64())
    offset = offset + 8

    return offset - start_offset
end

-- DELETE_PERSONAL_ACCESS_TOKEN (43)
command_parsers[43] = function(buffer, pinfo, tree, offset)
    local consumed = parse_string_u8(buffer, offset, tree, f.name, "Token Name")
    if consumed == 0 then return -1 end
    return consumed
end

-- LOGIN_WITH_PERSONAL_ACCESS_TOKEN (44)
command_parsers[44] = function(buffer, pinfo, tree, offset)
    local consumed = parse_string_u8(buffer, offset, tree, f.string_u8, "Personal Access Token")
    if consumed == 0 then return -1 end
    return consumed
end

-- GET_CONSUMER_GROUP (600)
command_parsers[600] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Consumer Group identifier
    consumed = parse_identifier(buffer, offset, tree, "Consumer Group ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- GET_CONSUMER_GROUPS (601)
command_parsers[601] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- CREATE_CONSUMER_GROUP (602)
command_parsers[602] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Consumer Group ID
    if buffer:len() < offset + 4 then return -1 end
    tree:add_le(iggy_proto, buffer(offset, 4), "Consumer Group ID: " .. buffer(offset, 4):le_uint())
    offset = offset + 4

    -- Name
    consumed = parse_string_u8(buffer, offset, tree, f.name, "Consumer Group Name")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- DELETE_CONSUMER_GROUP (603)
command_parsers[603] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Consumer Group identifier
    consumed = parse_identifier(buffer, offset, tree, "Consumer Group ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- JOIN_CONSUMER_GROUP (604)
command_parsers[604] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Consumer Group identifier
    consumed = parse_identifier(buffer, offset, tree, "Consumer Group ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- LEAVE_CONSUMER_GROUP (605)
command_parsers[605] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Consumer Group identifier
    consumed = parse_identifier(buffer, offset, tree, "Consumer Group ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    return offset - start_offset
end

-- CREATE_PARTITIONS (402)
command_parsers[402] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Partitions count
    if buffer:len() < offset + 4 then return -1 end
    tree:add_le(iggy_proto, buffer(offset, 4), "Partitions Count: " .. buffer(offset, 4):le_uint())
    offset = offset + 4

    return offset - start_offset
end

-- DELETE_PARTITIONS (403)
command_parsers[403] = function(buffer, pinfo, tree, offset)
    local start_offset = offset

    -- Stream identifier
    local consumed = parse_identifier(buffer, offset, tree, "Stream ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Topic identifier
    consumed = parse_identifier(buffer, offset, tree, "Topic ID")
    if consumed == 0 then return -1 end
    offset = offset + consumed

    -- Partitions count
    if buffer:len() < offset + 4 then return -1 end
    tree:add_le(iggy_proto, buffer(offset, 4), "Partitions Count: " .. buffer(offset, 4):le_uint())
    offset = offset + 4

    return offset - start_offset
end

-- Parse request
local function parse_request(buffer, pinfo, tree)
    local offset = 0

    -- Length (4 bytes)
    local length = buffer(0, 4):le_uint()
    tree:add_le(f.length, buffer(0, 4))
    offset = 4

    -- Command (4 bytes)
    local command = buffer(4, 4):le_uint()
    local cmd_name = get_command_name(command)
    tree:add_le(f.command, buffer(4, 4)):append_text(" (" .. cmd_name .. ")")
    tree:add(f.command_name, cmd_name):set_generated()
    offset = 8

    -- Update info column
    pinfo.cols.info = "Request: " .. cmd_name

    -- Parse payload if parser exists
    if command_parsers[command] then
        local payload_tree = tree:add(iggy_proto, buffer(offset), "Payload")
        local consumed = command_parsers[command](buffer, pinfo, payload_tree, offset)
        if consumed == -1 then
            -- Need more data
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            pinfo.desegment_offset = 0
            return -1
        end
    else
        -- Unknown command, show raw payload
        local payload_len = length - 4
        if payload_len > 0 then
            tree:add(iggy_proto, buffer(offset, payload_len), "Payload (unparsed): " .. payload_len .. " bytes")
        end
    end

    return length + 4  -- Total message size
end

-- Parse response
local function parse_response(buffer, pinfo, tree)
    local offset = 0

    -- Status (4 bytes)
    local status = buffer(0, 4):le_uint()
    local status_text = status == 0 and "Success" or ("Error: " .. status)
    tree:add_le(f.status, buffer(0, 4)):append_text(" (" .. status_text .. ")")
    tree:add(f.status_text, status_text):set_generated()
    offset = 4

    -- Payload Length (4 bytes)
    local payload_length = buffer(4, 4):le_uint()
    tree:add_le(f.payload_length, buffer(4, 4))
    offset = 8

    -- Update info column
    pinfo.cols.info = "Response: " .. status_text

    -- Payload
    if payload_length > 0 and payload_length ~= 1 then
        tree:add(iggy_proto, buffer(offset, payload_length), "Payload: " .. payload_length .. " bytes")
        offset = offset + payload_length
    end

    return offset  -- Total message size
end

-- Main dissector function
function iggy_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = iggy_proto.name

    local subtree = tree:add(iggy_proto, buffer(), "IGGY Protocol")

    -- Need at least 8 bytes (minimum header)
    if length < 8 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short")
        return
    end

    -- Detect if this is a request or response
    -- Heuristic: Check if first 4 bytes looks like a reasonable length
    local first_u32 = buffer(0, 4):le_uint()
    local is_request = false

    -- If first_u32 is a reasonable message length (< 16MB), likely a request
    -- If first_u32 is 0 or very small, likely a status code (response)
    if first_u32 > 4 and first_u32 < 16777216 then
        -- Check if we have enough data
        local expected_total = first_u32 + 4
        if length < expected_total then
            -- Need more data
            pinfo.desegment_len = expected_total - length
            pinfo.desegment_offset = 0
            return
        end
        is_request = true
    end

    -- Parse based on message type
    local consumed = 0
    if is_request then
        subtree:append_text(" (Request)")
        consumed = parse_request(buffer, pinfo, subtree)
    else
        subtree:append_text(" (Response)")
        consumed = parse_response(buffer, pinfo, subtree)
    end

    if consumed == -1 then
        -- Need more data
        return
    end

    -- If we consumed all data, we're done
    return consumed
end

-- Register protocol on TCP port 8090 (default IGGY port)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8090, iggy_proto)

-- Also register on common alternative ports
tcp_port:add(8091, iggy_proto)
tcp_port:add(8092, iggy_proto)

-- Enable heuristic dissector
iggy_proto:register_heuristic("tcp", function(buffer, pinfo, tree)
    -- Heuristic: Check if packet looks like IGGY protocol
    if buffer:len() < 8 then return false end

    local first_u32 = buffer(0, 4):le_uint()

    -- Check for request pattern
    if first_u32 > 4 and first_u32 < 16777216 then
        local command = buffer(4, 4):le_uint()
        if command_names[command] ~= nil then
            iggy_proto.dissector(buffer, pinfo, tree)
            return true
        end
    end

    -- Check for response pattern (status code)
    if first_u32 < 1000 then  -- Status codes should be small
        local length = buffer(4, 4):le_uint()
        if length >= 0 and length < 16777216 then
            iggy_proto.dissector(buffer, pinfo, tree)
            return true
        end
    end

    return false
end)

-- Dissector loaded successfully
-- Registered on TCP ports: 8090, 8091, 8092
-- Heuristic dissector enabled
