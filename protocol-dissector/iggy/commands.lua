-- Command Registry module for Iggy Protocol Dissector

local commands = {}

-- Dependencies
local fields = require("iggy.fields")
local utils = require("iggy.utils")
local types = require("iggy.types")

----------------------------------------
-- Command Registry
-- Each command has: name, fields (ProtoFields), dissect_payload function
----------------------------------------
commands.registry = {
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
            offset = types.dissect_consumer(tvbuf, payload_tree, offset, pktlen, "Consumer", self.fields.consumer)
            if not offset then return end

            -- Stream ID (common data type)
            offset = types.dissect_identifier(tvbuf, payload_tree, offset, pktlen, "Stream ID", self.fields.stream_id)
            if not offset then return end

            -- Topic ID (common data type)
            offset = types.dissect_identifier(tvbuf, payload_tree, offset, pktlen, "Topic ID", self.fields.topic_id)
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

return commands
