-- Protocol Fields module for Iggy Protocol Dissector

local fields = {}

----------------------------------------
-- Common Protocol fields (used across all messages)
----------------------------------------
-- Base message fields
fields.pf_message_type   = ProtoField.string("iggy.message_type", "Message Type")
fields.pf_req_length     = ProtoField.uint32("iggy.request.length", "Length", base.DEC)
fields.pf_req_code       = ProtoField.uint32("iggy.request.code", "Command Code", base.DEC)
fields.pf_req_code_name  = ProtoField.string("iggy.request.code_name", "Command Name")
fields.pf_req_payload    = ProtoField.bytes("iggy.request.payload", "Payload")

fields.pf_resp_status      = ProtoField.uint32("iggy.response.status", "Status", base.DEC)
fields.pf_resp_status_name = ProtoField.string("iggy.response.status_name", "Status Name")
fields.pf_resp_length      = ProtoField.uint32("iggy.response.length", "Length", base.DEC)
fields.pf_resp_payload     = ProtoField.bytes("iggy.response.payload", "Payload")

-- Common data type: Identifier
fields.pf_id_kind      = ProtoField.uint8("iggy.identifier.kind", "Kind", base.DEC)
fields.pf_id_length    = ProtoField.uint8("iggy.identifier.length", "Length", base.DEC)
fields.pf_id_value_num = ProtoField.uint32("iggy.identifier.value_num", "Value (Numeric)", base.DEC)
fields.pf_id_value_str = ProtoField.string("iggy.identifier.value_str", "Value (String)")

-- Common data type: Consumer
fields.pf_consumer_kind = ProtoField.uint8("iggy.consumer.kind", "Kind", base.DEC)

-- Command 38: LoginUser (Request)
fields.pf_login_username_len = ProtoField.uint8("iggy.login.username_len", "Username Length", base.DEC)
fields.pf_login_username     = ProtoField.string("iggy.login.username", "Username")
fields.pf_login_password_len = ProtoField.uint8("iggy.login.password_len", "Password Length", base.DEC)
fields.pf_login_password     = ProtoField.string("iggy.login.password", "Password")
fields.pf_login_version_len  = ProtoField.uint32("iggy.login.version_len", "Version Length", base.DEC)
fields.pf_login_version      = ProtoField.string("iggy.login.version", "Version")
fields.pf_login_context_len  = ProtoField.uint32("iggy.login.context_len", "Context Length", base.DEC)
fields.pf_login_context      = ProtoField.string("iggy.login.context", "Context")

-- Command 38: LoginUser (Response)
fields.pf_login_user_id = ProtoField.uint32("iggy.login.user_id", "User ID", base.DEC)

----------------------------------------
-- Field structure helpers (for command declarations)
----------------------------------------
-- These functions return field structure tables that commands can use
-- to declare their payload structure in a self-documenting way

function fields.make_identifier_fields()
    return {
        kind = fields.pf_id_kind,
        length = fields.pf_id_length,
        value_num = fields.pf_id_value_num,
        value_str = fields.pf_id_value_str,
    }
end

function fields.make_consumer_fields()
    return {
        kind = fields.pf_consumer_kind,
        id_fields = fields.make_identifier_fields(),
    }
end

----------------------------------------
-- Get all fields as array (for Proto.fields registration)
----------------------------------------
function fields.get_all()
    return {
        -- Base message fields
        fields.pf_message_type,
        fields.pf_req_length, fields.pf_req_code, fields.pf_req_code_name, fields.pf_req_payload,
        fields.pf_resp_status, fields.pf_resp_status_name, fields.pf_resp_length, fields.pf_resp_payload,

        -- Common data type fields
        fields.pf_id_kind, fields.pf_id_length, fields.pf_id_value_num, fields.pf_id_value_str,
        fields.pf_consumer_kind,

        -- Command-specific fields: LoginUser (38)
        fields.pf_login_username_len, fields.pf_login_username,
        fields.pf_login_password_len, fields.pf_login_password,
        fields.pf_login_version_len, fields.pf_login_version,
        fields.pf_login_context_len, fields.pf_login_context,
        fields.pf_login_user_id,
    }
end

return fields
