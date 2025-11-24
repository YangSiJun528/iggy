/* packet-iggy.c
 * Routines for Iggy protocol dissection
 * Copyright 2024, Iggy Contributors
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/wmem_scopes.h>
#include <epan/expert.h>

#define IGGY_DEFAULT_PORT 8090
#define IGGY_MIN_LENGTH 8

void proto_register_iggy(void);
void proto_reg_handoff_iggy(void);

/* Protocol handle */
static int proto_iggy;
static dissector_handle_t iggy_handle;

/* Preferences */
static unsigned pref_server_port = IGGY_DEFAULT_PORT;

/* Protocol fields */
static int hf_iggy_message_type;
static int hf_iggy_request_length;
static int hf_iggy_request_command;
static int hf_iggy_request_command_name;
static int hf_iggy_response_status;
static int hf_iggy_response_status_name;
static int hf_iggy_response_length;
static int hf_iggy_request_frame;
static int hf_iggy_response_frame;

/* Ping command fields */
/* No additional fields needed for ping */

/* User Login command fields (38) */
static int hf_iggy_login_username_len;
static int hf_iggy_login_username;
static int hf_iggy_login_password_len;
static int hf_iggy_login_password;
static int hf_iggy_login_version_len;
static int hf_iggy_login_version;
static int hf_iggy_login_context_len;
static int hf_iggy_login_context;
static int hf_iggy_login_user_id;

/* Topic Create command fields (302) */
static int hf_iggy_create_topic_stream_id_kind;
static int hf_iggy_create_topic_stream_id_length;
static int hf_iggy_create_topic_stream_id_numeric;
static int hf_iggy_create_topic_stream_id_string;
static int hf_iggy_create_topic_topic_id;
static int hf_iggy_create_topic_partitions_count;
static int hf_iggy_create_topic_compression_algorithm;
static int hf_iggy_create_topic_message_expiry;
static int hf_iggy_create_topic_max_topic_size;
static int hf_iggy_create_topic_replication_factor;
static int hf_iggy_create_topic_name_len;
static int hf_iggy_create_topic_name;
static int hf_iggy_create_topic_resp_topic_id;
static int hf_iggy_create_topic_resp_created_at;
static int hf_iggy_create_topic_resp_partitions_count;
static int hf_iggy_create_topic_resp_message_expiry;
static int hf_iggy_create_topic_resp_compression_algorithm;
static int hf_iggy_create_topic_resp_max_topic_size;
static int hf_iggy_create_topic_resp_replication_factor;
static int hf_iggy_create_topic_resp_size;
static int hf_iggy_create_topic_resp_messages_count;
static int hf_iggy_create_topic_resp_name_len;
static int hf_iggy_create_topic_resp_name;

/* Subtree indices */
static int ett_iggy;
static int ett_iggy_payload;

/* Expert info */
static expert_field ei_iggy_unknown_command;
static expert_field ei_iggy_invalid_length;

/* Command codes */
#define IGGY_CMD_PING 1
#define IGGY_CMD_USER_LOGIN 38
#define IGGY_CMD_TOPIC_CREATE 302

/* Status codes */
typedef enum {
    IGGY_STATUS_OK = 0,
    IGGY_STATUS_ERROR = 1,
    IGGY_STATUS_INVALID_CONFIGURATION = 2,
    IGGY_STATUS_INVALID_COMMAND = 3,
    IGGY_STATUS_INVALID_FORMAT = 4,
    IGGY_STATUS_FEATURE_UNAVAILABLE = 5,
    IGGY_STATUS_INVALID_IDENTIFIER = 6,
    IGGY_STATUS_DISCONNECTED = 8,
    IGGY_STATUS_UNAUTHENTICATED = 40,
    IGGY_STATUS_UNAUTHORIZED = 41,
    IGGY_STATUS_INVALID_CREDENTIALS = 42
} iggy_status_code_t;

static const value_string iggy_status_vals[] = {
    { IGGY_STATUS_OK, "OK" },
    { IGGY_STATUS_ERROR, "Error" },
    { IGGY_STATUS_INVALID_CONFIGURATION, "Invalid Configuration" },
    { IGGY_STATUS_INVALID_COMMAND, "Invalid Command" },
    { IGGY_STATUS_INVALID_FORMAT, "Invalid Format" },
    { IGGY_STATUS_FEATURE_UNAVAILABLE, "Feature Unavailable" },
    { IGGY_STATUS_INVALID_IDENTIFIER, "Invalid Identifier" },
    { IGGY_STATUS_DISCONNECTED, "Disconnected" },
    { IGGY_STATUS_UNAUTHENTICATED, "Unauthenticated" },
    { IGGY_STATUS_UNAUTHORIZED, "Unauthorized" },
    { IGGY_STATUS_INVALID_CREDENTIALS, "Invalid Credentials" },
    { 0, NULL }
};

static const value_string iggy_stream_id_kind_vals[] = {
    { 1, "Numeric" },
    { 2, "String" },
    { 0, NULL }
};

/* Conversation data structure for request-response tracking */
typedef struct {
    uint32_t command_code;
    uint32_t request_frame;
} iggy_request_data_t;

typedef struct {
    wmem_list_t *pending_requests;  /* List of pending request frames */
    wmem_tree_t *matched_responses; /* Map response frame -> request data */
} iggy_conv_data_t;

/* Get or create conversation data */
static iggy_conv_data_t*
get_or_create_conv_data(packet_info *pinfo)
{
    conversation_t *conv;
    iggy_conv_data_t *conv_data;

    conv = find_or_create_conversation(pinfo);
    conv_data = (iggy_conv_data_t *)conversation_get_proto_data(conv, proto_iggy);

    if (!conv_data) {
        conv_data = wmem_new0(wmem_file_scope(), iggy_conv_data_t);
        conv_data->pending_requests = wmem_list_new(wmem_file_scope());
        conv_data->matched_responses = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conv, proto_iggy, conv_data);
    }

    return conv_data;
}

/* Record a request for later matching */
static void
record_request(packet_info *pinfo, uint32_t command_code)
{
    if (pinfo->fd->visited)
        return;

    iggy_conv_data_t *conv_data = get_or_create_conv_data(pinfo);
    iggy_request_data_t *req_data = wmem_new(wmem_file_scope(), iggy_request_data_t);
    req_data->command_code = command_code;
    req_data->request_frame = pinfo->num;

    wmem_list_append(conv_data->pending_requests, req_data);
}

/* Find matching request for a response */
static iggy_request_data_t*
find_matching_request(packet_info *pinfo)
{
    iggy_conv_data_t *conv_data = get_or_create_conv_data(pinfo);
    iggy_request_data_t *req_data;

    /* Check if already matched */
    req_data = (iggy_request_data_t *)wmem_tree_lookup32(conv_data->matched_responses, pinfo->num);
    if (req_data)
        return req_data;

    /* First pass - match with first pending request */
    if (!pinfo->fd->visited && wmem_list_count(conv_data->pending_requests) > 0) {
        req_data = (iggy_request_data_t *)wmem_list_remove_frame(
            conv_data->pending_requests,
            wmem_list_head(conv_data->pending_requests)
        );
        wmem_tree_insert32(conv_data->matched_responses, pinfo->num, req_data);
        return req_data;
    }

    return NULL;
}

/* Get command name from command code */
static const char*
get_command_name(uint32_t command_code)
{
    switch (command_code) {
        case IGGY_CMD_PING:
            return "ping";
        case IGGY_CMD_USER_LOGIN:
            return "user.login";
        case IGGY_CMD_TOPIC_CREATE:
            return "topic.create";
        default:
            return wmem_strdup_printf(wmem_packet_scope(), "Unimplemented (%u)", command_code);
    }
}

/* Dissect login request payload */
static void
dissect_login_request(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t username_len, password_len;
    uint32_t version_len, context_len;

    /* Username */
    username_len = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_iggy_login_username_len, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_iggy_login_username, tvb, *offset, username_len, ENC_UTF_8);
    *offset += username_len;

    /* Password */
    password_len = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_iggy_login_password_len, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_iggy_login_password, tvb, *offset, password_len, ENC_UTF_8);
    *offset += password_len;

    /* Version */
    version_len = tvb_get_letohl(tvb, *offset);
    proto_tree_add_item(tree, hf_iggy_login_version_len, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    if (version_len > 0) {
        proto_tree_add_item(tree, hf_iggy_login_version, tvb, *offset, version_len, ENC_UTF_8);
        *offset += version_len;
    }

    /* Context */
    context_len = tvb_get_letohl(tvb, *offset);
    proto_tree_add_item(tree, hf_iggy_login_context_len, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    if (context_len > 0) {
        proto_tree_add_item(tree, hf_iggy_login_context, tvb, *offset, context_len, ENC_UTF_8);
        *offset += context_len;
    }
}

/* Dissect login response payload */
static void
dissect_login_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_iggy_login_user_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
}

/* Dissect topic create request payload */
static void
dissect_topic_create_request(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t stream_id_kind, stream_id_length, name_len;
    proto_item *kind_item;

    /* Stream ID */
    stream_id_kind = tvb_get_uint8(tvb, *offset);
    kind_item = proto_tree_add_item(tree, hf_iggy_create_topic_stream_id_kind, tvb, *offset, 1, ENC_NA);
    proto_item_append_text(kind_item, " (%s)",
        val_to_str(stream_id_kind, iggy_stream_id_kind_vals, "Unknown: %d"));
    *offset += 1;

    stream_id_length = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_iggy_create_topic_stream_id_length, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    if (stream_id_kind == 1) {
        proto_tree_add_item(tree, hf_iggy_create_topic_stream_id_numeric, tvb, *offset, stream_id_length, ENC_LITTLE_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_iggy_create_topic_stream_id_string, tvb, *offset, stream_id_length, ENC_UTF_8);
    }
    *offset += stream_id_length;

    /* Topic parameters */
    proto_tree_add_item(tree, hf_iggy_create_topic_topic_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_iggy_create_topic_partitions_count, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_iggy_create_topic_compression_algorithm, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_iggy_create_topic_message_expiry, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_iggy_create_topic_max_topic_size, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_iggy_create_topic_replication_factor, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Topic name */
    name_len = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_iggy_create_topic_name_len, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_iggy_create_topic_name, tvb, *offset, name_len, ENC_UTF_8);
    *offset += name_len;
}

/* Dissect topic create response payload */
static void
dissect_topic_create_response(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint8_t name_len;

    proto_tree_add_item(tree, hf_iggy_create_topic_resp_topic_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_iggy_create_topic_resp_created_at, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_iggy_create_topic_resp_partitions_count, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_iggy_create_topic_resp_message_expiry, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_iggy_create_topic_resp_compression_algorithm, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_iggy_create_topic_resp_max_topic_size, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_iggy_create_topic_resp_replication_factor, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_iggy_create_topic_resp_size, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_iggy_create_topic_resp_messages_count, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;

    name_len = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_iggy_create_topic_resp_name_len, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_iggy_create_topic_resp_name, tvb, *offset, name_len, ENC_UTF_8);
    *offset += name_len;
}

/* Main dissector function */
static int
dissect_iggy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *type_item;
    proto_tree *iggy_tree, *payload_tree;
    unsigned offset = 0;
    bool is_request, is_response;
    uint32_t length, command_code, status_code;
    const char *command_name;
    uint32_t total_len;
    iggy_request_data_t *req_data;

    /* Check if this is Iggy traffic based on port */
    is_request = (pinfo->destport == pref_server_port);
    is_response = (pinfo->srcport == pref_server_port);

    if (!is_request && !is_response)
        return 0;

    /* Set protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IGGY");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Check minimum length */
    if (tvb_captured_length(tvb) < IGGY_MIN_LENGTH)
        return 0;

    /* Calculate total message length */
    if (is_request) {
        length = tvb_get_letohl(tvb, 0);
        total_len = 4 + length;
    } else {
        length = tvb_get_letohl(tvb, 4);
        total_len = 8 + length;
    }

    /* Create protocol tree */
    ti = proto_tree_add_item(tree, proto_iggy, tvb, 0, total_len, ENC_NA);
    iggy_tree = proto_item_add_subtree(ti, ett_iggy);

    if (is_request) {
        /* Request dissection */
        proto_item_set_text(ti, "Iggy Protocol - Request");
        type_item = proto_tree_add_string(iggy_tree, hf_iggy_message_type, tvb, 0, 0, "Request");
        proto_item_set_generated(type_item);

        proto_tree_add_item_ret_uint(iggy_tree, hf_iggy_request_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
        offset += 4;
        proto_tree_add_item_ret_uint(iggy_tree, hf_iggy_request_command, tvb, offset, 4, ENC_LITTLE_ENDIAN, &command_code);
        offset += 4;

        command_name = get_command_name(command_code);
        type_item = proto_tree_add_string(iggy_tree, hf_iggy_request_command_name, tvb, 0, 0, command_name);
        proto_item_set_generated(type_item);

        /* Dissect payload based on command */
        uint32_t payload_len = length - 4; /* length includes command code */
        if (payload_len > 0) {
            payload_tree = proto_tree_add_subtree(iggy_tree, tvb, offset, payload_len,
                ett_iggy_payload, NULL, "Payload");

            switch (command_code) {
                case IGGY_CMD_PING:
                    /* No payload */
                    break;
                case IGGY_CMD_USER_LOGIN:
                    dissect_login_request(tvb, payload_tree, &offset);
                    break;
                case IGGY_CMD_TOPIC_CREATE:
                    dissect_topic_create_request(tvb, payload_tree, &offset);
                    break;
                default:
                    /* Unknown command */
                    expert_add_info_format(pinfo, ti, &ei_iggy_unknown_command,
                        "Unknown command code: %u", command_code);
                    break;
            }
        }

        /* Record request for response matching */
        record_request(pinfo, command_code);

        col_add_fstr(pinfo->cinfo, COL_INFO, "Request: %s (code=%u, length=%u)",
            command_name, command_code, length);

    } else {
        /* Response dissection */
        proto_item_set_text(ti, "Iggy Protocol - Response");
        type_item = proto_tree_add_string(iggy_tree, hf_iggy_message_type, tvb, 0, 0, "Response");
        proto_item_set_generated(type_item);

        proto_tree_add_item_ret_uint(iggy_tree, hf_iggy_response_status, tvb, offset, 4, ENC_LITTLE_ENDIAN, &status_code);
        offset += 4;
        proto_tree_add_item_ret_uint(iggy_tree, hf_iggy_response_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
        offset += 4;

        const char *status_name = val_to_str(status_code, iggy_status_vals, "Unknown (%u)");
        type_item = proto_tree_add_string(iggy_tree, hf_iggy_response_status_name, tvb, 0, 0, status_name);
        proto_item_set_generated(type_item);

        /* Find matching request */
        req_data = find_matching_request(pinfo);
        if (req_data) {
            type_item = proto_tree_add_uint(iggy_tree, hf_iggy_request_frame, tvb, 0, 0, req_data->request_frame);
            proto_item_set_generated(type_item);

            command_code = req_data->command_code;
            command_name = get_command_name(command_code);
        } else {
            command_code = 0;
            command_name = "No matching request";
        }

        type_item = proto_tree_add_string(iggy_tree, hf_iggy_request_command_name, tvb, 0, 0, command_name);
        proto_item_set_generated(type_item);

        /* Dissect payload if status is OK */
        if (length > 0 && status_code == IGGY_STATUS_OK && req_data) {
            payload_tree = proto_tree_add_subtree(iggy_tree, tvb, offset, length,
                ett_iggy_payload, NULL, "Payload");

            switch (command_code) {
                case IGGY_CMD_PING:
                    /* No payload */
                    break;
                case IGGY_CMD_USER_LOGIN:
                    dissect_login_response(tvb, payload_tree, &offset);
                    break;
                case IGGY_CMD_TOPIC_CREATE:
                    dissect_topic_create_response(tvb, payload_tree, &offset);
                    break;
                default:
                    /* Unknown command */
                    break;
            }
        }

        if (status_code == IGGY_STATUS_OK) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Response: %s OK (length=%u)",
                command_name, length);
        } else {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Response: %s %s (status=%u, length=%u)",
                command_name, status_name, status_code, length);
        }
    }

    return total_len;
}

/* Calculate PDU length for TCP reassembly */
static unsigned
get_iggy_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_)
{
    bool is_request = (pinfo->destport == pref_server_port);

    if (is_request) {
        uint32_t length = tvb_get_letohl(tvb, offset);
        return 4 + length;
    } else {
        uint32_t length = tvb_get_letohl(tvb, offset + 4);
        return 8 + length;
    }
}

/* TCP dissector entry point with reassembly */
static int
dissect_iggy_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, IGGY_MIN_LENGTH,
        get_iggy_pdu_len, dissect_iggy, data);
    return tvb_captured_length(tvb);
}

/* Register protocol */
void
proto_register_iggy(void)
{
    static hf_register_info hf[] = {
        /* Common fields */
        { &hf_iggy_message_type,
            { "Message Type", "iggy.message_type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_request_length,
            { "Length", "iggy.request.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Length of command code + payload", HFILL }
        },
        { &hf_iggy_request_command,
            { "Command Code", "iggy.request.command",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_request_command_name,
            { "Command Name", "iggy.request.command_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_response_status,
            { "Status Code", "iggy.response.status",
            FT_UINT32, BASE_DEC, VALS(iggy_status_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_response_status_name,
            { "Status Name", "iggy.response.status_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_response_length,
            { "Length", "iggy.response.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Length of payload", HFILL }
        },
        { &hf_iggy_request_frame,
            { "Request Frame", "iggy.request_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_response_frame,
            { "Response Frame", "iggy.response_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            NULL, HFILL }
        },

        /* User Login fields */
        { &hf_iggy_login_username_len,
            { "Username Length", "iggy.login.username_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_login_username,
            { "Username", "iggy.login.username",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_login_password_len,
            { "Password Length", "iggy.login.password_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_login_password,
            { "Password", "iggy.login.password",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_login_version_len,
            { "Version Length", "iggy.login.version_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_login_version,
            { "Version", "iggy.login.version",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_login_context_len,
            { "Context Length", "iggy.login.context_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_login_context,
            { "Context", "iggy.login.context",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_login_user_id,
            { "User ID", "iggy.login.user_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        /* Topic Create fields */
        { &hf_iggy_create_topic_stream_id_kind,
            { "Stream ID Kind", "iggy.create_topic.stream_id_kind",
            FT_UINT8, BASE_DEC, VALS(iggy_stream_id_kind_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_stream_id_length,
            { "Stream ID Length", "iggy.create_topic.stream_id_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_stream_id_numeric,
            { "Stream ID (Numeric)", "iggy.create_topic.stream_id_numeric",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_stream_id_string,
            { "Stream ID (String)", "iggy.create_topic.stream_id_string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_topic_id,
            { "Topic ID", "iggy.create_topic.topic_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_partitions_count,
            { "Partitions Count", "iggy.create_topic.partitions_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_compression_algorithm,
            { "Compression Algorithm", "iggy.create_topic.compression_algorithm",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_message_expiry,
            { "Message Expiry (μs)", "iggy.create_topic.message_expiry",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_max_topic_size,
            { "Max Topic Size (bytes)", "iggy.create_topic.max_topic_size",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_replication_factor,
            { "Replication Factor", "iggy.create_topic.replication_factor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_name_len,
            { "Name Length", "iggy.create_topic.name_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_name,
            { "Name", "iggy.create_topic.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_resp_topic_id,
            { "Topic ID", "iggy.create_topic.resp.topic_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_resp_created_at,
            { "Created At (μs)", "iggy.create_topic.resp.created_at",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_resp_partitions_count,
            { "Partitions Count", "iggy.create_topic.resp.partitions_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_resp_message_expiry,
            { "Message Expiry (μs)", "iggy.create_topic.resp.message_expiry",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_resp_compression_algorithm,
            { "Compression Algorithm", "iggy.create_topic.resp.compression_algorithm",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_resp_max_topic_size,
            { "Max Topic Size (bytes)", "iggy.create_topic.resp.max_topic_size",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_resp_replication_factor,
            { "Replication Factor", "iggy.create_topic.resp.replication_factor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_resp_size,
            { "Size (bytes)", "iggy.create_topic.resp.size",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_resp_messages_count,
            { "Messages Count", "iggy.create_topic.resp.messages_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_resp_name_len,
            { "Name Length", "iggy.create_topic.resp.name_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_iggy_create_topic_resp_name,
            { "Name", "iggy.create_topic.resp.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_iggy,
        &ett_iggy_payload
    };

    static ei_register_info ei[] = {
        { &ei_iggy_unknown_command,
            { "iggy.unknown_command", PI_UNDECODED, PI_WARN,
            "Unknown command code", EXPFILL }
        },
        { &ei_iggy_invalid_length,
            { "iggy.invalid_length", PI_MALFORMED, PI_ERROR,
            "Invalid message length", EXPFILL }
        }
    };

    module_t *iggy_module;
    expert_module_t *expert_iggy;

    /* Register protocol */
    proto_iggy = proto_register_protocol(
        "Iggy Protocol",    /* name */
        "IGGY",             /* short name */
        "iggy"              /* filter name */
    );

    /* Register fields and subtrees */
    proto_register_field_array(proto_iggy, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register expert info */
    expert_iggy = expert_register_protocol(proto_iggy);
    expert_register_field_array(expert_iggy, ei, array_length(ei));

    /* Register preferences */
    iggy_module = prefs_register_protocol(proto_iggy, proto_reg_handoff_iggy);
    prefs_register_uint_preference(iggy_module, "server_port",
        "Server Port",
        "TCP port for Iggy server",
        10, &pref_server_port);

    /* Register dissector */
    iggy_handle = register_dissector("iggy", dissect_iggy_tcp, proto_iggy);
}

/* Handoff registration */
void
proto_reg_handoff_iggy(void)
{
    static bool initialized = false;
    static unsigned current_port = 0;

    if (!initialized) {
        dissector_add_for_decode_as_with_preference("tcp.port", iggy_handle);
        initialized = true;
    }

    /* Update port registration if changed */
    if (current_port != pref_server_port) {
        if (current_port != 0) {
            dissector_delete_uint("tcp.port", current_port, iggy_handle);
        }
        dissector_add_uint("tcp.port", pref_server_port, iggy_handle);
        current_port = pref_server_port;
    }
}
