/* plugin.c
 * Iggy protocol plugin registration
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <wireshark.h>

#define PLUGIN_VERSION "0.1.0"

/* Protocol registration functions */
extern void proto_register_iggy(void);
extern void proto_reg_handoff_iggy(void);

/* Plugin registration function */
WIRESHARK_PLUGIN_REGISTER_EPAN_INFO() {
    static const struct plugin_info info = {
        .name = "Iggy Protocol",
        .version = PLUGIN_VERSION,
        .description = "Dissector for Iggy messaging protocol",
        .author = "Iggy Contributors"
    };
    return &info;
}

/* Register protocol handlers */
WIRESHARK_PLUGIN_REGISTER_PROTO_FILES() {
    static const proto_plugin plugin = {
        .register_protoinfo = proto_register_iggy,
        .register_handoff = proto_reg_handoff_iggy
    };
    return &plugin;
}
