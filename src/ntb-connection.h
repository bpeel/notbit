/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013  Neil Roberts
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NTB_CONNECTION_H
#define NTB_CONNECTION_H

#include <stdint.h>
#include <stdbool.h>

#include "ntb-error.h"
#include "ntb-netaddress.h"
#include "ntb-buffer.h"
#include "ntb-main-context.h"
#include "ntb-signal.h"

extern struct ntb_error_domain
ntb_connection_error;

enum ntb_connection_error {
        NTB_CONNECTION_ERROR_SOCKET,
        NTB_CONNECTION_ERROR_CONNECT,
        NTB_CONNECTION_ERROR_ACCEPT
};

struct ntb_connection {
        struct ntb_netaddress remote_address;
        char *remote_address_string;
        struct ntb_main_context_source *source;
        int sock;

        struct ntb_buffer in_buf;
        struct ntb_buffer out_buf;

        struct ntb_signal error_signal;
};

struct ntb_connection *
ntb_connection_connect(const struct ntb_netaddress *address,
                       struct ntb_error **error);

struct ntb_connection *
ntb_connection_accept(int server_sock,
                      struct ntb_error **error);

void
ntb_connection_free(struct ntb_connection *conn);

#endif /* NTB_CONNECTION_H */
