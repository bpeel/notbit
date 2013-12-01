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

#ifndef NTB_NETWORK_H
#define NTB_NETWORK_H

#include <stdbool.h>

#include "ntb-error.h"

extern struct ntb_error_domain
ntb_network_error;

enum ntb_network_error {
        NTB_NETWORK_ERROR_SOCKET,
        NTB_NETWORK_ERROR_INVALID_ADDRESS
};

struct ntb_network;

struct ntb_network *
ntb_network_new(void);

bool
ntb_network_add_listen_address(struct ntb_network *nw,
                               const char *address,
                               int port,
                               struct ntb_error **error);

void
ntb_network_free(struct ntb_network *nw);

#endif /* NTB_NETWORK_H */
