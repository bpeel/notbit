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
#include "ntb-signal.h"
#include "ntb-blob.h"

extern struct ntb_error_domain
ntb_network_error;

enum ntb_network_error {
        NTB_NETWORK_ERROR_INVALID_ADDRESS
};

enum ntb_network_add_object_flags {
        NTB_NETWORK_SKIP_VALIDATION = (1 << 0),
        NTB_NETWORK_DELAY = (1 << 1)
};

enum ntb_network_object_location {
        NTB_NETWORK_OBJECT_LOCATION_NOWHERE,
        NTB_NETWORK_OBJECT_LOCATION_STORE,
        NTB_NETWORK_OBJECT_LOCATION_MEMORY
};

struct ntb_network;

struct ntb_network *
ntb_network_new(void);

void
ntb_network_add_object_from_data(struct ntb_network *nw,
                                 enum ntb_proto_inv_type type,
                                 const uint8_t *object_data,
                                 size_t object_data_length,
                                 enum ntb_network_add_object_flags flags,
                                 const char *source_note);

void
ntb_network_add_blob(struct ntb_network *nw,
                     struct ntb_blob *blob,
                     enum ntb_network_add_object_flags flags,
                     const char *source_note);

void
ntb_network_load_store(struct ntb_network *nw);

bool
ntb_network_add_listen_address(struct ntb_network *nw,
                               const char *address,
                               struct ntb_error **error);

bool
ntb_network_add_peer_address(struct ntb_network *nw,
                             const char *address,
                             struct ntb_error **error);

struct ntb_signal *
ntb_network_get_new_object_signal(struct ntb_network *nw);

void
ntb_network_set_only_use_explicit_addresses(struct ntb_network *nw,
                                            bool value);

enum ntb_network_object_location
ntb_network_get_object(struct ntb_network *nw,
                       const uint8_t *hash,
                       struct ntb_blob **blob);

void
ntb_network_free(struct ntb_network *nw);

#endif /* NTB_NETWORK_H */
