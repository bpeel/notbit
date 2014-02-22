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

#ifndef NTB_KEYRING_H
#define NTB_KEYRING_H

#include <stdbool.h>
#include <stdint.h>

#include "ntb-network.h"
#include "ntb-key.h"
#include "ntb-address.h"
#include "ntb-error.h"

struct ntb_keyring;

struct ntb_keyring_cookie;

extern struct ntb_error_domain
ntb_keyring_error;

enum ntb_keyring_error {
        NTB_KEYRING_ERROR_UNKNOWN_FROM_ADDRESS
};

typedef void
(* ntb_keyring_create_key_func)(struct ntb_key *key,
                                void *user_data);

struct ntb_keyring *
ntb_keyring_new(struct ntb_network *nw);

void
ntb_keyring_start(struct ntb_keyring *keyring);

void
ntb_keyring_load_store(struct ntb_keyring *keyring);

bool
ntb_keyring_send_message(struct ntb_keyring *keyring,
                         const struct ntb_address *from_address,
                         const struct ntb_address *to_addresses,
                         int n_to_addresses,
                         int content_encoding,
                         struct ntb_blob *content,
                         struct ntb_error **error);

struct ntb_keyring_cookie *
ntb_keyring_create_key(struct ntb_keyring *keyring,
                       const struct ntb_key_params *params,
                       int leading_zeroes,
                       ntb_keyring_create_key_func func,
                       void *user_data);

void
ntb_keyring_cancel_task(struct ntb_keyring_cookie *cookie);

void
ntb_keyring_free(struct ntb_keyring *crypto);

#endif /* NTB_KEYRING_H */
