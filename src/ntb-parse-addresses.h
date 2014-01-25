/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2014  Neil Roberts
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

#ifndef NTB_PARSE_ADDRESSES_H
#define NTB_PARSE_ADDRESSES_H

#include <stdbool.h>
#include <stdint.h>

#include "ntb-error.h"
#include "ntb-buffer.h"
#include "ntb-address.h"

extern struct ntb_error_domain
ntb_parse_addresses_error;

enum ntb_parse_addresses_error {
        NTB_PARSE_ADDRESSES_ERROR_INVALID
};

typedef bool
(* ntb_parse_addresses_cb)(const struct ntb_address *address,
                           void *user_data,
                           struct ntb_error **error);

bool
ntb_parse_addresses(struct ntb_buffer *buffer,
                    ntb_parse_addresses_cb cb,
                    void *user_data,
                    struct ntb_error **error);

#endif /* NTB_PARSE_ADDRESSES_H */
