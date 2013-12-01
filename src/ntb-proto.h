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

#ifndef NTB_PROTO_H
#define NTB_PROTO_H

#include <stdint.h>
#include <stdbool.h>

#include "ntb-error.h"

extern struct ntb_error_domain
ntb_proto_error;

enum ntb_proto_error {
        NTB_PROTO_ERROR_PROTOCOL
};

void
ntb_proto_double_hash(const void *data,
                      int length,
                      uint8_t *hash);

void
ntb_proto_address_hash(const void *data,
                       int length,
                       uint8_t *hash);

uint16_t
ntb_proto_get_16(const uint8_t *p);

uint32_t
ntb_proto_get_32(const uint8_t *p);

uint64_t
ntb_proto_get_64(const uint8_t *p);

bool
ntb_proto_get_var_int(const uint8_t **p_ptr,
                      int *length_ptr,
                      uint64_t *result,
                      struct ntb_error **error);

#endif /* NTB_PROTO_H */
