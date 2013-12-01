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

#include "config.h"

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <stdint.h>
#include <string.h>

#include "ntb-proto.h"
#include "ntb-util.h"

struct ntb_error_domain
ntb_proto_error;

void
ntb_proto_double_hash(const void *data,
                      int length,
                      uint8_t *hash)
{
        uint8_t hash1[SHA512_DIGEST_LENGTH];

        SHA512(data, length, hash1);
        SHA512(hash1, SHA512_DIGEST_LENGTH, hash);
}

void
ntb_proto_address_hash(const void *data,
                       int length,
                       uint8_t *hash)
{
        uint8_t hash1[SHA512_DIGEST_LENGTH];

        SHA512(data, length, hash1);
        RIPEMD160(hash1, SHA512_DIGEST_LENGTH, hash);
}

uint16_t
ntb_proto_get_16(const uint8_t *p)
{
        uint16_t value;

        memcpy(&value, p, sizeof value);

        return NTB_UINT16_FROM_LE(value);
}

uint32_t
ntb_proto_get_32(const uint8_t *p)
{
        uint32_t value;

        memcpy(&value, p, sizeof value);

        return NTB_UINT32_FROM_LE(value);
}

uint64_t
ntb_proto_get_64(const uint8_t *p)
{
        uint64_t value;

        memcpy(&value, p, sizeof value);

        return NTB_UINT64_FROM_LE(value);
}

bool
ntb_proto_get_var_int(const uint8_t **p_ptr,
                      int *length_ptr,
                      uint64_t *result,
                      struct ntb_error **error)
{
        const uint8_t *p = *p_ptr;
        int length = *length_ptr;

        if (length < 0) {
                goto error;
        } else if (*p < 0xfd) {
                if (length < 2)
                        goto error;
                *result = p[0];
                *length_ptr -= 1;
                *p_ptr += 1;
                return true;
        } else if (*p == 0xfd) {
                if (length < 3)
                        goto error;
                *result = ntb_proto_get_16(p + 1);
                *length_ptr -= 3;
                *p_ptr += 3;
                return true;
        } else if (*p == 0xfe) {
                if (length < 5)
                        goto error;
                *result = ntb_proto_get_32(p + 1);
                *length_ptr -= 5;
                *p_ptr += 5;
                return true;
        } else {
                if (length < 9)
                        goto error;
                *result = ntb_proto_get_64(p + 1);
                *length_ptr -= 9;
                *p_ptr += 9;
                return true;
        }

error:
        ntb_set_error(error,
                      &ntb_proto_error,
                      NTB_PROTO_ERROR_PROTOCOL,
                      "Not enough space for a var int in a message");

        return false;
}
