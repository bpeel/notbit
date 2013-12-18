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

#include <openssl/bn.h>
#include <assert.h>

#include "ntb-base58.h"

static const char
alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static void
reverse_bytes(char *data,
              size_t length)
{
        char tmp;
        size_t i;

        for (i = 0; i < length / 2; i++) {
                tmp = data[i];
                data[i] = data[length - 1 - i];
                data[length - 1 - i] = tmp;
        }
}

size_t
ntb_base58_encode(const uint8_t *input,
                  size_t length,
                  char *output)
{
        BIGNUM val;
        BN_ULONG part;
        char *p = output;

        BN_init(&val);

        if (BN_bin2bn(input, length, &val) == NULL)
                ntb_fatal("A big number operation failed");

        while (!BN_is_zero(&val)) {
                part = BN_div_word(&val, 58);
                assert(part >= 0 && part < 58);
                *(p++) = alphabet[part];
        }

        /* Make it big-endian */
        reverse_bytes(output, p - output);

        return p - output;
}
