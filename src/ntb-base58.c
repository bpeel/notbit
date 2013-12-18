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

        BN_free(&val);

        /* Make it big-endian */
        reverse_bytes(output, p - output);

        return p - output;
}

static int
get_digit_value(char digit)
{
        int min, max, mid;

        min = 0;
        max = sizeof alphabet - 1;

        while (max > min) {
                mid = (min + max) / 2;

                if (alphabet[mid] < digit)
                        min = mid + 1;
                else
                        max = mid;
        }

        if (alphabet[min] == digit)
                return min;

        return -1;
}

ssize_t
ntb_base58_decode(const char *input,
                  size_t input_length,
                  uint8_t *output,
                  size_t output_length)
{
        BIGNUM val;
        int bn_result;
        int digit_value;
        int n_bytes;
        size_t i;

        BN_init(&val);

        for (i = 0; i < input_length; i++) {
                digit_value = get_digit_value(input[i]);
                if (digit_value == -1)
                        return -1;

                bn_result = BN_mul_word(&val, 58);
                assert(bn_result);

                bn_result = BN_add_word(&val, digit_value);
                assert(bn_result);
        }

        n_bytes = BN_num_bytes(&val);

        if (n_bytes > output_length)
                return -1;

        BN_bn2bin(&val, output);

        BN_free(&val);

        return n_bytes;
}
