/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013  Neil Roberts
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting documentation, and
 * that the name of the copyright holders not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  The copyright holders make no representations
 * about the suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
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
        BIGNUM* val;
        BN_ULONG part;
        char *p = output;

        val = BN_new();

        if (BN_bin2bn(input, length, val) == NULL)
                ntb_fatal("A big number operation failed");

        while (!BN_is_zero(val)) {
                part = BN_div_word(val, 58);
                assert(part >= 0 && part < 58);
                *(p++) = alphabet[part];
        }

        BN_free(val);

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
        BIGNUM* val;
        int bn_result;
        int digit_value;
        int n_bytes;
        size_t i;

        val = BN_new();

        for (i = 0; i < input_length; i++) {
                digit_value = get_digit_value(input[i]);
                if (digit_value == -1)
                        return -1;

                bn_result = BN_mul_word(val, 58);
                assert(bn_result);

                bn_result = BN_add_word(val, digit_value);
                assert(bn_result);
        }

        n_bytes = BN_num_bytes(val);

        if (n_bytes > output_length)
                return -1;

        BN_bn2bin(val, output);

        BN_free(val);

        return n_bytes;
}
