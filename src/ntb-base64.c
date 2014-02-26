/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2014  Neil Roberts
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "ntb-base64.h"
#include "ntb-error.h"

struct ntb_error_domain
ntb_base64_error;

static int
alphabet_value(int ch)
{
        if (ch == '/') {
                return 63;
        } else if (ch == '+') {
                return 62;
        } else if (ch <= '9') {
                if (ch < '0')
                        return -1;
                return ch - '0' + 26 * 2;
        } else if (ch <= 'Z') {
                if (ch < 'A')
                        return -1;
                return ch - 'A';
        } else if (ch <= 'z') {
                if (ch < 'a')
                        return -1;
                return ch - 'a' + 26;
        } else {
                return -1;
        }
}

void
ntb_base64_decode_start(struct ntb_base64_data *data)
{
        memset(data, 0, sizeof *data);
}

static ssize_t
padding_error(struct ntb_error **error)
{
        ntb_set_error(error,
                      &ntb_base64_error,
                      NTB_BASE64_ERROR_INVALID_PADDING,
                      "The padding in the base64-encoded data is invalid");
        return -1;
}

static bool
handle_padding(struct ntb_base64_data *data,
               const uint8_t *in_buffer,
               size_t length,
               struct ntb_error **error)
{
        const uint8_t *in;

        for (in = in_buffer; in - in_buffer < length; in++) {
                if (*in == '=') {
                        if (++data->n_padding > 2) {
                                padding_error(error);
                                return false;
                        }
                } else if (alphabet_value(*in) != -1) {
                        padding_error(error);
                        return false;
                }
        }

        return true;
}

ssize_t
ntb_base64_decode(struct ntb_base64_data *data,
                  const uint8_t *in_buffer,
                  size_t length,
                  uint8_t *out_buffer,
                  struct ntb_error **error)
{
        uint8_t *out = out_buffer;
        const uint8_t *in;
        int ch_value;

        if (data->n_padding > 0)
                return handle_padding(data, in_buffer, length, error) ? 0 : -1;

        for (in = in_buffer; in - in_buffer < length; in++) {
                ch_value = alphabet_value(*in);

                if (ch_value >= 0) {
                        data->value = (data->value << 6) | ch_value;

                        if (++data->n_chars >= 4) {
                                *(out++) = data->value >> 16;
                                *(out++) = data->value >> 8;
                                *(out++) = data->value;
                                data->n_chars = 0;
                        }
                } else if (*in == '=') {
                        if (!handle_padding(data,
                                            in,
                                            in_buffer + length - in,
                                            error))
                                return -1;

                        break;
                }
        }

        return out - out_buffer;
}

ssize_t
ntb_base64_decode_end(struct ntb_base64_data *data,
                      uint8_t *buffer,
                      struct ntb_error **error)
{
        switch (data->n_padding) {
        case 0:
                if (data->n_chars != 0)
                        return padding_error(error);
                return 0;
        case 1:
                if (data->n_chars != 3 ||
                    (data->value & 3) != 0)
                        return padding_error(error);
                *(buffer++) = data->value >> 10;
                *(buffer++) = data->value >> 2;
                return 2;
        case 2:
                if (data->n_chars != 2 ||
                    (data->value & 15) != 0)
                        return padding_error(error);
                *(buffer++) = data->value >> 4;
                return 1;
        }

        assert(false);

        return 0;
}

static int
to_alphabet_value(int value)
{
        if (value < 26)
                return value + 'A';
        else if (value < 52)
                return value - 26 + 'a';
        else if (value < 62)
                return value - 52 + '0';
        else if (value == 62)
                return '+';
        else
                return '/';
}

size_t
ntb_base64_encode(const uint8_t *data_in,
                  size_t data_in_length,
                  char *data_out)
{
        char *out = data_out;
        int value;

        while (data_in_length >= 3) {
                value = data_in[0] << 16 | data_in[1] << 8 | data_in[2];

                *(out++) = to_alphabet_value(value >> 18);
                *(out++) = to_alphabet_value((value >> 12) & 63);
                *(out++) = to_alphabet_value((value >> 6) & 63);
                *(out++) = to_alphabet_value(value & 63);

                data_in += 3;
                data_in_length -= 3;
        }

        switch (data_in_length) {
        case 0:
                break;

        case 1:
                value = data_in[0] << 16;
                *(out++) = to_alphabet_value(value >> 18);
                *(out++) = to_alphabet_value((value >> 12) & 63);
                *(out++) = '=';
                *(out++) = '=';
                break;

        case 2:
                value = (data_in[0] << 16) | (data_in[1] << 8);
                *(out++) = to_alphabet_value(value >> 18);
                *(out++) = to_alphabet_value((value >> 12) & 63);
                *(out++) = to_alphabet_value((value >> 6) & 63);
                *(out++) = '=';
                break;
        }

        return out - data_out;
}
