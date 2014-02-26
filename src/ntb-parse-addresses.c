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

#include <string.h>
#include <openssl/ripemd.h>
#include <assert.h>

#include "ntb-parse-addresses.h"
#include "ntb-address.h"

struct ntb_error_domain
ntb_parse_addresses_error;

struct ntb_parse_addresses_data {
        struct ntb_buffer *buffer;
        bool had_address;
        ntb_parse_addresses_cb cb;
        void *cb_user_data;
};

static void
reset_data(struct ntb_parse_addresses_data *data)
{
        data->buffer->length = 0;
        data->had_address = false;
}

static bool
process_address(struct ntb_parse_addresses_data *data,
                struct ntb_error **error)
{
        uint8_t *end;
        struct ntb_address address;

        end = memchr(data->buffer->data, '@', data->buffer->length);

        if (end == NULL) {
                ntb_set_error(error,
                              &ntb_parse_addresses_error,
                              NTB_PARSE_ADDRESSES_ERROR_INVALID,
                              "Email address is missing the ‘@’ symbol");
                return false;
        }

        if (data->buffer->data + data->buffer->length - end - 1 != 10 ||
            memcmp(end + 1, "bitmessage", 10)) {
                ntb_set_error(error,
                              &ntb_parse_addresses_error,
                              NTB_PARSE_ADDRESSES_ERROR_INVALID,
                              "The email addresses must be of the form "
                              "<address>@bitmessage");
                return false;
        }

        *end = '\0';

        if (!ntb_address_decode(&address,
                                (const char *) data->buffer->data)) {
                ntb_set_error(error,
                              &ntb_parse_addresses_error,
                              NTB_PARSE_ADDRESSES_ERROR_INVALID,
                              "The Bitmessage address in the email address "
                              "is invalid");
                return false;
        }

        return data->cb(&address, data->cb_user_data, error);
}

static bool
end_address(struct ntb_parse_addresses_data *data,
            struct ntb_error **error)
{
        if (!data->had_address &&
            !process_address(data, error))
                return false;

        reset_data(data);

        return true;
}

static ssize_t
parse_quotes(struct ntb_parse_addresses_data *data,
             const uint8_t *quotes_start,
             size_t in_length,
             struct ntb_error **error)
{
        const uint8_t *in = quotes_start;

        assert(*in == '"');

        in++;
        in_length--;

        while (in_length > 0) {
                switch (*in) {
                case '"':
                        return in + 1 - quotes_start;

                case '\\':
                        if (in_length < 2) {
                                ntb_set_error(error,
                                              &ntb_parse_addresses_error,
                                              NTB_PARSE_ADDRESSES_ERROR_INVALID,
                                              "\\ character at end of address");
                                return -1;
                        }

                        ntb_buffer_append_c(data->buffer, in[1]);

                        in += 2;
                        in_length -= 2;
                        break;

                default:
                        ntb_buffer_append_c(data->buffer, *in);
                        in += 1;
                        in_length -= 1;
                }
        }

        ntb_set_error(error,
                      &ntb_parse_addresses_error,
                      NTB_PARSE_ADDRESSES_ERROR_INVALID,
                      "Unterminated quotes in address");
        return -1;
}

static ssize_t
parse_brackets(struct ntb_parse_addresses_data *data,
               const uint8_t *brackets_start,
               size_t in_length,
               struct ntb_error **error)
{
        const uint8_t *in = brackets_start;

        assert(*in == '<');

        if (data->had_address) {
                ntb_set_error(error,
                              &ntb_parse_addresses_error,
                              NTB_PARSE_ADDRESSES_ERROR_INVALID,
                              "Address contains multiple <>-brackets");
                return -1;
        }

        data->had_address = true;

        in++;
        in_length--;

        data->buffer->length = 0;

        while (in_length > 0) {
                switch (*in) {
                case '>':
                        if (!process_address(data, error))
                                return -1;
                        return in + 1 - brackets_start;

                default:
                        ntb_buffer_append_c(data->buffer, *in);
                        in += 1;
                        in_length -= 1;
                }
        }

        ntb_set_error(error,
                      &ntb_parse_addresses_error,
                      NTB_PARSE_ADDRESSES_ERROR_INVALID,
                      "Unterminated brackets in address");
        return -1;
}

bool
ntb_parse_addresses(struct ntb_buffer *buffer,
                    ntb_parse_addresses_cb cb,
                    void *user_data,
                    struct ntb_error **error)
{
        struct ntb_parse_addresses_data data;
        const uint8_t *in;
        ssize_t processed;
        size_t in_length;

        /* The buffer is used as both the incoming address list and as
         * a temporary buffer to store the potential addresses. The
         * addresses should never end up being longer than the point
         * we've parsed to so this shouldn't cause any problems */

        in = buffer->data;
        in_length = buffer->length;

        data.buffer = buffer;
        data.cb = cb;
        data.cb_user_data = user_data;
        reset_data(&data);

        while (in_length > 0) {
                switch (*in) {
                case ',':
                        if (!end_address(&data, error))
                                return false;
                        reset_data(&data);
                        in++;
                        in_length--;
                        break;

                case '"':
                        processed = parse_quotes(&data, in, in_length, error);
                        if (processed < 0)
                                return false;
                        in += processed;
                        in_length -= processed;
                        break;

                case '<':
                        processed = parse_brackets(&data, in, in_length, error);
                        if (processed < 0)
                                return false;
                        in += processed;
                        in_length -= processed;
                        break;

                case ' ':
                        in++;
                        in_length--;
                        break;

                default:
                        ntb_buffer_append_c(buffer, *in);
                        in++;
                        in_length--;
                        break;
                }
        }

        return end_address(&data, error);
}
