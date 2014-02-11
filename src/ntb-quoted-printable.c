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

#include "config.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "ntb-quoted-printable.h"
#include "ntb-error.h"

struct ntb_error_domain
ntb_quoted_printable_error;

void
ntb_quoted_printable_decode_start(struct ntb_quoted_printable_data *data,
                                  bool underscore_is_space)
{
        data->state = NTB_QUOTED_PRINTABLE_STATE_OCTET;
        data->underscore_is_space = underscore_is_space;
}

static int
hex_value(int ch)
{
        if (ch <= '9') {
                if (ch < '0')
                        return -1;
                return ch - '0';
        } else if (ch <= 'F') {
                if (ch < 'A')
                        return -1;
                return ch - 'A' + 10;
        } else if (ch <= 'f') {
                if (ch < 'a')
                        return -1;
                return ch - 'a' + 10;
        } else {
                return -1;
        }
}

static ssize_t
invalid_escape_error(struct ntb_error **error)
{
        ntb_set_error(error,
                      &ntb_quoted_printable_error,
                      NTB_QUOTED_PRINTABLE_ERROR_INVALID_ESCAPE,
                      "The quoted-printable data contains an invalid escape "
                      "sequence");
        return -1;
}

static void
output_octets(struct ntb_quoted_printable_data *data,
              const uint8_t *octets,
              size_t length)
{
        if (data->underscore_is_space) {
                while (length > 0) {
                        if (*octets == '_')
                                *(data->out++) = ' ';
                        else
                                *(data->out++) = *octets;
                        octets++;
                        length--;
                }
        } else {
                memcpy(data->out, octets, length);
                data->out += length;
        }
}

static ssize_t
handle_octet(struct ntb_quoted_printable_data *data,
             const uint8_t *in_buffer,
             size_t length,
             struct ntb_error **error)
{
        const uint8_t *equals;

        equals = memchr(in_buffer, '=', length);

        if (equals == NULL) {
                output_octets(data, in_buffer, length);
                return length;
        }

        output_octets(data, in_buffer, equals - in_buffer);

        data->state = NTB_QUOTED_PRINTABLE_STATE_QUOTE_START;

        return equals + 1 - in_buffer;
}

static ssize_t
handle_quote_start(struct ntb_quoted_printable_data *data,
                   const uint8_t *in_buffer,
                   size_t length,
                   struct ntb_error **error)
{
        int nibble = hex_value(*in_buffer);

        if (nibble >= 0) {
                data->nibble = nibble;
                data->state = NTB_QUOTED_PRINTABLE_STATE_ESCAPED_OCTET;
        } else if (*in_buffer == ' ' || *in_buffer == '\t') {
                data->state = NTB_QUOTED_PRINTABLE_STATE_SKIP_SPACES;
        } else if (*in_buffer == '\r') {
                data->state = NTB_QUOTED_PRINTABLE_STATE_SOFT_CR;
        } else if (*in_buffer == '\n') {
                data->state = NTB_QUOTED_PRINTABLE_STATE_OCTET;
        } else {
                return invalid_escape_error(error);
        }

        return 1;
}

static ssize_t
handle_skip_spaces(struct ntb_quoted_printable_data *data,
                   const uint8_t *in_buffer,
                   size_t length,
                   struct ntb_error **error)
{
        size_t skip;

        for (skip = 0; skip < length; skip++) {
                switch (in_buffer[skip]) {
                case ' ':
                case '\t':
                        break;

                case '\r':
                        data->state = NTB_QUOTED_PRINTABLE_STATE_SOFT_CR;
                        return skip + 1;

                case '\n':
                        data->state = NTB_QUOTED_PRINTABLE_STATE_OCTET;
                        return skip + 1;

                default:
                        return invalid_escape_error(error);
                }
        }

        return skip;
}

static ssize_t
handle_soft_cr(struct ntb_quoted_printable_data *data,
               const uint8_t *in_buffer,
               size_t length,
               struct ntb_error **error)
{
        if (*in_buffer != '\n')
                return invalid_escape_error(error);

        data->state = NTB_QUOTED_PRINTABLE_STATE_OCTET;

        return 1;
}

static ssize_t
handle_escaped_octet(struct ntb_quoted_printable_data *data,
                     const uint8_t *in_buffer,
                     size_t length,
                     struct ntb_error **error)
{
        int nibble = hex_value(*in_buffer);

        if (nibble == -1)
                return invalid_escape_error(error);

        *(data->out++) = (data->nibble << 4) | nibble;

        data->state = NTB_QUOTED_PRINTABLE_STATE_OCTET;

        return 1;
}

ssize_t
ntb_quoted_printable_decode(struct ntb_quoted_printable_data *data,
                            const uint8_t *in_buffer,
                            size_t length,
                            uint8_t *out_buffer,
                            struct ntb_error **error)
{
        ssize_t processed;

        data->out = out_buffer;

        while (length > 0) {
                switch (data->state) {
                case NTB_QUOTED_PRINTABLE_STATE_OCTET:
                        processed = handle_octet(data,
                                                 in_buffer,
                                                 length,
                                                 error);
                        break;

                case NTB_QUOTED_PRINTABLE_STATE_QUOTE_START:
                        processed = handle_quote_start(data,
                                                       in_buffer,
                                                       length,
                                                       error);
                        break;

                case NTB_QUOTED_PRINTABLE_STATE_SKIP_SPACES:
                        processed = handle_skip_spaces(data,
                                                       in_buffer,
                                                       length,
                                                       error);
                        break;

                case NTB_QUOTED_PRINTABLE_STATE_SOFT_CR:
                        processed = handle_soft_cr(data,
                                                   in_buffer,
                                                   length,
                                                   error);
                        break;

                case NTB_QUOTED_PRINTABLE_STATE_ESCAPED_OCTET:
                        processed = handle_escaped_octet(data,
                                                         in_buffer,
                                                         length,
                                                         error);
                        break;
                }

                if (processed == -1)
                        return -1;

                length -= processed;
                in_buffer += processed;
        }

        return data->out - out_buffer;
}

bool
ntb_quoted_printable_decode_end(struct ntb_quoted_printable_data *data,
                                struct ntb_error **error)
{
        if (data->state != NTB_QUOTED_PRINTABLE_STATE_OCTET) {
                invalid_escape_error(error);
                return false;
        }

        return true;
}

#if 0 /* for testing */

#include <stdio.h>

int
main(int argc, char **argv)
{
        struct ntb_quoted_printable_data data;
        struct ntb_error *error = NULL;
        uint8_t buf[1];
        size_t got;
        ssize_t got_out;

        ntb_quoted_printable_decode_start(&data);

        do {
                got = fread(buf, 1, sizeof buf, stdin);

                got_out = ntb_quoted_printable_decode(&data,
                                                      buf,
                                                      got,
                                                      buf,
                                                      &error);

                if (got_out == -1) {
                        fprintf(stderr, "%s\n", error->message);
                        ntb_error_free(error);
                        return 1;
                }

                fwrite(buf, 1, got_out, stdout);
        } while (got >= sizeof buf);

        if (!ntb_quoted_printable_decode_end(&data, &error)) {
                fprintf(stderr, "%s\n", error->message);
                ntb_error_free(error);
                return 1;
        }

        return 0;
}

#endif /* for testing */
