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

#ifndef NTB_QUOTED_PRINTABLE_H
#define NTB_QUOTED_PRINTABLE_H

#include <stdlib.h>
#include <stdint.h>

#include "ntb-error.h"

extern struct ntb_error_domain
ntb_quoted_printable_error;

enum ntb_quoted_printable_error {
        NTB_QUOTED_PRINTABLE_ERROR_INVALID_ESCAPE
};

enum ntb_quoted_printable_state {
        /* The default state where if we see a character we will
         * directly add it to the output or if we see an equals sign
         * we'll start a quote */
        NTB_QUOTED_PRINTABLE_STATE_OCTET,
        /* We've encountered an equals sign and the next character
         * will determine how to handle it */
        NTB_QUOTED_PRINTABLE_STATE_QUOTE_START,
        /* We've encountered a space or tab character afer an equals
         * sign and we're ignoring the rest of the whitespace until
         * the end of the line */
        NTB_QUOTED_PRINTABLE_STATE_SKIP_SPACES,
        /* We've encountered the CR (0xd) of a soft line break */
        NTB_QUOTED_PRINTABLE_STATE_SOFT_CR,
        /* We've encountered the first hex digit of an escaped octet */
        NTB_QUOTED_PRINTABLE_STATE_ESCAPED_OCTET
};

struct ntb_quoted_printable_data {
        enum ntb_quoted_printable_state state;
        int nibble;
        uint8_t *out;
};

void
ntb_quoted_printable_decode_start(struct ntb_quoted_printable_data *state);

ssize_t
ntb_quoted_printable_decode(struct ntb_quoted_printable_data *state,
                            const uint8_t *in_buffer,
                            size_t length,
                            uint8_t *out_buffer,
                            struct ntb_error **error);

bool
ntb_quoted_printable_decode_end(struct ntb_quoted_printable_data *state,
                                struct ntb_error **error);

#endif /* NTB_QUOTED_PRINTABLE_H */
