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
        bool underscore_is_space;
};

void
ntb_quoted_printable_decode_start(struct ntb_quoted_printable_data *state,
                                  bool underscore_is_space);

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
