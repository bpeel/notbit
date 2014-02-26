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

#ifndef NTB_BASE64_H
#define NTB_BASE64_H

#include <stdlib.h>
#include <stdint.h>

#include "ntb-error.h"

extern struct ntb_error_domain
ntb_base64_error;

enum ntb_base64_error {
        NTB_BASE64_ERROR_INVALID_PADDING
};

struct ntb_base64_data {
        int n_padding;
        int n_chars;
        int value;
};

#define NTB_BASE64_MAX_INPUT_FOR_SIZE(input_size) \
        ((size_t) (input_size) * 4 / 3)

void
ntb_base64_decode_start(struct ntb_base64_data *data);

ssize_t
ntb_base64_decode(struct ntb_base64_data *data,
                  const uint8_t *in_buffer,
                  size_t length,
                  uint8_t *out_buffer,
                  struct ntb_error **error);

ssize_t
ntb_base64_decode_end(struct ntb_base64_data *data,
                      uint8_t *buffer,
                      struct ntb_error **error);

size_t
ntb_base64_encode(const uint8_t *data_in,
                  size_t data_in_length,
                  char *data_out);

#endif /* NTB_BASE64_H */
