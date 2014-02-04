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
