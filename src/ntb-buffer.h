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

#ifndef NTB_BUFFER_H
#define NTB_BUFFER_H

#include <stdint.h>
#include <stdarg.h>

#include "ntb-util.h"

struct ntb_buffer {
        uint8_t *data;
        size_t length;
        size_t size;
};

#define NTB_BUFFER_STATIC_INIT { .data = NULL, .length = 0, .size = 0 }

void
ntb_buffer_init(struct ntb_buffer *buffer);

void
ntb_buffer_ensure_size(struct ntb_buffer *buffer,
                       size_t size);

void
ntb_buffer_set_length(struct ntb_buffer *buffer,
                      size_t length);

NTB_PRINTF_FORMAT(2, 3) void
ntb_buffer_append_printf(struct ntb_buffer *buffer,
                         const char *format,
                         ...);

void
ntb_buffer_append_vprintf(struct ntb_buffer *buffer,
                          const char *format,
                          va_list ap);

void
ntb_buffer_append(struct ntb_buffer *buffer,
                  const void *data,
                  size_t length);

static inline void
ntb_buffer_append_c(struct ntb_buffer *buffer,
                    char c)
{
        if (buffer->size > buffer->length)
                buffer->data[buffer->length++] = c;
        else
                ntb_buffer_append(buffer, &c, 1);
}

void
ntb_buffer_append_string(struct ntb_buffer *buffer,
                         const char *str);

void
ntb_buffer_destroy(struct ntb_buffer *buffer);

#endif /* NTB_BUFFER_H */
