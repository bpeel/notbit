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
