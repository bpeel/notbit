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

#include <string.h>

#include "ntb-blob.h"
#include "ntb-util.h"

void
ntb_blob_dynamic_init(struct ntb_buffer *buffer)
{
        ntb_buffer_init(buffer);

        ntb_buffer_set_length(buffer,
                              NTB_STRUCT_OFFSET(struct ntb_blob, data));
}

struct ntb_blob *
ntb_blob_dynamic_end(struct ntb_buffer *buffer)
{
        struct ntb_blob *blob = (struct ntb_blob *) buffer->data;

        blob->size = buffer->length - NTB_STRUCT_OFFSET(struct ntb_blob, data);
        ntb_ref_count_init(&blob->ref_count);

        return blob;
}

struct ntb_blob *
ntb_blob_new(const void *data,
             size_t size)
{
        struct ntb_blob *blob =
                ntb_alloc(NTB_STRUCT_OFFSET(struct ntb_blob, data) + size);

        blob->size = size;

        ntb_ref_count_init(&blob->ref_count);

        if (data)
                memcpy(blob->data, data, size);

        return blob;
}

struct ntb_blob *
ntb_blob_ref(struct ntb_blob *blob)
{
        ntb_ref_count_ref(&blob->ref_count);

        return blob;
}

void
ntb_blob_unref(struct ntb_blob *blob)
{
        if (ntb_ref_count_unref(&blob->ref_count) <= 1) {
                ntb_ref_count_destroy(&blob->ref_count);
                ntb_free(blob);
        }
}
