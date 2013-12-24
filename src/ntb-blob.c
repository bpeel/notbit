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

#include "config.h"

#include <string.h>

#include "ntb-blob.h"
#include "ntb-util.h"

void
ntb_blob_dynamic_init(struct ntb_buffer *buffer,
                      enum ntb_proto_inv_type type)
{
        struct ntb_blob *blob;

        ntb_buffer_init(buffer);

        ntb_buffer_set_length(buffer,
                              NTB_STRUCT_OFFSET(struct ntb_blob, data));

        blob = (struct ntb_blob *) buffer->data;
        blob->type = type;
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
ntb_blob_new(enum ntb_proto_inv_type type,
             const void *data,
             size_t size)
{
        struct ntb_blob *blob =
                ntb_alloc(NTB_STRUCT_OFFSET(struct ntb_blob, data) + size);

        blob->type = type;
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
