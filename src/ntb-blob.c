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

struct ntb_blob *
ntb_blob_new(enum ntb_blob_type type,
             const void *data,
             size_t size)
{
        struct ntb_blob *blob =
                ntb_alloc(NTB_STRUCT_OFFSET(struct ntb_blob, data) + size);

        blob->type = type;
        blob->ref_count = 1;
        blob->size = size;

#ifndef HAVE_SYNC_REF_COUNT
        pthread_mutex_init(&blob->ref_count_mutex, NULL);
#endif

        memcpy(blob->data, data, size);

        return blob;
}

struct ntb_blob *
ntb_blob_ref(struct ntb_blob *blob)
{
#ifdef HAVE_SYNC_REF_COUNT
        __sync_fetch_and_add(&blob->ref_count, 1);
#else
        pthread_mutex_lock(&blob->ref_count_mutex);
        blob->ref_count++;
        pthread_mutex_unlock(&blob->ref_count_mutex);
#endif

        return blob;
}

void
ntb_blob_unref(struct ntb_blob *blob)
{
        int old_value;

#ifdef HAVE_SYNC_REF_COUNT
        old_value = __sync_fetch_and_sub(&blob->ref_count, 1);
#else
        pthread_mutex_lock(&blob->ref_count_mutex);
        old_value = blob->ref_count--;
        pthread_mutex_unlock(&blob->ref_count_mutex);
#endif

        if (old_value <= 1) {
#ifndef HAVE_SYNC_REF_COUNT
                pthread_mutex_destroy(&blob->ref_count_mutex);
#endif

                ntb_free(blob);
        }
}
