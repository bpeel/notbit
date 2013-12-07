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

#ifndef NTB_BLOB_H
#define NTB_BLOB_H

#ifndef HAVE_SYNC_REF_COUNT
#include <pthread.h>
#endif /* HAVE_SYNC_REF_COUNT */

#include <stdint.h>
#include <stddef.h>

#include "ntb-proto.h"

/* A blob represents a ref-counted immutable chunk of data. This will
 * be used to hold all inventory objects from the network such as
 * messages and public keys. The ref-count is thread-safe so that the
 * blob can be passed off to the store thread to be written to
 * disk. */

struct ntb_blob {
        enum ntb_proto_inv_type type;

#ifndef HAVE_SYNC_REF_COUNT
        pthread_mutex_t ref_count_mutex;
#endif /* HAVE_SYNC_REF_COUNT */

        int ref_count;

        size_t size;

        /* Over-allocated to contain the data */
        uint8_t data[1];
};

struct ntb_blob *
ntb_blob_new(enum ntb_proto_inv_type type,
             const void *data,
             size_t size);

struct ntb_blob *
ntb_blob_ref(struct ntb_blob *blob);

void
ntb_blob_unref(struct ntb_blob *blob);

#endif /* NTB_BLOB_H */
