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

#ifndef NTB_STORE_H
#define NTB_STORE_H

#include <stdint.h>

#include "ntb-blob.h"
#include "ntb-error.h"

/* The store is used to do all of the disk I/O. The actions are stored
 * in a queue and then executed in a separate thread */

struct ntb_store;

extern struct ntb_error_domain
ntb_store_error;

enum ntb_store_error {
        NTB_STORE_ERROR_CREATING_DIRECTORY,
        NTB_STORE_ERROR_INVALID_STORE_DIRECTORY
};

struct ntb_store *
ntb_store_new(const char *store_directory,
              struct ntb_error **error);

void
ntb_store_save_blob(struct ntb_store *store,
                    const uint8_t *hash,
                    struct ntb_blob *blob);

void
ntb_store_delete_object(struct ntb_store *store,
                        const uint8_t *hash);

void
ntb_store_free(struct ntb_store *store);

#endif /* NTB_STORE_H */
