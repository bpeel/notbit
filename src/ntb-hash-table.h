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

#ifndef NTB_HASH_TABLE_H
#define NTB_HASH_TABLE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct ntb_hash_table;

struct ntb_hash_table *
ntb_hash_table_new(size_t hash_offset);

void *
ntb_hash_table_get(struct ntb_hash_table *hash_table,
                   const uint8_t *hash);

void *
ntb_hash_table_set(struct ntb_hash_table *hash_table,
                   void *value);

bool
ntb_hash_table_remove(struct ntb_hash_table *hash_table,
                      const void *value);

void
ntb_hash_table_free(struct ntb_hash_table *hash_table);

#endif /* NTB_HASH_TABLE_H */
