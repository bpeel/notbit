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

#include "ntb-hash-table.h"
#include "ntb-util.h"
#include "ntb-slice.h"
#include "ntb-proto.h"

struct ntb_hash_table_entry {
        struct ntb_hash_table_entry *next;
        uint8_t *data;
};

struct ntb_hash_table {
        size_t hash_offset;
        size_t size;
        size_t n_entries;
        struct ntb_hash_table_entry **entries;
};

NTB_SLICE_ALLOCATOR(struct ntb_hash_table_entry,
                    ntb_hash_table_entry_allocator);

static void
alloc_entries(struct ntb_hash_table *hash_table,
              size_t size)
{
        size_t alloc_size = sizeof (struct ntb_hash_table_entry *) * size;
        hash_table->entries = ntb_alloc(alloc_size);
        memset(hash_table->entries, 0, alloc_size);
        hash_table->size = size;
}

struct ntb_hash_table *
ntb_hash_table_new(size_t hash_offset)
{
        struct ntb_hash_table *hash_table = ntb_alloc(sizeof *hash_table);

        hash_table->hash_offset = hash_offset;
        hash_table->n_entries = 0;

        alloc_entries(hash_table, 8);

        return hash_table;
}

static uint32_t
get_index(struct ntb_hash_table *hash_table,
          const uint8_t *hash)
{
        uint32_t index;

        memcpy(&index, hash, sizeof index);

        return index & (hash_table->size - 1);
}

void *
ntb_hash_table_get(struct ntb_hash_table *hash_table,
                   const uint8_t *hash)
{
        struct ntb_hash_table_entry *entry;
        uint32_t index = get_index(hash_table, hash);

        for (entry = hash_table->entries[index]; entry; entry = entry->next) {
                if (!memcmp(hash,
                            entry->data + hash_table->hash_offset,
                            NTB_PROTO_HASH_LENGTH)) {
                        return entry->data;
                }
        }

        return NULL;
}

static void
insert_entry_at_index(struct ntb_hash_table *hash_table,
                      struct ntb_hash_table_entry *entry,
                      uint32_t index)
{
        entry->next = hash_table->entries[index]->next;
        hash_table->entries[index]->next = entry;
}

static void
ntb_hash_table_grow(struct ntb_hash_table *hash_table)
{
        size_t old_size = hash_table->size;
        struct ntb_hash_table_entry **old_entries = hash_table->entries;
        struct ntb_hash_table_entry *entry, *next;
        const uint8_t *hash;
        uint32_t index;
        int i;

        alloc_entries(hash_table, old_size * 2);

        for (i = 0; i < old_size; i++) {
                for (entry = old_entries[i]; entry; entry = next) {
                        next = entry->next;

                        hash = entry->data + hash_table->hash_offset;

                        index = get_index(hash_table, hash);

                        insert_entry_at_index(hash_table, entry, index);
                }
        }

        ntb_free(old_entries);
}

void *
ntb_hash_table_set(struct ntb_hash_table *hash_table,
                   void *value)
{
        struct ntb_hash_table_entry *entry;
        const uint8_t *hash = (const uint8_t *) value + hash_table->hash_offset;
        uint32_t index = get_index(hash_table, hash);
        void *old_value;

        for (entry = hash_table->entries[index]; entry; entry = entry->next) {
                if (!memcmp(hash,
                            entry->data + hash_table->hash_offset,
                            NTB_PROTO_HASH_LENGTH)) {
                        old_value = entry->data;
                        entry->data = value;
                        return old_value;
                }
        }

        if (hash_table->n_entries >= hash_table->size * 3 / 4) {
                ntb_hash_table_grow(hash_table);
                index = get_index(hash_table, hash);
        }

        entry = ntb_slice_alloc(&ntb_hash_table_entry_allocator);
        entry->data = value;
        insert_entry_at_index(hash_table, entry, index);

        return NULL;
}

void
ntb_hash_table_free(struct ntb_hash_table *hash_table)
{
        struct ntb_hash_table_entry *entry, *next;
        int i;

        for (i = 0; i < hash_table->size; i++) {
                for (entry = hash_table->entries[i]; entry; entry = next) {
                        next = entry->next;
                        ntb_slice_free(&ntb_hash_table_entry_allocator, entry);
                }
        }

        ntb_free(hash_table->entries);
        ntb_free(hash_table);
}
