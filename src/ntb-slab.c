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

#include <stdint.h>

#include "ntb-slab.h"
#include "ntb-util.h"

/* All of the allocations are made out of slabs of 2kb. That way all
 * of the memory can be freed by just freeing the few slabs */
struct ntb_slab {
        struct ntb_slab *next;
};

void
ntb_slab_init(struct ntb_slab_allocator *allocator)
{
        static const struct ntb_slab_allocator init = NTB_SLAB_STATIC_INIT;

        *allocator = init;
}

static size_t
ntb_slab_align(size_t base, int alignment)
{
        return (base + alignment - 1) & ~(alignment - 1);
}

void *
ntb_slab_allocate(struct ntb_slab_allocator *allocator,
                  size_t size, int alignment)
{
        struct ntb_slab *slab;
        size_t offset;

        offset = ntb_slab_align(allocator->slab_used, alignment);

        if (size + offset > NTB_SLAB_SIZE) {
                /* Start a new slab */
                slab = ntb_alloc(NTB_SLAB_SIZE);
                slab->next = allocator->slabs;
                allocator->slabs = slab;

                offset = ntb_slab_align(sizeof(struct ntb_slab), alignment);
        } else {
                slab = allocator->slabs;
        }

        allocator->slab_used = offset + size;

        return (uint8_t *) slab + offset;
}

void
ntb_slab_destroy(struct ntb_slab_allocator *allocator)
{
        struct ntb_slab *slab, *next;

        for (slab = allocator->slabs; slab; slab = next) {
                next = slab->next;
                ntb_free(slab);
        }
}
