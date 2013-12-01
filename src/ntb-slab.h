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

#ifndef NTB_SLAB_H
#define NTB_SLAB_H

#include <stddef.h>

#ifdef __GNUC__
#define NTB_SLAB_ALIGNOF(x) __alignof__ (x)
#else
#error "FIXME: add an implementation of the alignof macro for this compiler"
#endif

struct ntb_slab;

struct ntb_slab_allocator {
        struct ntb_slab *slabs;
        size_t slab_used;
};

void
ntb_slab_init(struct ntb_slab_allocator *allocator);

void *
ntb_slab_allocate(struct ntb_slab_allocator *allocator,
                  size_t size,
                  int alignment);

void
ntb_slab_destroy(struct ntb_slab_allocator *allocator);

#endif /* NTB_SLAB_H */
