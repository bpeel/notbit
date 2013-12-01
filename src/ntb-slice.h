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

#ifndef NTB_SLICE_H
#define NTB_SLICE_H

#include "ntb-util.h"
#include "ntb-slab.h"

struct ntb_slice {
        struct ntb_slice *next;
};

struct ntb_slice_allocator {
        size_t element_size;
        size_t element_alignment;
        struct ntb_slice *magazine;
        struct ntb_slab_allocator slab;
};

#define NTB_SLICE_ALLOCATOR(type, name)                                 \
        static struct ntb_slice_allocator                               \
        name = {                                                        \
                .element_size = MAX(sizeof(type), sizeof (struct ntb_slice)), \
                .element_alignment = NTB_ALIGNOF(type),                 \
                .magazine = NULL,                                       \
                .slab = NTB_SLAB_STATIC_INIT                            \
        }

void *
ntb_slice_alloc(struct ntb_slice_allocator *allocator);

void
ntb_slice_free(struct ntb_slice_allocator *allocator,
               void *ptr);

#endif /* NTB_SLICE_H */
