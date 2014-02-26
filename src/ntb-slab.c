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
