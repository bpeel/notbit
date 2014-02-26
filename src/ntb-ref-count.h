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

#ifndef NTB_REF_COUNT_H
#define NTB_REF_COUNT_H

#ifndef HAVE_SYNC_REF_COUNT
#include <pthread.h>
#endif /* HAVE_SYNC_REF_COUNT */

#include <stdint.h>
#include <stddef.h>

/* This is used for thread-safe atomic reference counting */

struct ntb_ref_count {
#ifndef HAVE_SYNC_REF_COUNT
        pthread_mutex_t mutex;
#endif /* HAVE_SYNC_REF_COUNT */

        int count;
};

static inline void
ntb_ref_count_init(struct ntb_ref_count *ref_count)
{
#ifndef HAVE_SYNC_REF_COUNT
        pthread_mutex_init(&blob->mutex, NULL);
#endif
        ref_count->count = 1;
}

static inline void
ntb_ref_count_ref(struct ntb_ref_count *ref_count)
{
#ifdef HAVE_SYNC_REF_COUNT
        __sync_fetch_and_add(&ref_count->count, 1);
#else
        pthread_mutex_lock(&ref_count->mutex);
        blob->count++;
        pthread_mutex_unlock(&ref_count->mutex);
#endif
}

/* Returns the old ref count */

static inline int
ntb_ref_count_unref(struct ntb_ref_count *ref_count)
{
        int old_value;

#ifdef HAVE_SYNC_REF_COUNT
        old_value = __sync_fetch_and_sub(&ref_count->count, 1);
#else
        pthread_mutex_lock(&ref_count->mutex);
        old_value = ref_count->count--;
        pthread_mutex_unlock(&ref_count->mutex);
#endif

        return old_value;
}

static inline void
ntb_ref_count_destroy(struct ntb_ref_count *ref_count)
{
#ifndef HAVE_SYNC_REF_COUNT
        pthread_mutex_destroy(&ref_count->mutex);
#endif
}

#endif /* NTB_REF_COUNT_H */
