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
