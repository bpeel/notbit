/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2011, 2013  Neil Roberts
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

#include <errno.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>

#include "ntb-main-context.h"
#include "ntb-list.h"
#include "ntb-util.h"
#include "ntb-slice.h"
#include "ntb-buffer.h"

struct ntb_error_domain
ntb_main_context_error;

struct ntb_main_context_bucket;

struct ntb_main_context {
        /* This mutex the idle_sources list and the slice allocator so
         * that idle sources can be added from other threads.
         * Everything else should only be accessed from the main
         * thread so it doesn't need to guarded. Removing an idle
         * source can only happen in the main thread. That is
         * necessary because it is difficult to cope with random idle
         * sources being removed while we are iterating the list */
        pthread_mutex_t idle_mutex;

        /* Array for receiving events */
        struct ntb_buffer poll_array;
        bool poll_array_dirty;

        /* List of quit sources. All of these get invoked when a quit signal
           is received */
        struct ntb_list quit_sources;

        struct ntb_list idle_sources;

        struct ntb_list poll_sources;

        struct ntb_main_context_source *async_pipe_source;
        int async_pipe[2];
        pthread_t main_thread;

        void (* old_int_handler)(int);
        void (* old_term_handler)(int);

        bool monotonic_time_valid;
        int64_t monotonic_time;

        bool wall_time_valid;
        int64_t wall_time;

        struct ntb_list buckets;
        int64_t last_timer_time;

        /* This allocator is protected by the idle_mutex */
        struct ntb_slice_allocator source_allocator;
};

struct ntb_main_context_source {
        enum {
                NTB_MAIN_CONTEXT_POLL_SOURCE,
                NTB_MAIN_CONTEXT_TIMER_SOURCE,
                NTB_MAIN_CONTEXT_IDLE_SOURCE,
                NTB_MAIN_CONTEXT_QUIT_SOURCE
        } type;

        union {
                /* Poll sources */
                struct {
                        int fd;
                        enum ntb_main_context_poll_flags current_flags;
                };

                /* Timer sources */
                struct {
                        struct ntb_main_context_bucket *bucket;
                        bool busy;
                        bool removed;
                };
        };

        void *user_data;
        void *callback;
        struct ntb_list link;

        struct ntb_main_context *mc;
};

struct ntb_main_context_bucket {
        struct ntb_list link;
        struct ntb_list sources;
        int minutes;
        int minutes_passed;
};

NTB_SLICE_ALLOCATOR(struct ntb_main_context_bucket,
                    ntb_main_context_bucket_allocator);

static struct ntb_main_context *ntb_main_context_default = NULL;

struct ntb_main_context *
ntb_main_context_get_default(void)
{
        if (ntb_main_context_default == NULL)
                ntb_main_context_default = ntb_main_context_new();

        return ntb_main_context_default;
}

static void
free_source(struct ntb_main_context *mc,
            struct ntb_main_context_source *source)
{
        pthread_mutex_lock(&mc->idle_mutex);
        ntb_list_remove(&source->link);
        ntb_slice_free(&mc->source_allocator, source);
        pthread_mutex_unlock(&mc->idle_mutex);
}

static void
async_pipe_cb(struct ntb_main_context_source *source,
              int fd,
              enum ntb_main_context_poll_flags flags,
              void *user_data)
{
        struct ntb_main_context *mc = user_data;
        struct ntb_main_context_source *quit_source;
        ntb_main_context_quit_callback callback;
        uint8_t byte;

        if (read(mc->async_pipe[0], &byte, sizeof(byte)) == -1) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                        ntb_warning("Read from quit pipe failed: %s",
                                    strerror(errno));
        } else if (byte == 'Q') {
                ntb_list_for_each(quit_source, &mc->quit_sources, link) {
                        callback = quit_source->callback;
                        callback(quit_source, quit_source->user_data);
                }
        }
}

static void
send_async_byte(struct ntb_main_context *mc,
                char byte)
{
        while (write(mc->async_pipe[1], &byte, 1) == -1 && errno == EINTR);
}

static void
ntb_main_context_quit_signal_cb(int signum)
{
        struct ntb_main_context *mc = ntb_main_context_get_default();

        send_async_byte(mc, 'Q');
}

struct ntb_main_context *
ntb_main_context_new(void)
{
        struct ntb_main_context *mc = ntb_alloc(sizeof *mc);

        pthread_mutex_init(&mc->idle_mutex, NULL /* attrs */);
        ntb_slice_allocator_init(&mc->source_allocator,
                                 sizeof(struct ntb_main_context_source),
                                 NTB_ALIGNOF(struct ntb_main_context_source));
        mc->monotonic_time_valid = false;
        mc->wall_time_valid = false;
        mc->poll_array_dirty = true;
        ntb_buffer_init(&mc->poll_array);
        ntb_list_init(&mc->quit_sources);
        ntb_list_init(&mc->idle_sources);
        ntb_list_init(&mc->poll_sources);
        ntb_list_init(&mc->buckets);
        mc->last_timer_time = ntb_main_context_get_monotonic_clock(mc);

        mc->old_int_handler = signal(SIGINT, ntb_main_context_quit_signal_cb);
        mc->old_term_handler = signal(SIGTERM, ntb_main_context_quit_signal_cb);

        if (pipe(mc->async_pipe) == -1) {
                ntb_warning("Failed to create pipe: %s",
                            strerror(errno));
        } else {
                mc->async_pipe_source
                        = ntb_main_context_add_poll(mc, mc->async_pipe[0],
                                                    NTB_MAIN_CONTEXT_POLL_IN,
                                                    async_pipe_cb,
                                                    mc);
        }

        mc->main_thread = pthread_self();

        return mc;
}

struct ntb_main_context_source *
ntb_main_context_add_poll(struct ntb_main_context *mc,
                          int fd,
                          enum ntb_main_context_poll_flags flags,
                          ntb_main_context_poll_callback callback,
                          void *user_data)
{
        struct ntb_main_context_source *source;

        if (mc == NULL)
                mc = ntb_main_context_get_default();

        pthread_mutex_lock(&mc->idle_mutex);
        source = ntb_slice_alloc(&mc->source_allocator);
        pthread_mutex_unlock(&mc->idle_mutex);

        source->mc = mc;
        source->fd = fd;
        source->callback = callback;
        source->type = NTB_MAIN_CONTEXT_POLL_SOURCE;
        source->user_data = user_data;
        source->current_flags = flags;
        ntb_list_insert(&mc->poll_sources, &source->link);

        mc->poll_array_dirty = true;

        return source;
}

void
ntb_main_context_modify_poll(struct ntb_main_context_source *source,
                             enum ntb_main_context_poll_flags flags)
{
        ntb_return_if_fail(source->type == NTB_MAIN_CONTEXT_POLL_SOURCE);

        if (source->current_flags == flags)
                return;

        source->current_flags = flags;
        source->mc->poll_array_dirty = true;
}

struct ntb_main_context_source *
ntb_main_context_add_quit(struct ntb_main_context *mc,
                          ntb_main_context_quit_callback callback,
                          void *user_data)
{
        struct ntb_main_context_source *source;

        if (mc == NULL)
                mc = ntb_main_context_get_default();

        pthread_mutex_lock(&mc->idle_mutex);
        source = ntb_slice_alloc(&mc->source_allocator);
        pthread_mutex_unlock(&mc->idle_mutex);

        source->mc = mc;
        source->callback = callback;
        source->type = NTB_MAIN_CONTEXT_QUIT_SOURCE;
        source->user_data = user_data;

        ntb_list_insert(&mc->quit_sources, &source->link);

        return source;
}

static struct ntb_main_context_bucket *
get_bucket(struct ntb_main_context *mc, int minutes)
{
        struct ntb_main_context_bucket *bucket;

        ntb_list_for_each(bucket, &mc->buckets, link) {
                if (bucket->minutes == minutes)
                        return bucket;
        }

        bucket = ntb_slice_alloc(&ntb_main_context_bucket_allocator);
        ntb_list_init(&bucket->sources);
        bucket->minutes = minutes;
        bucket->minutes_passed = 0;
        ntb_list_insert(&mc->buckets, &bucket->link);

        return bucket;
}

struct ntb_main_context_source *
ntb_main_context_add_timer(struct ntb_main_context *mc,
                           int minutes,
                           ntb_main_context_timer_callback callback,
                           void *user_data)
{
        struct ntb_main_context_source *source;

        if (mc == NULL)
                mc = ntb_main_context_get_default();

        pthread_mutex_lock(&mc->idle_mutex);
        source = ntb_slice_alloc(&mc->source_allocator);
        pthread_mutex_unlock(&mc->idle_mutex);

        source->mc = mc;
        source->bucket = get_bucket(mc, minutes);
        source->callback = callback;
        source->type = NTB_MAIN_CONTEXT_TIMER_SOURCE;
        source->user_data = user_data;
        source->removed = false;
        source->busy = false;

        ntb_list_insert(&source->bucket->sources, &source->link);

        return source;
}

static void
wakeup_main_loop(struct ntb_main_context *mc)
{
        if (!pthread_equal(pthread_self(), mc->main_thread))
                send_async_byte(mc, 'W');
}

struct ntb_main_context_source *
ntb_main_context_add_idle(struct ntb_main_context *mc,
                          ntb_main_context_idle_callback callback,
                          void *user_data)
{
        struct ntb_main_context_source *source;

        if (mc == NULL)
                mc = ntb_main_context_get_default();

        /* This may be called from a thread other than the main one so
         * we need to guard access to the idle sources lists */
        pthread_mutex_lock(&mc->idle_mutex);
        source = ntb_slice_alloc(&mc->source_allocator);
        ntb_list_insert(&mc->idle_sources, &source->link);
        pthread_mutex_unlock(&mc->idle_mutex);

        source->mc = mc;
        source->callback = callback;
        source->type = NTB_MAIN_CONTEXT_IDLE_SOURCE;
        source->user_data = user_data;

        wakeup_main_loop(mc);

        return source;
}

void
ntb_main_context_remove_source(struct ntb_main_context_source *source)
{
        struct ntb_main_context *mc = source->mc;

        switch (source->type) {
        case NTB_MAIN_CONTEXT_POLL_SOURCE:
                free_source(mc, source);
                mc->poll_array_dirty = true;
                break;

        case NTB_MAIN_CONTEXT_IDLE_SOURCE:
        case NTB_MAIN_CONTEXT_QUIT_SOURCE:
                free_source(mc, source);
                break;

        case NTB_MAIN_CONTEXT_TIMER_SOURCE:
                /* Timer sources need to be able to be removed while
                 * iterating the source list to emit, so we need to
                 * handle them specially during iteration. */
                assert(!source->removed);
                if (source->busy)
                        source->removed = true;
                else
                        free_source(mc, source);
                break;
        }
}

static int
get_timeout(struct ntb_main_context *mc)
{
        struct ntb_main_context_bucket *bucket;
        int min_minutes, minutes_to_wait;
        int64_t elapsed, elapsed_minutes;

        if (!ntb_list_empty(&mc->idle_sources))
                return 0;

        if (ntb_list_empty(&mc->buckets))
                return -1;

        min_minutes = INT_MAX;

        ntb_list_for_each(bucket, &mc->buckets, link) {
                minutes_to_wait = bucket->minutes - bucket->minutes_passed;

                if (minutes_to_wait < min_minutes)
                        min_minutes = minutes_to_wait;
        }

        elapsed =
            ntb_main_context_get_monotonic_clock(mc) - mc->last_timer_time;
        elapsed_minutes = elapsed / 60000000;

        /* If we've already waited enough time then don't wait any
         * further time */
        if (elapsed_minutes >= min_minutes)
                return 0;

        /* Subtract the number of minutes we've already waited */
        min_minutes -= (int) elapsed_minutes;

        return (60000 - (elapsed / 1000 % 60000) + (min_minutes - 1) * 60000);
}

static void
check_timer_sources(struct ntb_main_context *mc)
{
        struct ntb_main_context_bucket *bucket;
        int64_t now;
        int64_t elapsed_minutes;

        if (ntb_list_empty(&mc->buckets))
                return;

        now = ntb_main_context_get_monotonic_clock(mc);
        elapsed_minutes = (now - mc->last_timer_time) / 60000000;
        mc->last_timer_time += elapsed_minutes * 60000000;

        if (elapsed_minutes < 1)
                return;

        /* Collect all of the sources to emit into a list and mark
         * them as busy. That way if they are removed they will just
         * be marked as removed instead of actually modifying the
         * bucket’s list. That way any timers can be removed as a
         * result of invoking any callback.
         */
        struct ntb_list to_emit;
        ntb_list_init(&to_emit);

        ntb_list_for_each(bucket, &mc->buckets, link) {
                if (bucket->minutes_passed + elapsed_minutes >=
                    bucket->minutes) {
                        ntb_list_insert_list(&to_emit, &bucket->sources);
                        bucket->minutes_passed = 0;
                        ntb_list_init(&bucket->sources);
                } else {
                        bucket->minutes_passed += elapsed_minutes;
                }
        }

        struct ntb_main_context_source *source, *tmp_source;

        ntb_list_for_each(source, &to_emit, link) {
                source->busy = true;
        }

        ntb_list_for_each(source, &to_emit, link) {
                if (source->removed)
                        continue;
                ntb_main_context_timer_callback callback = source->callback;
                callback(source, source->user_data);
        }

        ntb_list_for_each_safe(source, tmp_source, &to_emit, link) {
                if (source->removed) {
                        free_source(mc, source);
                }
        }
        ntb_list_for_each_safe(source, tmp_source, &to_emit, link) {
                ntb_list_insert(&source->bucket->sources,
                                &source->link);
                source->busy = false;
        }
}

static void
emit_idle_sources(struct ntb_main_context *mc)
{
        struct ntb_main_context_source *source, *tmp_source;
        ntb_main_context_timer_callback callback;

        pthread_mutex_lock(&mc->idle_mutex);

        /* This loop needs to cope with sources being added from other
         * threads while iterating. It doesn't need to cope with
         * sources being removed, apart from the one currently being
         * executed. Any new sources would be added at the beginning
         * of the list so they shouldn't cause any problems and they
         * would just be missed by this loop */

        ntb_list_for_each_safe(source, tmp_source,
                               &mc->idle_sources,
                               link) {
                callback = source->callback;

                pthread_mutex_unlock(&mc->idle_mutex);
                callback(source, source->user_data);
                pthread_mutex_lock(&mc->idle_mutex);
        }

        pthread_mutex_unlock(&mc->idle_mutex);
}

static struct ntb_main_context_source *
get_source_for_fd(struct ntb_main_context *mc,
                  int fd)
{
        struct ntb_main_context_source *source;

        ntb_list_for_each(source, &mc->poll_sources, link) {
                if (source->fd == fd)
                        return source;
        }

        ntb_fatal("Poll result found for unknown fd");
}

static void
handle_poll_result(struct ntb_main_context *mc,
                   const struct pollfd *pollfd)
{
        struct ntb_main_context_source *source;
        ntb_main_context_poll_callback callback;
        enum ntb_main_context_poll_flags flags;

        if (pollfd->revents == 0)
                return;

        source = get_source_for_fd(mc, pollfd->fd);

        callback = source->callback;
        flags = 0;

        if (pollfd->revents & POLLOUT)
                flags |= NTB_MAIN_CONTEXT_POLL_OUT;
        if (pollfd->revents & POLLIN)
                flags |= NTB_MAIN_CONTEXT_POLL_IN;
        if (pollfd->revents & POLLHUP) {
                /* If the source is polling for read then we'll
                 * just mark it as ready for reading so that any
                 * error or EOF will be handled by the read call
                 * instead of immediately aborting */
                if ((source->current_flags & NTB_MAIN_CONTEXT_POLL_IN))
                        flags |= NTB_MAIN_CONTEXT_POLL_IN;
                else
                        flags |= NTB_MAIN_CONTEXT_POLL_ERROR;
        }
        if (pollfd->revents & POLLERR)
                flags |= NTB_MAIN_CONTEXT_POLL_ERROR;

        callback(source, source->fd, flags, source->user_data);
}

static short int
get_poll_events(enum ntb_main_context_poll_flags flags)
{
        short int events = 0;

        if (flags & NTB_MAIN_CONTEXT_POLL_IN)
                events |= POLLIN;
        if (flags & NTB_MAIN_CONTEXT_POLL_OUT)
                events |= POLLOUT;

        return events;
}

static void
ensure_poll_array(struct ntb_main_context *mc)
{
        struct ntb_main_context_source *source;
        struct pollfd *pollfd;

        if (!mc->poll_array_dirty)
                return;

        mc->poll_array.length = 0;

        ntb_list_for_each(source, &mc->poll_sources, link) {
                ntb_buffer_set_length(&mc->poll_array,
                                      mc->poll_array.length +
                                      sizeof (struct pollfd));
                pollfd = (struct pollfd *) (mc->poll_array.data +
                                            mc->poll_array.length -
                                            sizeof (struct pollfd));
                pollfd->fd = source->fd;
                pollfd->events = get_poll_events(source->current_flags);
        }

        mc->poll_array_dirty = false;
}

void
ntb_main_context_poll(struct ntb_main_context *mc)
{
        int n_events;

        if (mc == NULL)
                mc = ntb_main_context_get_default();

        ensure_poll_array(mc);

        n_events = poll((struct pollfd *) mc->poll_array.data,
                        mc->poll_array.length / sizeof (struct pollfd),
                        get_timeout(mc));

        /* Once we've polled we can assume that some time has passed so our
           cached values of the clocks are no longer valid */
        mc->monotonic_time_valid = false;
        mc->wall_time_valid = false;

        if (n_events == -1) {
                if (errno != EINTR)
                        ntb_warning("poll failed: %s", strerror(errno));
        } else {
                struct pollfd *pollfds = (struct pollfd *) mc->poll_array.data;
                int i;

                for (i = 0; i < mc->poll_array.length / sizeof *pollfds; i++)
                        handle_poll_result(mc, pollfds + i);

                check_timer_sources(mc);
                emit_idle_sources(mc);
        }
}

uint64_t
ntb_main_context_get_monotonic_clock(struct ntb_main_context *mc)
{
        struct timespec ts;

        if (mc == NULL)
                mc = ntb_main_context_get_default();

        /* Because in theory the program doesn't block between calls
           to poll, we can act as if no time passes between calls.
           That way we can cache the clock value instead of having to
           do a system call every time we need it */
        if (!mc->monotonic_time_valid) {
                clock_gettime(CLOCK_MONOTONIC, &ts);
                mc->monotonic_time = (ts.tv_sec * UINT64_C(1000000) +
                                      ts.tv_nsec / UINT64_C(1000));
                mc->monotonic_time_valid = true;
        }

        return mc->monotonic_time;
}

int64_t
ntb_main_context_get_wall_clock(struct ntb_main_context *mc)
{
        time_t now;

        if (mc == NULL)
                mc = ntb_main_context_get_default();

        /* Because in theory the program doesn't block between calls
           to poll, we can act as if no time passes between calls.
           That way we can cache the clock value instead of having to
           do a system call every time we need it */
        if (!mc->wall_time_valid) {
                time(&now);

                mc->wall_time = now;
                mc->wall_time_valid = true;
        }

        return mc->wall_time;
}

static void
free_buckets(struct ntb_main_context *mc)
{
        struct ntb_main_context_bucket *bucket, *tmp;

        ntb_list_for_each_safe(bucket, tmp, &mc->buckets, link) {
                assert(ntb_list_empty(&bucket->sources));
                ntb_slice_free(&ntb_main_context_bucket_allocator, bucket);
        }
}

void
ntb_main_context_free(struct ntb_main_context *mc)
{
        ntb_return_if_fail(mc != NULL);

        signal(SIGINT, mc->old_int_handler);
        signal(SIGTERM, mc->old_term_handler);
        ntb_main_context_remove_source(mc->async_pipe_source);
        ntb_close(mc->async_pipe[0]);
        ntb_close(mc->async_pipe[1]);

        assert(ntb_list_empty(&mc->quit_sources));
        assert(ntb_list_empty(&mc->idle_sources));
        assert(ntb_list_empty(&mc->poll_sources));

        free_buckets(mc);

        pthread_mutex_destroy(&mc->idle_mutex);

        ntb_buffer_destroy(&mc->poll_array);

        ntb_slice_allocator_destroy(&mc->source_allocator);

        ntb_free(mc);

        if (mc == ntb_main_context_default)
                ntb_main_context_default = NULL;
}
