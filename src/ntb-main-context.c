/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2011, 2013  Neil Roberts
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

#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>

#include "ntb-main-context.h"
#include "ntb-list.h"
#include "ntb-util.h"
#include "ntb-slice.h"

/* This is a simple replacement for the GMainLoop which uses
   epoll. The hope is that it will scale to more connections easily
   because it doesn't use poll which needs to upload the set of file
   descriptors every time it blocks and it doesn't have to walk the
   list of file descriptors to find out which object it belongs to */

struct ntb_error_domain
ntb_main_context_error;

struct ntb_main_context_bucket;

struct ntb_main_context {
        /* This mutex only guards access to n_sources, the
         * idle_sources list and the slice allocator so that idle
         * sources can be added from other threads. Everything else
         * should only be accessed from the main thread so it doesn't
         * need to guarded. Removing an idle source can only happen in
         * the main thread. That is necessary because it is difficult
         * to cope with random idle sources being removed while we are
         * iterating the list */
        pthread_mutex_t idle_mutex;

        int epoll_fd;
        /* Number of sources that are currently attached. This is used so we
           can size the array passed to epoll_wait to ensure it's possible
           to process an event for every single source */
        unsigned int n_sources;
        /* Array for receiving events */
        unsigned int events_size;
        struct epoll_event *events;

        /* List of quit sources. All of these get invoked when a quit signal
           is received */
        struct ntb_list quit_sources;

        struct ntb_list idle_sources;

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

                /* Quit sources */
                struct {
                        struct ntb_list quit_link;
                };

                /* Idle sources */
                struct {
                        struct ntb_list idle_link;
                };

                /* Timer sources */
                struct {
                        struct ntb_main_context_bucket *bucket;
                        struct ntb_list timer_link;
                };
        };

        void *user_data;
        void *callback;

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
ntb_main_context_get_default(struct ntb_error **error)
{
        if (ntb_main_context_default == NULL)
                ntb_main_context_default = ntb_main_context_new(error);

        return ntb_main_context_default;
}

static struct ntb_main_context *
ntb_main_context_get_default_or_abort(void)
{
        struct ntb_main_context *mc;
        struct ntb_error *error = NULL;

        mc = ntb_main_context_get_default(&error);

        if (mc == NULL)
                ntb_fatal("failed to create default main context: %s\n",
                          error->message);

        return mc;
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
                ntb_list_for_each(quit_source, &mc->quit_sources, quit_link) {
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
        struct ntb_main_context *mc = ntb_main_context_get_default_or_abort();

        send_async_byte(mc, 'Q');
}

static void
init_main_context(struct ntb_main_context *mc,
                  int fd)
{
        pthread_mutex_init(&mc->idle_mutex, NULL /* attrs */);
        ntb_slice_allocator_init(&mc->source_allocator,
                                 sizeof(struct ntb_main_context_source),
                                 NTB_ALIGNOF(struct ntb_main_context_source));
        mc->epoll_fd = fd;
        mc->n_sources = 0;
        mc->events = NULL;
        mc->events_size = 0;
        mc->monotonic_time_valid = false;
        mc->wall_time_valid = false;
        ntb_list_init(&mc->quit_sources);
        ntb_list_init(&mc->idle_sources);
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
}

struct ntb_main_context *
ntb_main_context_new(struct ntb_error **error)
{
        int fd;

        fd = epoll_create(16);

        if (fd == -1) {
                if (errno == EINVAL)
                        ntb_set_error(error,
                                      &ntb_main_context_error,
                                      NTB_MAIN_CONTEXT_ERROR_UNSUPPORTED,
                                      "epoll is unsupported on this system");
                else
                        ntb_set_error(error,
                                      &ntb_main_context_error,
                                      NTB_MAIN_CONTEXT_ERROR_UNKNOWN,
                                      "failed to create an "
                                      "epoll descriptor: %s",
                                      strerror(errno));

                return NULL;
        } else {
                struct ntb_main_context *mc = ntb_alloc(sizeof *mc);

                init_main_context(mc, fd);

                return mc;
        }
}

static uint32_t
get_epoll_events(enum ntb_main_context_poll_flags flags)
{
        uint32_t events = 0;

        if (flags & NTB_MAIN_CONTEXT_POLL_IN)
                events |= EPOLLIN | EPOLLRDHUP;
        if (flags & NTB_MAIN_CONTEXT_POLL_OUT)
                events |= EPOLLOUT;

        return events;
}

struct ntb_main_context_source *
ntb_main_context_add_poll(struct ntb_main_context *mc,
                          int fd,
                          enum ntb_main_context_poll_flags flags,
                          ntb_main_context_poll_callback callback,
                          void *user_data)
{
        struct ntb_main_context_source *source;
        struct epoll_event event;

        if (mc == NULL)
                mc = ntb_main_context_get_default_or_abort();

        pthread_mutex_lock(&mc->idle_mutex);
        source = ntb_slice_alloc(&mc->source_allocator);
        mc->n_sources++;
        pthread_mutex_unlock(&mc->idle_mutex);

        source->mc = mc;
        source->fd = fd;
        source->callback = callback;
        source->type = NTB_MAIN_CONTEXT_POLL_SOURCE;
        source->user_data = user_data;

        event.events = get_epoll_events(flags);
        event.data.ptr = source;

        if (epoll_ctl(mc->epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1)
                ntb_warning("EPOLL_CTL_ADD failed: %s", strerror(errno));

        source->current_flags = flags;

        return source;
}

void
ntb_main_context_modify_poll(struct ntb_main_context_source *source,
                             enum ntb_main_context_poll_flags flags)
{
        struct epoll_event event;

        ntb_return_if_fail(source->type == NTB_MAIN_CONTEXT_POLL_SOURCE);

        if (source->current_flags == flags)
                return;

        event.events = get_epoll_events(flags);
        event.data.ptr = source;

        if (epoll_ctl(source->mc->epoll_fd,
                      EPOLL_CTL_MOD,
                      source->fd,
                      &event) == -1)
                ntb_warning("EPOLL_CTL_MOD failed: %s", strerror(errno));

        source->current_flags = flags;
}

struct ntb_main_context_source *
ntb_main_context_add_quit(struct ntb_main_context *mc,
                          ntb_main_context_quit_callback callback,
                          void *user_data)
{
        struct ntb_main_context_source *source;

        if (mc == NULL)
                mc = ntb_main_context_get_default_or_abort();

        pthread_mutex_lock(&mc->idle_mutex);
        source = ntb_slice_alloc(&mc->source_allocator);
        mc->n_sources++;
        pthread_mutex_unlock(&mc->idle_mutex);

        source->mc = mc;
        source->callback = callback;
        source->type = NTB_MAIN_CONTEXT_QUIT_SOURCE;
        source->user_data = user_data;

        ntb_list_insert(&mc->quit_sources, &source->quit_link);

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
                mc = ntb_main_context_get_default_or_abort();

        pthread_mutex_lock(&mc->idle_mutex);
        source = ntb_slice_alloc(&mc->source_allocator);
        mc->n_sources++;
        pthread_mutex_unlock(&mc->idle_mutex);

        source->mc = mc;
        source->bucket = get_bucket(mc, minutes);
        source->callback = callback;
        source->type = NTB_MAIN_CONTEXT_TIMER_SOURCE;
        source->user_data = user_data;

        ntb_list_insert(&source->bucket->sources, &source->timer_link);

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
                mc = ntb_main_context_get_default_or_abort();

        /* This may be called from a thread other than the main one so
         * we need to guard access to the idle sources lists */
        pthread_mutex_lock(&mc->idle_mutex);
        source = ntb_slice_alloc(&mc->source_allocator);
        ntb_list_insert(&mc->idle_sources, &source->idle_link);
        mc->n_sources++;
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
        struct ntb_main_context_bucket *bucket;
        struct epoll_event event;

        switch (source->type) {
        case NTB_MAIN_CONTEXT_POLL_SOURCE:
                if (epoll_ctl(mc->epoll_fd,
                              EPOLL_CTL_DEL,
                              source->fd,
                              &event) == -1)
                        ntb_warning("EPOLL_CTL_DEL failed: %s",
                                    strerror(errno));
                break;

        case NTB_MAIN_CONTEXT_QUIT_SOURCE:
                ntb_list_remove(&source->quit_link);
                break;

        case NTB_MAIN_CONTEXT_IDLE_SOURCE:
                pthread_mutex_lock(&mc->idle_mutex);
                ntb_list_remove(&source->idle_link);
                pthread_mutex_unlock(&mc->idle_mutex);
                break;

        case NTB_MAIN_CONTEXT_TIMER_SOURCE:
                bucket = source->bucket;
                ntb_list_remove(&source->timer_link);

                if (ntb_list_empty(&bucket->sources)) {
                        ntb_list_remove(&bucket->link);
                        ntb_slice_free(&ntb_main_context_bucket_allocator,
                                       bucket);
                }
                break;
        }

        pthread_mutex_lock(&mc->idle_mutex);
        ntb_slice_free(&mc->source_allocator, source);
        mc->n_sources--;
        pthread_mutex_unlock(&mc->idle_mutex);
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
emit_bucket(struct ntb_main_context_bucket *bucket)
{
        struct ntb_main_context_source *source, *tmp_source;
        ntb_main_context_timer_callback callback;

        ntb_list_for_each_safe(source,
                               tmp_source,
                               &bucket->sources,
                               timer_link) {
                callback = source->callback;
                callback(source, source->user_data);
        }

        bucket->minutes_passed = 0;
}

static void
check_timer_sources(struct ntb_main_context *mc)
{
        struct ntb_main_context_bucket *bucket, *tmp_bucket;
        int64_t now;
        int64_t elapsed_minutes;

        if (ntb_list_empty(&mc->buckets))
                return;

        now = ntb_main_context_get_monotonic_clock(mc);
        elapsed_minutes = (now - mc->last_timer_time) / 60000000;
        mc->last_timer_time += elapsed_minutes * 60000000;

        if (elapsed_minutes < 1)
                return;

        ntb_list_for_each_safe(bucket, tmp_bucket, &mc->buckets, link) {
                if (bucket->minutes_passed + elapsed_minutes >= bucket->minutes)
                        emit_bucket(bucket);
                else
                        bucket->minutes_passed += elapsed_minutes;
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
                               idle_link) {
                callback = source->callback;

                pthread_mutex_unlock(&mc->idle_mutex);
                callback(source, source->user_data);
                pthread_mutex_lock(&mc->idle_mutex);
        }

        pthread_mutex_unlock(&mc->idle_mutex);
}

static void
handle_epoll_event(struct ntb_main_context *mc,
                   struct epoll_event *event)
{
        struct ntb_main_context_source *source = source = event->data.ptr;
        ntb_main_context_poll_callback callback;
        enum ntb_main_context_poll_flags flags;

        switch (source->type) {
        case NTB_MAIN_CONTEXT_POLL_SOURCE:
                callback = source->callback;
                flags = 0;

                if (event->events & EPOLLOUT)
                        flags |= NTB_MAIN_CONTEXT_POLL_OUT;
                if (event->events & (EPOLLIN | EPOLLRDHUP))
                        flags |= NTB_MAIN_CONTEXT_POLL_IN;
                if (event->events & EPOLLHUP) {
                        /* If the source is polling for read then we'll
                         * just mark it as ready for reading so that any
                         * error or EOF will be handled by the read call
                         * instead of immediately aborting */
                        if ((source->current_flags & NTB_MAIN_CONTEXT_POLL_IN))
                                flags |= NTB_MAIN_CONTEXT_POLL_IN;
                        else
                                flags |= NTB_MAIN_CONTEXT_POLL_ERROR;
                }
                if (event->events & EPOLLERR)
                        flags |= NTB_MAIN_CONTEXT_POLL_ERROR;

                callback(source, source->fd, flags, source->user_data);
                break;

        case NTB_MAIN_CONTEXT_QUIT_SOURCE:
        case NTB_MAIN_CONTEXT_TIMER_SOURCE:
        case NTB_MAIN_CONTEXT_IDLE_SOURCE:
                ntb_warn_if_reached();
                break;
        }
}

void
ntb_main_context_poll(struct ntb_main_context *mc)
{
        int n_events;
        int n_sources;

        if (mc == NULL)
                mc = ntb_main_context_get_default_or_abort();

        pthread_mutex_lock(&mc->idle_mutex);
        n_sources = mc->n_sources;
        pthread_mutex_unlock(&mc->idle_mutex);

        if (n_sources > mc->events_size) {
                ntb_free(mc->events);
                mc->events = ntb_alloc(sizeof (struct epoll_event) *
                                       n_sources);
                mc->events_size = n_sources;
        }

        n_events = epoll_wait(mc->epoll_fd,
                              mc->events,
                              mc->events_size,
                              get_timeout(mc));

        /* Once we've polled we can assume that some time has passed so our
           cached values of the clocks are no longer valid */
        mc->monotonic_time_valid = false;
        mc->wall_time_valid = false;

        if (n_events == -1) {
                if (errno != EINTR)
                        ntb_warning("epoll_wait failed: %s", strerror(errno));
        } else {
                int i;

                for (i = 0; i < n_events; i++)
                        handle_epoll_event(mc, mc->events + i);

                check_timer_sources(mc);
                emit_idle_sources(mc);
        }
}

uint64_t
ntb_main_context_get_monotonic_clock(struct ntb_main_context *mc)
{
        struct timespec ts;

        if (mc == NULL)
                mc = ntb_main_context_get_default_or_abort();

        /* Because in theory the program doesn't block between calls to
           poll, we can act as if no time passes between calls to
           epoll. That way we can cache the clock value instead of having to
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
                mc = ntb_main_context_get_default_or_abort();

        /* Because in theory the program doesn't block between calls to
           poll, we can act as if no time passes between calls to
           epoll. That way we can cache the clock value instead of having to
           do a system call every time we need it */
        if (!mc->wall_time_valid) {
                time(&now);

                mc->wall_time = now;
                mc->wall_time_valid = true;
        }

        return mc->wall_time;
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

        if (mc->n_sources > 0)
                ntb_warning("Sources still remain on a main context "
                            "that is being freed");

        ntb_free(mc->events);
        pthread_mutex_destroy(&mc->idle_mutex);
        ntb_close(mc->epoll_fd);

        ntb_slice_allocator_destroy(&mc->source_allocator);

        ntb_free(mc);

        if (mc == ntb_main_context_default)
                ntb_main_context_default = NULL;
}
