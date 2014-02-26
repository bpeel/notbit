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

#ifndef NTB_MAIN_CONTEXT_H
#define NTB_MAIN_CONTEXT_H

#include <stdint.h>

#include "ntb-util.h"
#include "ntb-error.h"

enum ntb_main_context_error {
        NTB_MAIN_CONTEXT_ERROR_UNSUPPORTED,
        NTB_MAIN_CONTEXT_ERROR_UNKNOWN
};

enum ntb_main_context_poll_flags {
        NTB_MAIN_CONTEXT_POLL_IN = 1 << 0,
        NTB_MAIN_CONTEXT_POLL_OUT = 1 << 1,
        NTB_MAIN_CONTEXT_POLL_ERROR = 1 << 2,
};

extern struct ntb_error_domain
ntb_main_context_error;

struct ntb_main_context;
struct ntb_main_context_source;

typedef void
(* ntb_main_context_poll_callback) (struct ntb_main_context_source *source,
                                    int fd,
                                    enum ntb_main_context_poll_flags flags,
                                    void *user_data);

typedef void
(* ntb_main_context_timer_callback) (struct ntb_main_context_source *source,
                                     void *user_data);

typedef void
(* ntb_main_context_idle_callback) (struct ntb_main_context_source *source,
                                    void *user_data);

typedef void
(* ntb_main_context_quit_callback) (struct ntb_main_context_source *source,
                                    void *user_data);

struct ntb_main_context *
ntb_main_context_new(void);

struct ntb_main_context *
ntb_main_context_get_default(void);

struct ntb_main_context_source *
ntb_main_context_add_poll(struct ntb_main_context *mc,
                          int fd,
                          enum ntb_main_context_poll_flags flags,
                          ntb_main_context_poll_callback callback,
                          void *user_data);

void
ntb_main_context_modify_poll(struct ntb_main_context_source *source,
                             enum ntb_main_context_poll_flags flags);

struct ntb_main_context_source *
ntb_main_context_add_quit(struct ntb_main_context *mc,
                          ntb_main_context_quit_callback callback,
                          void *user_data);

struct ntb_main_context_source *
ntb_main_context_add_timer(struct ntb_main_context *mc,
                           int minutes,
                           ntb_main_context_timer_callback callback,
                           void *user_data);

struct ntb_main_context_source *
ntb_main_context_add_idle(struct ntb_main_context *mc,
                          ntb_main_context_idle_callback callback,
                          void *user_data);

void
ntb_main_context_remove_source(struct ntb_main_context_source *source);

void
ntb_main_context_poll(struct ntb_main_context *mc);

uint64_t
ntb_main_context_get_monotonic_clock(struct ntb_main_context *mc);

int64_t
ntb_main_context_get_wall_clock(struct ntb_main_context *mc);

void
ntb_main_context_free(struct ntb_main_context *mc);

#endif /* NTB_MAIN_CONTEXT_H */
