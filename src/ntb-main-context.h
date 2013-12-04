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
ntb_main_context_new(struct ntb_error **error);

struct ntb_main_context *
ntb_main_context_get_default(struct ntb_error **error);

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
