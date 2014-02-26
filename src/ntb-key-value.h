/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013, 2014  Neil Roberts
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

#ifndef NTB_KEY_VALUE_H
#define NTB_KEY_VALUE_H

#include <stdio.h>

#include "ntb-key.h"

enum ntb_key_value_event {
        NTB_KEY_VALUE_EVENT_HEADER,
        NTB_KEY_VALUE_EVENT_PROPERTY
};

typedef void
(* ntb_key_value_func)(enum ntb_key_value_event event,
                       int line_number,
                       const char *key,
                       const char *value,
                       void *user_data);

void
ntb_key_value_load(FILE *file,
                   ntb_key_value_func func,
                   void *user_data);

bool
ntb_key_value_parse_bool_value(int line_number,
                               const char *value,
                               bool *result);

bool
ntb_key_value_parse_int_value(int line_number,
                              const char *value_string,
                              int64_t max,
                              int64_t *result);

#endif /* NTB_KEY_VALUE_H */
