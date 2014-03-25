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

#ifndef NTB_POW_H
#define NTB_POW_H

#include <stdint.h>
#include <stdbool.h>

#include "ntb-error.h"

struct ntb_pow;

struct ntb_pow_cookie;

typedef void (* ntb_pow_calculate_func)(uint64_t nonce,
                                        void *user_data);

struct ntb_pow *
ntb_pow_new(void);

struct ntb_pow_cookie *
ntb_pow_calculate(struct ntb_pow *pow,
                  const uint8_t *payload,
                  size_t length,
                  int pow_per_byte,
                  int pow_extra_bytes,
                  ntb_pow_calculate_func func,
                  void *user_data);

void
ntb_pow_cancel(struct ntb_pow_cookie *cookie);

void
ntb_pow_free(struct ntb_pow *pow);

bool
ntb_pow_check(const uint8_t *payload,
              size_t length,
              int pow_per_byte,
              int pow_extra_bytes);

#endif /* NTB_POW_H */
