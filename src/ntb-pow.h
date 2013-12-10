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
ntb_pow_new(struct ntb_error **error);

struct ntb_pow_cookie *
ntb_pow_calculate(struct ntb_pow *pow,
                  const uint8_t *payload,
                  size_t length,
                  int payload_extra_bytes,
                  int average_trials_per_byte,
                  ntb_pow_calculate_func func,
                  void *user_data);

void
ntb_pow_cancel(struct ntb_pow_cookie *cookie);

void
ntb_pow_free(struct ntb_pow *pow);

bool
ntb_pow_check(const uint8_t *payload,
              size_t length,
              int payload_extra_bytes,
              int average_trials_per_byte);

#endif /* NTB_POW_H */
