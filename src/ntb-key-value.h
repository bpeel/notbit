/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013, 2014  Neil Roberts
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
