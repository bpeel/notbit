/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2011, 2014  Neil Roberts
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

#ifndef NTB_PARSE_CONTENT_TYPE_H
#define NTB_PARSE_CONTENT_TYPE_H

#include <stdbool.h>

typedef bool
(* ntb_parse_content_type_type_cb)(const char *type,
                                   void *user_data);

typedef bool
(* ntb_parse_content_type_attribute_cb)(const char *attribute,
                                        const char *value,
                                        void *user_data);

bool
ntb_parse_content_type(const char *header_value,
                       ntb_parse_content_type_type_cb type_cb,
                       ntb_parse_content_type_attribute_cb attribute_cb,
                       void *user_data);

#endif /* NTB_PARSE_CONTENT_TYPE_H */
