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

#ifndef NTB_POINTER_LIST_H
#define NTB_POINTER_LIST_H

#include "ntb-list.h"

/* The pointer list is used to make a linked list when you can't
 * really embedded the link in the target struct. The link nodes are
 * allocated using a shared slice allocator */

struct ntb_pointer_list {
        void *data;
        struct ntb_list link;
};

struct ntb_pointer_list *
ntb_pointer_list_new(void *data);

void
ntb_pointer_list_insert(struct ntb_list *position,
                        void *data);

void
ntb_pointer_list_free(struct ntb_pointer_list *list);

#endif /* NTB_POINTER_LIST_H */
