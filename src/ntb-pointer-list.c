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

#include "config.h"

#include "ntb-pointer-list.h"
#include "ntb-slice.h"

NTB_SLICE_ALLOCATOR(struct ntb_pointer_list,
                    ntb_pointer_list_allocator);

struct ntb_pointer_list *
ntb_pointer_list_new(void *data)
{
        struct ntb_pointer_list *list =
                ntb_slice_alloc(&ntb_pointer_list_allocator);

        list->data = data;

        return list;
}

void
ntb_pointer_list_insert(struct ntb_list *position,
                        void *data)
{
        struct ntb_pointer_list *list;

        list = ntb_pointer_list_new(data);

        ntb_list_insert(position, &list->link);
}

void
ntb_pointer_list_free(struct ntb_pointer_list *list)
{
        ntb_slice_free(&ntb_pointer_list_allocator, list);
}
