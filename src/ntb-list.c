/*
 * Copyright © 2008-2011 Kristian Høgsberg
 * Copyright © 2011, 2012, 2013 Intel Corporation
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

/* This list implementation is based on the Wayland source code */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "ntb-list.h"

void
ntb_list_init(struct ntb_list *list)
{
        list->prev = list;
        list->next = list;
}

void
ntb_list_insert(struct ntb_list *list, struct ntb_list *elm)
{
        elm->prev = list;
        elm->next = list->next;
        list->next = elm;
        elm->next->prev = elm;
}

void
ntb_list_remove(struct ntb_list *elm)
{
        elm->prev->next = elm->next;
        elm->next->prev = elm->prev;
        elm->next = NULL;
        elm->prev = NULL;
}

int
ntb_list_length(struct ntb_list *list)
{
        struct ntb_list *e;
        int count;

        count = 0;
        e = list->next;
        while (e != list) {
                e = e->next;
                count++;
        }

        return count;
}

int
ntb_list_empty(struct ntb_list *list)
{
        return list->next == list;
}

void
ntb_list_insert_list(struct ntb_list *list, struct ntb_list *other)
{
        if (ntb_list_empty(other))
                return;

        other->next->prev = list;
        other->prev->next = list->next;
        list->next->prev = other->prev;
        list->next = other->next;
}
