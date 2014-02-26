/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2014  Neil Roberts
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

#include "config.h"

#include <string.h>

#include "ntb-ipc-proto.h"
#include "ntb-buffer.h"

void
ntb_ipc_proto_begin_command(struct ntb_buffer *buffer,
                            const char *name,
                            uint32_t request_id)
{
        int name_length = strlen(name);
        int i;

        ntb_buffer_append(buffer, name, name_length);
        for (i = name_length; i < 12; i++)
                ntb_buffer_append_c(buffer, '\0');

        request_id = NTB_UINT32_TO_BE(request_id);
        ntb_buffer_append(buffer, &request_id, sizeof request_id);

        /* Reserve space for the length */
        ntb_buffer_set_length(buffer, buffer->length + 4);
}

void
ntb_ipc_proto_end_command(struct ntb_buffer *buffer,
                          size_t command_start)
{
        uint32_t command_length;

        command_length = buffer->length - command_start - 20;
        command_length = NTB_UINT32_TO_BE(command_length);

        memcpy(buffer->data + command_start + 16,
               &command_length,
               sizeof command_length);
}
