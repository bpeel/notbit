/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2014  Neil Roberts
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
