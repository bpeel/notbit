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

#ifndef NTB_IPC_PROTO_H
#define NTB_IPC_PROTO_H

#include "ntb-buffer.h"

enum ntb_ipc_proto_status {
        NTB_IPC_PROTO_STATUS_SUCCESS = 0,
        NTB_IPC_PROTO_STATUS_GENERIC_ERROR,
        NTB_IPC_PROTO_STATUS_INVALID_COMMAND,
        NTB_IPC_PROTO_STATUS_FD_ERROR,
        NTB_IPC_PROTO_STATUS_INVALID_EMAIL,
        NTB_IPC_PROTO_STATUS_UNKNOWN_FROM_ADDRESS,
        NTB_IPC_PROTO_STATUS_UNSUPPORTED
};

void
ntb_ipc_proto_begin_command(struct ntb_buffer *buffer,
                            const char *name,
                            uint32_t request_id);

void
ntb_ipc_proto_end_command(struct ntb_buffer *buffer,
                          size_t command_start);

#endif /* NTB_IPC_PROTO_H */
