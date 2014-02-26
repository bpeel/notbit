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

#ifndef NTB_IPC_CLIENT_H
#define NTB_IPC_CLIENT_H

#include <stdbool.h>

#include "ntb-error.h"
#include "ntb-buffer.h"

extern struct ntb_error_domain
ntb_ipc_client_error;

enum ntb_ipc_client_error {
        NTB_IPC_CLIENT_ERROR_INVALID_DATA,
        NTB_IPC_CLIENT_ERROR_INVALID_RESPONSE,
        NTB_IPC_CLIENT_ERROR_COMMAND_FAILED,
        NTB_IPC_CLIENT_ERROR_NO_RESPONSE
};

int
ntb_ipc_client_connect(struct ntb_error **error);

bool
ntb_ipc_client_send_command(int sock,
                            const uint8_t *data,
                            size_t data_length,
                            const int *fds,
                            size_t n_fds,
                            struct ntb_error **error);

bool
ntb_ipc_client_get_response(int sock,
                            struct ntb_buffer *response_buf,
                            struct ntb_error **error,
                            uint32_t request_id);

#endif /* NTB_IPC_CLIENT_H */
