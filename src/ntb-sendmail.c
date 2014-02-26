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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "ntb-sendmail.h"
#include "ntb-util.h"
#include "ntb-ipc-client.h"
#include "ntb-buffer.h"
#include "ntb-proto.h"

static const uint8_t
email_command[] =
        "email\0\0\0\0\0\0\0" /* command name */
        "\0\0\0\0" /* request id */
        "\0\0\0\0"; /* payload length */

static bool
send_email_command(int sock,
                   struct ntb_error **error)
{
        int fd = STDIN_FILENO;

        return ntb_ipc_client_send_command(sock,
                                           email_command,
                                           sizeof email_command - 1,
                                           &fd,
                                           1, /* n_fds */
                                           error);
}

int
ntb_sendmail(int argc, char **argv)
{
        struct ntb_error *error = NULL;
        struct ntb_buffer response_buf;
        int ret = EXIT_SUCCESS;
        int sock;

        sock = ntb_ipc_client_connect(&error);

        if (sock == -1) {
                fprintf(stderr, "%s\n", error->message);
                ntb_error_free(error);
                return EXIT_FAILURE;
        }

        if (send_email_command(sock, &error)) {
                ntb_buffer_init(&response_buf);
                if (!ntb_ipc_client_get_response(sock,
                                                 &response_buf,
                                                 &error,
                                                 0 /* request_id */)) {
                        fprintf(stderr, "%s\n", error->message);
                        ntb_error_free(error);
                        ret = EXIT_FAILURE;
                }
                ntb_buffer_destroy(&response_buf);
        } else {
                fprintf(stderr, "%s\n", error->message);
                ntb_error_free(error);
                ret = EXIT_FAILURE;
        }

        close(sock);

        return ret;
}
