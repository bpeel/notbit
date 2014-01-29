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
