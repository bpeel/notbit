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
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>

#include "ntb-sendmail.h"
#include "ntb-util.h"
#include "ntb-ipc-sockaddr.h"
#include "ntb-file-error.h"
#include "ntb-buffer.h"
#include "ntb-proto.h"

struct response_state {
        struct ntb_buffer buf;
        int exit_status;
        bool had_response;
};

static const uint8_t
email_command[] =
        "email\0\0\0\0\0\0\0" /* command name */
        "\0\0\0\0" /* request id */
        "\0\0\0\0"; /* payload length */

static int
ipc_connect(struct ntb_error **error)
{
        struct sockaddr *sockaddr;
        socklen_t sockaddr_len;
        int sock, res;

        if (!ntb_ipc_sockaddr_create(&sockaddr, &sockaddr_len, error))
                return -1;

        sock = socket(PF_LOCAL, SOCK_STREAM, 0);

        if (sock == -1) {
                ntb_file_error_set(error,
                                   errno,
                                   "Failed to create socket: %s",
                                   strerror(errno));
                return -1;
        }

        res = connect(sock, sockaddr, sockaddr_len);

        if (res == -1) {
                ntb_file_error_set(error,
                                   errno,
                                   "%s",
                                   strerror(errno));
                close(sock);
                return -1;
        }

        return sock;
}

static bool
send_email_command(int sock)
{
        struct msghdr msg;
        struct iovec iov;
        const uint8_t *tosend;
        size_t send_len;
        int sent;
        struct cmsghdr *cmsg;
        int *fd;
        uint8_t control_buf[CMSG_SPACE(sizeof (int))];

        msg.msg_control = control_buf;
        msg.msg_controllen = sizeof control_buf;

        cmsg = (struct cmsghdr *) control_buf;
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof (int));
        fd = (int *) CMSG_DATA(cmsg);
        *fd = STDIN_FILENO;

        tosend = email_command;
        send_len = sizeof email_command - 1;

        while (send_len > 0) {
                iov.iov_base = (void *) tosend;
                iov.iov_len = send_len;

                msg.msg_name = NULL;
                msg.msg_namelen = 0;
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;
                msg.msg_flags = 0;

                if (tosend > email_command) {
                        msg.msg_control = NULL;
                        msg.msg_controllen = 0;
                } else {
                        msg.msg_control = control_buf;
                        msg.msg_controllen = sizeof control_buf;
                }

                sent = sendmsg(sock, &msg, 0 /* flags */);

                if (sent == -1) {
                        if (errno != EINTR)
                                goto error;
                } else {
                        tosend += sent;
                        send_len -= sent;
                }
        }

        /* We only want to send one command so we can already close
         * the writing end of the socket */
        if (shutdown(sock, SHUT_WR) == -1)
                goto error;

        return true;

error:
        fprintf(stderr,
                "Error sending email command: %s\n",
                strerror(errno));
        return false;
}

static void
init_response_state(struct response_state *state)
{
        ntb_buffer_init(&state->buf);
        state->exit_status = EXIT_SUCCESS;
        state->had_response = false;
}

static void
destroy_response_state(struct response_state *state)
{
        ntb_buffer_destroy(&state->buf);
}

static uint32_t
get_32(const uint8_t *data)
{
        uint32_t value;

        memcpy(&value, data, sizeof value);

        return NTB_UINT32_FROM_BE(value);
}

static bool
handle_response(struct response_state *state,
                const uint8_t *data,
                size_t data_length)
{
        uint32_t status;

        if (data_length < 4 || state->had_response) {
                fprintf(stderr,
                        "Invalid response command received from "
                        "IPC connection\n");
                state->exit_status = EXIT_FAILURE;
                return false;
        }

        status = get_32(data);

        if (status != 0) {
                fprintf(stderr, "email command failed: ");
                fwrite(data + 4, 1, data_length - 4, stderr);
                fputc('\n', stderr);
                state->exit_status = EXIT_FAILURE;
                /* The data wasn't invalid so we can return true and
                 * continue reading any subsequent commands */
        }

        state->had_response = true;

        return true;
}

static bool
process_commands(struct response_state *state,
                 int sock)
{
        const uint8_t *data = state->buf.data;
        size_t data_length = state->buf.length;
        uint32_t command_length, request_id;

        while (true) {
                if (data_length < 20)
                        break;

                command_length = get_32(data + 16);

                if (data_length < command_length + 20)
                        break;

                if (!memchr(data, '\0', 12)) {
                        fprintf(stderr,
                                "Invalid data received from IPC connection\n");
                        state->exit_status = EXIT_FAILURE;
                        return false;
                }

                request_id = get_32(data + 12);

                if (!strcmp((const char *) data, "response") &&
                    request_id == 0 &&
                    !handle_response(state, data + 20, command_length)) {
                        return false;
                }

                data += 20 + command_length;
                data_length -= 20 + command_length;
        }

        memmove(state->buf.data, data, data_length);
        state->buf.length = data_length;

        return true;
}

static void
read_commands(struct response_state *state,
              int sock)
{
        ssize_t got;

        while (true) {
                ntb_buffer_ensure_size(&state->buf, state->buf.length + 512);

                got = read(sock,
                           state->buf.data + state->buf.length,
                           state->buf.size - state->buf.length);

                if (got == -1) {
                        fprintf(stderr, "Error reading from IPC socket: %s\n",
                                strerror(errno));
                        state->exit_status = EXIT_FAILURE;
                        break;
                } else if (got == 0) {
                        if (state->buf.length > 0) {
                                fprintf(stderr,
                                        "Invalid data received from "
                                        "IPC socket: %s\n",
                                        strerror(errno));
                                state->exit_status = EXIT_FAILURE;
                        }
                        break;
                } else {
                        state->buf.length += got;
                        if (!process_commands(state, sock))
                                break;
                }
        }

        if (state->exit_status == EXIT_SUCCESS && !state->had_response) {
                fprintf(stderr,
                        "No response received from IPC socket\n");
                state->exit_status = EXIT_FAILURE;
        }
}

int
ntb_sendmail(int argc, char **argv)
{
        struct ntb_error *error = NULL;
        struct response_state response_state;
        int ret = EXIT_SUCCESS;
        int sock;

        sock = ipc_connect(&error);

        if (sock == -1) {
                fprintf(stderr,
                        "Failed to connect to the notbit daemon: %s\n",
                        error->message);
                ntb_error_free(error);
                return EXIT_FAILURE;
        }

        if (!send_email_command(sock)) {
                ret = EXIT_FAILURE;
        } else {
                init_response_state(&response_state);
                read_commands(&response_state, sock);
                ret = response_state.exit_status;
                destroy_response_state(&response_state);
        }

        close(sock);

        return ret;
}
