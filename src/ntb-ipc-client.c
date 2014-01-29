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
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

#include "ntb-ipc-client.h"
#include "ntb-ipc-sockaddr.h"
#include "ntb-file-error.h"
#include "ntb-proto.h"

struct ntb_error_domain
ntb_ipc_client_error;

struct response_state {
        struct ntb_buffer buf;
        struct ntb_buffer *response_buf;
        struct ntb_error *error;
        uint32_t request_id;
        bool had_response;
};

bool
ntb_ipc_client_send_command(int sock,
                            const uint8_t *data,
                            size_t data_length,
                            const int *fds,
                            size_t n_fds,
                            struct ntb_error **error)
{
        struct msghdr msg;
        struct iovec iov;
        const uint8_t *tosend;
        size_t send_len;
        int sent;
        struct cmsghdr *cmsg;
        uint8_t *control_buf;
        size_t control_buf_len;

        if (n_fds) {
                control_buf_len = CMSG_SPACE(sizeof (int) * n_fds);
                control_buf = alloca(control_buf_len);
                cmsg = (struct cmsghdr *) control_buf;
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(sizeof (int) * n_fds);
                memcpy(CMSG_DATA(cmsg), fds, n_fds * sizeof (int));
        } else {
                control_buf_len = 0;
                control_buf = NULL;
        }

        tosend = data;
        send_len = data_length;

        while (send_len > 0) {
                iov.iov_base = (void *) tosend;
                iov.iov_len = send_len;

                msg.msg_name = NULL;
                msg.msg_namelen = 0;
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;
                msg.msg_flags = 0;

                if (tosend > data) {
                        msg.msg_control = NULL;
                        msg.msg_controllen = 0;
                } else {
                        msg.msg_control = control_buf;
                        msg.msg_controllen = control_buf_len;
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
        ntb_file_error_set(error,
                           errno,
                           "Error sending IPC command: %s\n",
                           strerror(errno));
        return false;
}

int
ntb_ipc_client_connect(struct ntb_error **error)
{
        struct sockaddr *sockaddr;
        socklen_t sockaddr_len;
        int sock, res;

        sock = socket(PF_LOCAL, SOCK_STREAM, 0);

        if (sock == -1) {
                ntb_file_error_set(error,
                                   errno,
                                   "Failed to create socket: %s",
                                   strerror(errno));
                return -1;
        }

        if (!ntb_ipc_sockaddr_create(&sockaddr, &sockaddr_len, error))
                return -1;

        res = connect(sock, sockaddr, sockaddr_len);

        ntb_free(sockaddr);

        if (res == -1) {
                ntb_file_error_set(error,
                                   errno,
                                   "Error connecting to IPC socket: %s",
                                   strerror(errno));
                close(sock);
                return -1;
        }

        return sock;
}

static void
init_response_state(struct response_state *state,
                    struct ntb_buffer *response_buf,
                    uint32_t request_id)
{
        ntb_buffer_init(&state->buf);
        state->error = NULL;
        state->response_buf = response_buf;
        state->had_response = false;
        state->request_id = request_id;
}

static void
destroy_response_state(struct response_state *state)
{
        if (state->error)
                ntb_error_free(state->error);
        ntb_buffer_destroy(&state->buf);
}

static void
set_response_error(struct response_state *state,
                   struct ntb_error_domain *domain,
                   int code,
                   const char *format,
                   ...)
{
        va_list ap;

        if (state->error) {
                ntb_error_free(state->error);
                state->error = NULL;
        }

        va_start(ap, format);
        ntb_set_error_va_list(&state->error, domain, code, format, ap);
        va_end(ap);
}

static bool
handle_response(struct response_state *state,
                const uint8_t *data,
                size_t data_length)
{
        uint32_t status;

        if (data_length < 4 || state->had_response) {
                set_response_error(state,
                                   &ntb_ipc_client_error,
                                   NTB_IPC_CLIENT_ERROR_INVALID_RESPONSE,
                                   "Invalid response command received from "
                                   "IPC connection");
                return false;
        }

        status = ntb_proto_get_32(data);

        if (status != 0) {
                set_response_error(state,
                                   &ntb_ipc_client_error,
                                   NTB_IPC_CLIENT_ERROR_COMMAND_FAILED,
                                   "command failed: %*s",
                                   data_length - 4,
                                   data + 4);
                /* The data wasn't invalid so we can return true and
                 * continue reading any subsequent commands */
        }

        state->had_response = true;

        ntb_buffer_append(state->response_buf, data + 4, data_length - 4);

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

                command_length = ntb_proto_get_32(data + 16);

                if (data_length < command_length + 20)
                        break;

                if (!ntb_proto_check_command_string(data)) {
                        set_response_error(state,
                                           &ntb_ipc_client_error,
                                           NTB_IPC_CLIENT_ERROR_INVALID_DATA,
                                           "Invalid data received from IPC "
                                           "connection");
                        return false;
                }

                request_id = ntb_proto_get_32(data + 12);

                if (!strcmp((const char *) data, "response") &&
                    request_id == state->request_id &&
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
        enum ntb_file_error file_error;
        ssize_t got;

        while (true) {
                ntb_buffer_ensure_size(&state->buf, state->buf.length + 512);

                got = read(sock,
                           state->buf.data + state->buf.length,
                           state->buf.size - state->buf.length);

                if (got == -1) {
                        set_response_error(state,
                                           &ntb_file_error,
                                           ntb_file_error_from_errno(errno),
                                           "Error reading from IPC socket: %s",
                                           strerror(errno));
                        break;
                } else if (got == 0) {
                        if (state->buf.length > 0) {
                                file_error = ntb_file_error_from_errno(errno);
                                set_response_error(state,
                                                   &ntb_file_error,
                                                   file_error,
                                                   "Invalid data received from "
                                                   "IPC socket: %s",
                                                   strerror(errno));
                        }
                        break;
                } else {
                        state->buf.length += got;
                        if (!process_commands(state, sock))
                                break;
                }
        }

        if (state->error == NULL && !state->had_response) {
                set_response_error(state,
                                   &ntb_ipc_client_error,
                                   NTB_IPC_CLIENT_ERROR_NO_RESPONSE,
                                   "No response received from IPC socket");
        }
}

bool
ntb_ipc_client_get_response(int sock,
                            struct ntb_buffer *response_buf,
                            struct ntb_error **error,
                            uint32_t request_id)
{
        struct response_state response_state;
        bool res;

        init_response_state(&response_state, response_buf, request_id);

        read_commands(&response_state, sock);

        if (response_state.error) {
                ntb_error_propagate(error, response_state.error);
                response_state.error = NULL;
        } else {
                res = true;
        }

        destroy_response_state(&response_state);

        return res;
}
