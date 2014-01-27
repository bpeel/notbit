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
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <assert.h>

#include "ntb-ipc.h"
#include "ntb-ipc-proto.h"
#include "ntb-ipc-sockaddr.h"
#include "ntb-file-error.h"
#include "ntb-util.h"
#include "ntb-list.h"
#include "ntb-main-context.h"
#include "ntb-log.h"
#include "ntb-buffer.h"
#include "ntb-proto.h"
#include "ntb-socket.h"
#include "ntb-mail-parser.h"
#include "ntb-blob.h"

struct ntb_ipc {
        int sock;
        uid_t uid;

        struct ntb_main_context_source *listen_source;

        struct ntb_keyring *keyring;

        struct ntb_list connections;
};

struct ntb_ipc_connection {
        struct ntb_ipc *ipc;

        int sock;
        struct ntb_main_context_source *source;

        /* This becomes TRUE when the client has closed its end of the
           connection */
        bool read_finished;
        /* This becomes TRUE when we've stopped writing data. This will only
           happen after the client closes its connection */
        bool write_finished;

        struct ntb_buffer outbuf;
        struct ntb_buffer inbuf;
        struct ntb_buffer fd_queue;

        struct ntb_list emails;

        struct ntb_list link;
};

/* This represents an email that is being read from a file descriptor
   passed in the email command */
struct ntb_ipc_email {
        struct ntb_ipc_connection *conn;

        struct ntb_address from_address;
        struct ntb_buffer to_addresses;
        struct ntb_buffer content;
        int content_encoding;

        struct ntb_main_context_source *source;
        int fd;
        int request_id;

        struct ntb_mail_parser *parser;

        struct ntb_list link;
};

struct ntb_ipc_command {
        const char *name;
        bool (* func)(struct ntb_ipc_connection *conn,
                      uint32_t request_id,
                      const uint8_t *data,
                      uint32_t command_length);
};

static NTB_PRINTF_FORMAT(4, 5) bool
send_response(struct ntb_ipc_connection *conn,
              uint32_t request_id,
              enum ntb_ipc_proto_status status,
              const char *format,
              ...);

static void
close_fd_queue(struct ntb_ipc_connection *conn)
{
        const int *fds = (const int *) conn->fd_queue.data;
        int i;

        for (i = 0; i < conn->fd_queue.length / sizeof (int); i++)
                close(fds[i]);

        conn->fd_queue.length = 0;
}

static void
remove_email(struct ntb_ipc_email *email)
{
        ntb_buffer_destroy(&email->to_addresses);
        ntb_buffer_destroy(&email->content);

        ntb_mail_parser_free(email->parser);
        ntb_main_context_remove_source(email->source);
        close(email->fd);
        ntb_list_remove(&email->link);
        ntb_free(email);
}

static void
remove_connection(struct ntb_ipc_connection *conn)
{
        struct ntb_ipc_email *email, *tmp;

        ntb_list_for_each_safe(email, tmp, &conn->emails, link)
                remove_email(email);

        close_fd_queue(conn);
        ntb_buffer_destroy(&conn->fd_queue);
        ntb_buffer_destroy(&conn->inbuf);
        ntb_buffer_destroy(&conn->outbuf);
        ntb_main_context_remove_source(conn->source);
        close(conn->sock);
        ntb_list_remove(&conn->link);
        ntb_free(conn);
}

static bool
update_poll(struct ntb_ipc_connection *conn)
{
        enum ntb_main_context_poll_flags flags = 0;

        if (!conn->read_finished)
                flags |= NTB_MAIN_CONTEXT_POLL_IN;

        /* Shutdown the socket if we've finished writing */
        if (!conn->write_finished &&
            conn->read_finished &&
            conn->outbuf.length == 0 &&
            ntb_list_empty(&conn->emails)) {
                if (shutdown(conn->sock, SHUT_WR) == -1) {
                        ntb_log("shutdown for IPC connection failed: %s",
                                strerror(errno));
                        remove_connection(conn);
                        return false;
                }

                conn->write_finished = true;
        }

        if (!conn->write_finished && conn->outbuf.length > 0)
                flags |= NTB_MAIN_CONTEXT_POLL_OUT;

        /* If both ends of the conn are closed then we can abandon
           this connection */
        if (conn->read_finished && conn->write_finished) {
                remove_connection(conn);
                return false;
        }

        ntb_main_context_modify_poll(conn->source, flags);

        return true;
}

static bool
process_control_data(struct ntb_ipc_connection *conn,
                     struct msghdr *msg)
{
        struct cmsghdr *cmsg;

        for (cmsg = CMSG_FIRSTHDR(msg);
             cmsg != NULL;
             cmsg = CMSG_NXTHDR(msg, cmsg)) {
                if (cmsg->cmsg_level != SOL_SOCKET ||
                    cmsg->cmsg_type != SCM_RIGHTS)
                        continue;

                ntb_buffer_append(&conn->fd_queue,
                                  CMSG_DATA(cmsg),
                                  cmsg->cmsg_len - CMSG_LEN(0));
        }

        return true;
}

static bool
send_response(struct ntb_ipc_connection *conn,
              uint32_t request_id,
              enum ntb_ipc_proto_status status,
              const char *format,
              ...)
{
        uint32_t command_length;
        size_t old_length;
        va_list ap;

        request_id = NTB_UINT32_TO_BE(request_id);

        ntb_buffer_append(&conn->outbuf, "response\0\0\0", 12);
        ntb_buffer_append(&conn->outbuf, &request_id, sizeof request_id);

        /* Reserve space for the length */
        ntb_buffer_set_length(&conn->outbuf, conn->outbuf.length + 4);
        old_length = conn->outbuf.length;

        ntb_proto_add_32(&conn->outbuf, status);

        if (format) {
                va_start(ap, format);
                ntb_buffer_append_vprintf(&conn->outbuf, format, ap);
                va_end(ap);
        }

        command_length = conn->outbuf.length - old_length;
        command_length = NTB_UINT32_TO_BE(command_length);

        memcpy(conn->outbuf.data + old_length - 4,
               &command_length,
               sizeof command_length);

        return update_poll(conn);
}

static void
send_email(struct ntb_ipc_email *email)
{
        struct ntb_ipc_connection *conn = email->conn;
        struct ntb_ipc *ipc = conn->ipc;
        struct ntb_error *error = NULL;
        struct ntb_blob *content;
        enum ntb_ipc_proto_status status;
        bool res;

        content = ntb_blob_dynamic_end(&email->content);
        ntb_buffer_init(&email->content);

        res = ntb_keyring_send_message(ipc->keyring,
                                       &email->from_address,
                                       (const struct ntb_address *)
                                       email->to_addresses.data,
                                       email->to_addresses.length /
                                       sizeof (struct ntb_address),
                                       email->content_encoding,
                                       content,
                                       &error);

        ntb_blob_unref(content);

        if (res) {
                send_response(conn,
                              email->request_id,
                              NTB_IPC_PROTO_STATUS_SUCCESS,
                              NULL);
        } else {
                if (error->domain == &ntb_keyring_error &&
                    error->code == NTB_KEYRING_ERROR_UNKNOWN_FROM_ADDRESS)
                        status = NTB_IPC_PROTO_STATUS_UNKNOWN_FROM_ADDRESS;
                else
                        status = NTB_IPC_PROTO_STATUS_GENERIC_ERROR;

                send_response(conn,
                              email->request_id,
                              status,
                              "%s",
                              error->message);

                ntb_error_free(error);
        }
}

static void
email_poll_cb(struct ntb_main_context_source *source,
              int fd,
              enum ntb_main_context_poll_flags flags,
              void *user_data)
{
        struct ntb_ipc_email *email = user_data;
        struct ntb_ipc_connection *conn = email->conn;
        struct ntb_error *error = NULL;
        uint8_t buf[512];
        ssize_t got;

        got = read(fd, buf, sizeof buf);

        if (got == -1) {
                send_response(conn,
                              email->request_id,
                              NTB_IPC_PROTO_STATUS_FD_ERROR,
                              "Error reading from email file descriptor");
                remove_email(email);
        } else if (got == 0) {
                send_email(email);
                remove_email(email);
        } else if (!ntb_mail_parser_parse(email->parser,
                                          buf,
                                          got,
                                          &error)) {
                send_response(conn,
                              email->request_id,
                              NTB_IPC_PROTO_STATUS_INVALID_EMAIL,
                              "Error parsing email: %s",
                              error->message);
                ntb_error_free(error);
                remove_email(email);
        }
}

static int
get_fd(struct ntb_ipc_connection *conn)
{
        int fd;

        memcpy(&fd, conn->fd_queue.data, sizeof fd);
        memmove(conn->fd_queue.data,
                conn->fd_queue.data + sizeof fd,
                conn->fd_queue.length - sizeof fd);
        conn->fd_queue.length -= sizeof fd;

        return fd;
}

static bool
mail_parser_data_cb(enum ntb_mail_parser_event event,
                    const uint8_t *data,
                    size_t length,
                    void *user_data,
                    struct ntb_error **error)
{
        struct ntb_ipc_email *email = user_data;

        switch (event) {
        case NTB_MAIL_PARSER_EVENT_SOURCE:
        case NTB_MAIL_PARSER_EVENT_DESTINATION:
                assert(false);

        case NTB_MAIL_PARSER_EVENT_SUBJECT:
                ntb_buffer_append_string(&email->content,
                                         "Subject:");
                ntb_buffer_append(&email->content, data, length);
                ntb_buffer_append_string(&email->content, "\nBody:");
                email->content_encoding = 2;
                break;

        case NTB_MAIL_PARSER_EVENT_CONTENT:
                ntb_buffer_append(&email->content, data, length);
                break;
        }

        return true;
}

static bool
mail_parser_address_cb(enum ntb_mail_parser_event event,
                       const struct ntb_address *address,
                       void *user_data,
                       struct ntb_error **error)
{
        struct ntb_ipc_email *email = user_data;

        switch (event) {
        case NTB_MAIL_PARSER_EVENT_SOURCE:
                email->from_address = *address;
                break;

        case NTB_MAIL_PARSER_EVENT_DESTINATION:
                ntb_buffer_append(&email->to_addresses,
                                  address,
                                  sizeof *address);
                break;

        case NTB_MAIL_PARSER_EVENT_SUBJECT:
        case NTB_MAIL_PARSER_EVENT_CONTENT:
                assert(false);
        }

        return true;
}

static bool
handle_email_command(struct ntb_ipc_connection *conn,
                     uint32_t request_id,
                     const uint8_t *data,
                     uint32_t command_length)
{
        struct ntb_ipc_email *email;
        struct ntb_error *error = NULL;
        bool res;
        int fd;

        if (conn->fd_queue.length < sizeof fd)
                return send_response(conn,
                                     request_id,
                                     NTB_IPC_PROTO_STATUS_INVALID_COMMAND,
                                     "email command was sent without a "
                                     "file descriptor argument");

        fd = get_fd(conn);

        if (!ntb_socket_set_nonblock(fd, &error)) {
                res = send_response(conn,
                                    request_id,
                                    NTB_IPC_PROTO_STATUS_FD_ERROR,
                                    "%s",
                                    error->message);
                ntb_error_free(error);
                close(fd);
                return res;
        }

        email = ntb_alloc(sizeof *email);
        email->conn = conn;
        email->fd = fd;
        email->request_id = request_id;
        email->source = ntb_main_context_add_poll(NULL,
                                                  email->fd,
                                                  NTB_MAIN_CONTEXT_POLL_IN,
                                                  email_poll_cb,
                                                  email);

        email->parser = ntb_mail_parser_new(mail_parser_address_cb,
                                            mail_parser_data_cb,
                                            email);

        ntb_buffer_init(&email->to_addresses);

        ntb_list_insert(&conn->emails, &email->link);

        ntb_blob_dynamic_init(&email->content,
                              NTB_PROTO_INV_TYPE_MSG);

        email->content_encoding = 1;

        return true;
}

static struct ntb_ipc_command
commands[] = {
        { "email", handle_email_command }
};


static bool
process_command(struct ntb_ipc_connection *conn,
                const uint8_t *data,
                uint32_t command_length)
{
        uint32_t request_id;
        int i;

        request_id = ntb_proto_get_32(data + 12);

        for (i = 0; i < NTB_N_ELEMENTS(commands); i++) {
                if (!strcmp((const char *) data, commands[i].name))
                        return commands[i].func(conn,
                                                request_id,
                                                data + 20,
                                                command_length);
        }

        return send_response(conn,
                             request_id,
                             NTB_IPC_PROTO_STATUS_INVALID_COMMAND,
                             "Unknown command “%s”",
                             (const char *) data);
}

static void
process_commands(struct ntb_ipc_connection *conn)
{
        const uint8_t *data = conn->inbuf.data;
        size_t data_length = conn->inbuf.length;
        uint32_t command_length;

        while (true) {
                if (data_length < 20)
                        break;

                command_length = ntb_proto_get_32(data + 16);

                if (data_length < command_length + 20)
                        break;

                if (!ntb_proto_check_command_string(data)) {
                       ntb_log("Invalid data received from IPC connection\n");
                       remove_connection(conn);
                       return;
                }

                if (!process_command(conn, data, command_length))
                        return;

                data += command_length + 20;
                data_length -= command_length + 20;
         }

        /* If there are remaining file descriptors then there must
         * have been some for a command that we didn't understand.
         * We'll just close them in order to prevent a leak */
        if (conn->inbuf.length == 0)
                close_fd_queue(conn);
}

static void
handle_read(struct ntb_ipc_connection *conn)
{
        ssize_t got;
        struct msghdr msg;
        struct iovec iov;
        uint8_t control_buf[512];

        ntb_buffer_ensure_size(&conn->inbuf, conn->inbuf.length + 128);

        iov.iov_base = conn->inbuf.data + conn->inbuf.length;
        iov.iov_len = conn->inbuf.size - conn->inbuf.length;

        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control_buf;
        msg.msg_controllen = sizeof control_buf;
        msg.msg_flags = 0;

        got = recvmsg(conn->sock, &msg, MSG_DONTWAIT);

        if (got == -1) {
                if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN) {
                        ntb_log("Error reading from IPC socket: %s",
                                strerror(errno));
                        remove_connection(conn);
                }
        } else {
                if (!process_control_data(conn, &msg))
                        return;

                if (got == 0) {
                        conn->read_finished = true;

                        update_poll(conn);
                } else {
                        conn->inbuf.length += got;
                        process_commands(conn);
                }
        }
}

static void
handle_write(struct ntb_ipc_connection *conn)
{
        ssize_t wrote;

        wrote = send(conn->sock,
                     conn->outbuf.data,
                     conn->outbuf.length,
                     MSG_DONTWAIT);

        if (wrote == -1) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                        ntb_log("Error writing to IPC socket: %s",
                                strerror(errno));
                        remove_connection(conn);
                }
        } else {
                /* Move any remaining data in the output buffer to the front */
                memmove(conn->outbuf.data,
                        conn->outbuf.data + wrote,
                        conn->outbuf.length - wrote);
                conn->outbuf.length -= wrote;

                update_poll(conn);
        }
}

static void
connection_source_cb(struct ntb_main_context_source *source,
                     int fd,
                     enum ntb_main_context_poll_flags flags,
                     void *user_data)
{
        struct ntb_ipc_connection *conn = user_data;

        if (flags & NTB_MAIN_CONTEXT_POLL_ERROR) {
                int value;
                unsigned int value_len = sizeof(value);

                if (getsockopt(conn->sock,
                               SOL_SOCKET,
                               SO_ERROR,
                               &value,
                               &value_len) == -1 ||
                    value_len != sizeof(value) ||
                    value == 0) {
                        ntb_log("Unknown error on IPC socket");
                } else {
                        ntb_log("Error on IPC socket: %s",
                                strerror(value));
                }

                remove_connection(conn);
        } else if (flags & NTB_MAIN_CONTEXT_POLL_IN) {
                handle_read(conn);
        } else if (flags & NTB_MAIN_CONTEXT_POLL_OUT) {
                handle_write(conn);
        }
}

static bool
check_credentials(struct ntb_ipc *ipc,
                  int sock)
{
        struct ucred ucred;
        socklen_t socklen = sizeof ucred;
        int res;

        res = getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &ucred, &socklen);
        if (res == -1) {
                ntb_log("Error getting credentials for IPC connection: %s",
                        strerror(errno));
                return false;
        }

        if (ucred.uid != 0 && ucred.uid != ipc->uid) {
                ntb_log("Rejecting IPC connection from unauthorized user %i",
                        ucred.uid);
                return false;
        }

        return true;
}

static void
listen_source_cb(struct ntb_main_context_source *source,
                 int fd,
                 enum ntb_main_context_poll_flags flags,
                 void *user_data)
{
        struct ntb_ipc *ipc = user_data;
        struct ntb_ipc_connection *conn;
        struct ntb_error *error = NULL;
        int sock;

        sock = accept(fd, NULL, 0);

        if (sock == -1) {
                ntb_log("Error accepting IPC connection: %s",
                        strerror(errno));
                ntb_main_context_remove_source(source);
                ipc->listen_source = NULL;
                return;
        }

        if (!ntb_socket_set_nonblock(sock, &error)) {
                ntb_log("Error accepting IPC connection: %s",
                        error->message);
                close(sock);
                ntb_error_free(error);
                return;
        }

        if (!check_credentials(ipc, sock)) {
                close(sock);
                return;
        }

        conn = ntb_alloc(sizeof *conn);
        conn->sock = sock;
        conn->ipc = ipc;

        conn->read_finished = false;
        conn->write_finished = false;

        ntb_buffer_init(&conn->inbuf);
        ntb_buffer_init(&conn->outbuf);
        ntb_buffer_init(&conn->fd_queue);

        ntb_list_init(&conn->emails);

        conn->source = ntb_main_context_add_poll(NULL,
                                                 sock,
                                                 NTB_MAIN_CONTEXT_POLL_IN,
                                                 connection_source_cb,
                                                 conn);

        ntb_list_insert(&ipc->connections, &conn->link);
}

struct ntb_ipc *
ntb_ipc_new(struct ntb_keyring *keyring,
            struct ntb_error **error)
{
        struct ntb_ipc *ipc;
        struct sockaddr *sockaddr;
        socklen_t sockaddr_len;
        const char *sockaddr_path;
        int sock;
        int res;

        if (!ntb_ipc_sockaddr_create(&sockaddr, &sockaddr_len, error))
                return NULL;

        sockaddr_path = ((struct sockaddr_un *) sockaddr)->sun_path + 1;

        sock = socket(PF_LOCAL, SOCK_STREAM, 0);

        if (sock == -1) {
                ntb_file_error_set(error,
                                   errno,
                                   "Failed to create socket: %s",
                                   strerror(errno));
                return NULL;
        }

        res = bind(sock, (struct sockaddr *) sockaddr, sockaddr_len);

        if (res == -1) {
                ntb_file_error_set(error,
                                   errno,
                                   "Failed to bind abstract sock %s: %s",
                                   sockaddr_path,
                                   strerror(errno));
                close(sock);
                return NULL;
        }

        res = listen(sock, 10);

        if (res == -1) {
                ntb_file_error_set(error,
                                   errno,
                                   "Failed to make socket listen: %s",
                                   strerror(errno));
                close(sock);
                return NULL;
        }

        ipc = ntb_alloc(sizeof *ipc);

        ipc->uid = getuid();

        ipc->sock = sock;
        ipc->listen_source =
                ntb_main_context_add_poll(NULL,
                                          sock,
                                          NTB_MAIN_CONTEXT_POLL_IN,
                                          listen_source_cb,
                                          ipc);

        ipc->keyring = keyring;

        ntb_list_init(&ipc->connections);

        return ipc;
}

void
ntb_ipc_free(struct ntb_ipc *ipc)
{
        struct ntb_ipc_connection *conn, *tmp;

        ntb_list_for_each_safe(conn, tmp, &ipc->connections, link)
                remove_connection(conn);

        if (ipc->listen_source)
                ntb_main_context_remove_source(ipc->listen_source);
        close(ipc->sock);
        ntb_free(ipc);
}
