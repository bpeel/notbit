/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013  Neil Roberts
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

#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>

#include "ntb-connection.h"
#include "ntb-proto.h"
#include "ntb-util.h"
#include "ntb-slice.h"
#include "ntb-main-context.h"
#include "ntb-buffer.h"
#include "ntb-log.h"

struct ntb_error_domain
ntb_connection_error;

struct ntb_connection {
        struct ntb_netaddress local_address;
        struct ntb_netaddress remote_address;
        char *remote_address_string;
        struct ntb_main_context_source *source;
        int sock;

        struct ntb_buffer in_buf;
        struct ntb_buffer out_buf;

        struct ntb_signal message_signal;

        bool connect_succeeded;
};

NTB_SLICE_ALLOCATOR(struct ntb_connection,
                    ntb_connection_allocator);

static void
emit_message(struct ntb_connection *conn,
             enum ntb_connection_message_type type,
             struct ntb_connection_message *message)
{
        message->type = type;
        message->connection = conn;
        ntb_signal_emit(&conn->message_signal, message);
}

static void
set_error_state(struct ntb_connection *conn)
{
        struct ntb_connection_message message;

        /* Stop polling for further events */
        if (conn->source) {
                ntb_main_context_remove_source(conn->source);
                conn->source = NULL;
        }

        emit_message(conn,
                     conn->connect_succeeded ?
                     NTB_CONNECTION_MESSAGE_ERROR :
                     NTB_CONNECTION_MESSAGE_CONNECT_FAILED,
                     &message);
}

static void
handle_error(struct ntb_connection *conn)
{
        int value;
        unsigned int value_len = sizeof(value);

        if (getsockopt(conn->sock,
                       SOL_SOCKET,
                       SO_ERROR,
                       &value,
                       &value_len) == -1 ||
            value_len != sizeof(value) ||
            value == 0) {
                ntb_log("Unknown error on socket for %s",
                        conn->remote_address_string);
        } else if (conn->connect_succeeded) {
                ntb_log("Error on socket for %s: %s",
                        conn->remote_address_string,
                        strerror(value));
        } else {
                ntb_log("Error connecting to %s: %s",
                        conn->remote_address_string,
                        strerror(value));
        }

        set_error_state(conn);
}

static void
process_messages(struct ntb_connection *conn)
{
}

static void
handle_read(struct ntb_connection *conn)
{
        int got;

        ntb_buffer_ensure_size(&conn->in_buf,
                               conn->in_buf.length + 1024);

        got = read(conn->sock,
                   conn->in_buf.data + conn->in_buf.length,
                   conn->in_buf.size - conn->in_buf.length);

        if (got == 0) {
                ntb_log("Connection closed for %s",
                        conn->remote_address_string);
                set_error_state(conn);
        } else if (got == -1) {
                ntb_log("Error reading from socket for %s: %s",
                        conn->remote_address_string,
                        strerror(errno));
                set_error_state(conn);
        } else {
                conn->in_buf.length += got;
                process_messages(conn);
        }
}

static void
update_poll_flags(struct ntb_connection *conn)
{
        enum ntb_main_context_poll_flags flags = NTB_MAIN_CONTEXT_POLL_IN;

        if (conn->out_buf.length > 0)
                flags |= NTB_MAIN_CONTEXT_POLL_OUT;

        ntb_main_context_modify_poll(conn->source, flags);
}

static void
handle_write(struct ntb_connection *conn)
{
        int wrote;

        wrote = write(conn->sock,
                      conn->out_buf.data,
                      conn->out_buf.length);

        if (wrote == -1) {
                ntb_log("Error writing to socket for %s: %s",
                        conn->remote_address_string,
                        strerror(errno));
                set_error_state(conn);
        } else {
                memmove(conn->out_buf.data,
                        conn->out_buf.data + wrote,
                        conn->out_buf.length - wrote);
                conn->out_buf.length -= wrote;

                update_poll_flags(conn);
        }
}

static void
connection_poll_cb(struct ntb_main_context_source *source,
                   int fd,
                   enum ntb_main_context_poll_flags flags, void *user_data)
{
        struct ntb_connection *conn = user_data;

        /* If the connection ever becomes ready for writing then we
         * know it has successfully connected */
        if ((flags & NTB_MAIN_CONTEXT_POLL_OUT) &&
            !conn->connect_succeeded) {
                conn->connect_succeeded = true;
                ntb_log("Connected to %s", conn->remote_address_string);
        }

        if (flags & NTB_MAIN_CONTEXT_POLL_ERROR)
                handle_error(conn);
        else if (flags & NTB_MAIN_CONTEXT_POLL_IN)
                handle_read(conn);
        else if (flags & NTB_MAIN_CONTEXT_POLL_OUT)
                handle_write(conn);
}

void
ntb_connection_free(struct ntb_connection *conn)
{
        if (conn->source)
                ntb_main_context_remove_source(conn->source);
        ntb_free(conn->remote_address_string);
        ntb_buffer_destroy(&conn->in_buf);
        ntb_buffer_destroy(&conn->out_buf);
        close(conn->sock);
}

static void
get_local_address(int sock,
                  struct ntb_netaddress *address)
{
        struct ntb_netaddress_native native;

        native.length = sizeof native.sockaddr_in6;

        if (getsockname(sock, &native.sockaddr, &native.length) == 0)
                ntb_netaddress_from_native(address, &native);
        else
                memset(address, 0, sizeof *address);
}

static struct ntb_connection *
ntb_connection_new_for_socket(int sock,
                              const struct ntb_netaddress *remote_address)
{
        struct ntb_connection *conn;

        conn = ntb_slice_alloc(&ntb_connection_allocator);

        conn->sock = sock;
        conn->remote_address = *remote_address;
        conn->remote_address_string = ntb_netaddress_to_string(remote_address);
        conn->connect_succeeded = false;

        get_local_address(sock, &conn->local_address);

        ntb_signal_init(&conn->message_signal);

        conn->source = ntb_main_context_add_poll(NULL, /* context */
                                                 sock,
                                                 NTB_MAIN_CONTEXT_POLL_IN,
                                                 connection_poll_cb,
                                                 conn);

        ntb_buffer_init(&conn->in_buf);
        ntb_buffer_init(&conn->out_buf);

        return conn;
}

static bool
set_nonblock(int sock,
             struct ntb_error **error)
{
        int flags;

        flags = fcntl(sock, F_GETFL, 0);

        if (flags == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
                ntb_set_error(error,
                              &ntb_connection_error,
                              NTB_CONNECTION_ERROR_SOCKET,
                              "Error setting non-blocking mode: %s",
                              strerror(errno));
                return false;
        }

        return true;
}

struct ntb_signal *
ntb_connection_get_message_signal(struct ntb_connection *conn)
{
        return &conn->message_signal;
}

const char *
ntb_connection_get_remote_address_string(struct ntb_connection *conn)
{
        return conn->remote_address_string;
}

struct ntb_connection *
ntb_connection_connect(const struct ntb_netaddress *address,
                       struct ntb_error **error)
{
        struct ntb_netaddress_native native_address;
        int sock;

        ntb_netaddress_to_native(address, &native_address);

        sock = socket(native_address.sockaddr.sa_family == AF_INET6 ?
                      PF_INET6 : PF_INET,
                      SOCK_STREAM,
                      0);
        if (sock == -1) {
                ntb_set_error(error,
                              &ntb_connection_error,
                              NTB_CONNECTION_ERROR_SOCKET,
                              "Failed to create socket: %s",
                              strerror(errno));
                return NULL;
        }

        if (!set_nonblock(sock, error)) {
                close(sock);
                return NULL;
        }

        if (connect(sock,
                    &native_address.sockaddr,
                    native_address.length) == -1 &&
            errno != EINPROGRESS) {
                ntb_set_error(error,
                              &ntb_connection_error,
                              NTB_CONNECTION_ERROR_CONNECT,
                              "Failed to connect to remote peer: %s",
                              strerror(errno));
                close(sock);
                return NULL;
        }

        return ntb_connection_new_for_socket(sock, address);
}

struct ntb_connection *
ntb_connection_accept(int server_sock,
                      struct ntb_error **error)
{
        struct ntb_netaddress address;
        struct ntb_netaddress_native native_address;
        struct ntb_connection *conn;
        int sock;

        sock = accept(server_sock,
                      &native_address.sockaddr,
                      &native_address.length);

        if (sock == -1) {
                ntb_set_error(error,
                              &ntb_connection_error,
                              NTB_CONNECTION_ERROR_ACCEPT,
                              "Error accepting connection: %s",
                              strerror(errno));
                return NULL;
        }

        if (!set_nonblock(sock, error)) {
                close(sock);
                return NULL;
        }

        ntb_netaddress_from_native(&address, &native_address);

        conn = ntb_connection_new_for_socket(sock, &address);

        conn->connect_succeeded = true;

        return conn;
}

void
ntb_connection_send_version(struct ntb_connection *conn,
                            uint64_t nonce)
{
        ntb_proto_add_command(&conn->out_buf,
                              "version",

                              NTB_PROTO_ARGUMENT_32,
                              NTB_PROTO_VERSION,

                              NTB_PROTO_ARGUMENT_64,
                              NTB_PROTO_SERVICES,

                              NTB_PROTO_ARGUMENT_TIMESTAMP,

                              NTB_PROTO_ARGUMENT_64,
                              NTB_PROTO_SERVICES,
                              NTB_PROTO_ARGUMENT_NETADDRESS,
                              &conn->remote_address,

                              NTB_PROTO_ARGUMENT_64,
                              NTB_PROTO_SERVICES,
                              NTB_PROTO_ARGUMENT_NETADDRESS,
                              &conn->local_address,

                              NTB_PROTO_ARGUMENT_64,
                              nonce,

                              NTB_PROTO_ARGUMENT_VAR_STR,
                              "notbit " VERSION,

                              /* Number of streams */
                              NTB_PROTO_ARGUMENT_VAR_INT,
                              UINT64_C(1),

                              /* The one stream */
                              NTB_PROTO_ARGUMENT_VAR_INT,
                              UINT64_C(1),

                              NTB_PROTO_ARGUMENT_END);

        update_poll_flags(conn);
}
