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

#include "ntb-connection.h"
#include "ntb-proto.h"
#include "ntb-util.h"
#include "ntb-slice.h"
#include "ntb-main-context.h"
#include "ntb-buffer.h"
#include "ntb-log.h"

struct ntb_error_domain
ntb_connection_error;

NTB_SLICE_ALLOCATOR(struct ntb_connection,
                    ntb_connection_allocator);

static void
set_error_state(struct ntb_connection *conn)
{
        /* Stop polling for further events */
        if (conn->source) {
                ntb_main_context_remove_source(conn->source);
                conn->source = NULL;
        }

        ntb_signal_emit(&conn->error_signal, conn);
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
            value == 0)
                ntb_log("Unknown error on socket for %s",
                        conn->remote_address_string);
        else
                ntb_log("Error on socket for %s: %s",
                        conn->remote_address_string,
                        strerror(value));

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

static struct ntb_connection *
ntb_connection_new_for_socket(int sock,
                              const struct ntb_netaddress *remote_address)
{
        struct ntb_connection *conn;

        conn = ntb_slice_alloc(&ntb_connection_allocator);

        conn->sock = sock;
        conn->remote_address = *remote_address;
        conn->remote_address_string = ntb_netaddress_to_string(remote_address);

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

        flags = fcntl(sock, F_GETFD, 0);

        if (flags == -1 || fcntl(sock, F_SETFD, flags | O_NONBLOCK) == -1) {
                ntb_set_error(error,
                              &ntb_connection_error,
                              NTB_CONNECTION_ERROR_SOCKET,
                              "Error setting non-blocking mode: %s",
                              strerror(errno));
                return false;
        }

        return true;
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
                    native_address.length) == -1) {
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

        return ntb_connection_new_for_socket(sock, &address);
}
