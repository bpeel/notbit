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
#include <openssl/ripemd.h>
#include <stdio.h>
#include <inttypes.h>

#include "ntb-connection.h"
#include "ntb-proto.h"
#include "ntb-util.h"
#include "ntb-slice.h"
#include "ntb-main-context.h"
#include "ntb-buffer.h"
#include "ntb-log.h"

#define NTB_CONNECTION_MAX_MESSAGE_SIZE (128 * 1024 * 1024)

struct ntb_error_domain
ntb_connection_error;

struct ntb_connection {
        struct ntb_netaddress remote_address;
        char *remote_address_string;
        struct ntb_main_context_source *source;
        int sock;

        struct ntb_buffer in_buf;
        struct ntb_buffer out_buf;

        struct ntb_signal message_signal;

        bool connect_succeeded;

        /* Position in out_buf of the start of a command. Used for
         * functions that build up a command on the fly */
        size_t command_start;
};

NTB_SLICE_ALLOCATOR(struct ntb_connection,
                    ntb_connection_allocator);

static bool
emit_message(struct ntb_connection *conn,
             enum ntb_connection_message_type type,
             struct ntb_connection_message *message)
{
        message->type = type;
        message->connection = conn;
        return ntb_signal_emit(&conn->message_signal, message);
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
get_hex_string(const uint8_t *data,
               int length,
               char *string)
{
        int i;

        for (i = 0; i < length; i++)
                snprintf(string + i * 2, 3, "%02x", data[i]);
}

static bool
check_command_string(const uint8_t *command_string)
{
        const uint8_t *command_end;
        int i;

        /* The command must end with a zero */
        command_end = memchr(command_string, 0, 12);

        if (command_end == NULL)
                return false;

        /* The rest of the command must be zeroes */
        for (i = command_end - command_string + 1; i < 12; i++)
                if (command_string[i] != '\0')
                        return false;

        return true;
}

static bool
version_command_handler(struct ntb_connection *conn,
                        const uint8_t *data,
                        uint32_t message_length)
{
        struct ntb_connection_version_message message;
        uint64_t dummy_64;

        if (ntb_proto_get_message(data,
                                  message_length,

                                  NTB_PROTO_ARGUMENT_32,
                                  &message.version,

                                  NTB_PROTO_ARGUMENT_64,
                                  &message.services,

                                  NTB_PROTO_ARGUMENT_TIMESTAMP,
                                  &message.timestamp,

                                  NTB_PROTO_ARGUMENT_64,
                                  &dummy_64,
                                  NTB_PROTO_ARGUMENT_NETADDRESS,
                                  &message.addr_recv,

                                  NTB_PROTO_ARGUMENT_64,
                                  &dummy_64,
                                  NTB_PROTO_ARGUMENT_NETADDRESS,
                                  &message.addr_from,

                                  NTB_PROTO_ARGUMENT_64,
                                  &message.nonce,

                                  NTB_PROTO_ARGUMENT_VAR_STR,
                                  &message.user_agent,

                                  NTB_PROTO_ARGUMENT_VAR_INT_LIST,
                                  &message.stream_numbers,

                                  NTB_PROTO_ARGUMENT_END) == -1) {
                ntb_log("Invalid version message received from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        return emit_message(conn,
                            NTB_CONNECTION_MESSAGE_VERSION,
                            &message.base);
}

static bool
getpubkey_command_handler(struct ntb_connection *conn,
                          const uint8_t *data,
                          uint32_t message_length)
{
        struct ntb_connection_object_message message;
        ssize_t header_length;

        header_length = ntb_proto_get_message(data,
                                              message_length,

                                              NTB_PROTO_ARGUMENT_64,
                                              &message.nonce,

                                              NTB_PROTO_ARGUMENT_TIMESTAMP,
                                              &message.timestamp,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &message.getpubkey.
                                              address_version,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &message.stream_number,

                                              NTB_PROTO_ARGUMENT_END);

        if (header_length == -1) {
                ntb_log("Invalid getpubkey message received from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        if (message.getpubkey.address_version < 2 ||
            message.getpubkey.address_version > 4) {
                ntb_log("getpubkey with unsupported address version "
                        "%" PRIu64 " received from %s",
                        message.getpubkey.address_version,
                        conn->remote_address_string);
                return true;
        }

        message.type = NTB_BLOB_TYPE_GETPUBKEY;
        message.object_data_length = message_length;
        message.object_data = data;

        if (message.getpubkey.address_version < 4) {
                message.getpubkey.ripe = data + header_length;
                message.getpubkey.tag = NULL;

                if (message_length - header_length < RIPEMD160_DIGEST_LENGTH) {
                        ntb_log("Invalid getpubkey message received from %s",
                                conn->remote_address_string);
                        set_error_state(conn);
                        return false;
                }
        } else {
                message.getpubkey.ripe = NULL;
                message.getpubkey.tag = data + header_length;

                if (message_length - header_length < 32) {
                        ntb_log("Invalid getpubkey message received from %s",
                                conn->remote_address_string);
                        set_error_state(conn);
                        return false;
                }
        }

        return emit_message(conn,
                            NTB_CONNECTION_MESSAGE_OBJECT,
                            &message.base);
}

static bool
process_v2_pubkey_parts(const uint8_t *data,
                        uint32_t message_length,
                        struct ntb_connection_object_message *message)
{
        if (message_length < 64 * 2 + 4)
                return false;

        message->pubkey.behaviours = ntb_proto_get_32(data);
        message->pubkey.public_signing_key = data + 4;
        message->pubkey.public_encryption_key = data + 4 + 64;

        message->pubkey.nonce_trials_per_byte =
                NTB_PROTO_MIN_NONCE_TRIALS_PER_BYTE;
        message->pubkey.extra_bytes =
                NTB_PROTO_MIN_EXTRA_BYTES;

        return true;
}

static bool
process_v3_pubkey_parts(const uint8_t *data,
                        uint32_t message_length,
                        struct ntb_connection_object_message *message)
{
        ssize_t header_length;

        if (message_length < 4 + 64 * 2)
                return false;

        message->pubkey.behaviours = ntb_proto_get_32(data);
        message->pubkey.public_signing_key = data + 4;
        message->pubkey.public_encryption_key = data + 4 + 64;

        data += 4 + 64 * 2;
        message_length -= 4 + 64 * 2;

        header_length =
                ntb_proto_get_message(data,
                                      message_length,

                                      NTB_PROTO_ARGUMENT_VAR_INT,
                                      &message->pubkey.
                                      nonce_trials_per_byte,

                                      NTB_PROTO_ARGUMENT_VAR_INT,
                                      &message->pubkey.extra_bytes,

                                      NTB_PROTO_ARGUMENT_VAR_INT,
                                      &message->pubkey.signature_length,

                                      NTB_PROTO_ARGUMENT_END);

        if (header_length == -1)
                return false;

        if (message_length < header_length + message->pubkey.signature_length)
                return false;

        message->pubkey.signature = data + header_length;

        return true;
}

static bool
process_v4_pubkey_parts(const uint8_t *data,
                        uint32_t message_length,
                        struct ntb_connection_object_message *message)
{
        if (message_length < 32)
                return false;

        message->pubkey.tag = data;
        message->pubkey.encrypted_data = data + 32;
        message->pubkey.encrypted_data_length = message_length - 32;

        return true;
}

static bool
pubkey_command_handler(struct ntb_connection *conn,
                       const uint8_t *data,
                       uint32_t message_length)
{
        struct ntb_connection_object_message message;
        ssize_t header_length;

        memset(&message, 0, sizeof message);

        message.type = NTB_BLOB_TYPE_PUBKEY;
        message.object_data_length = message_length;
        message.object_data = data;

        header_length = ntb_proto_get_message(data,
                                              message_length,

                                              NTB_PROTO_ARGUMENT_64,
                                              &message.nonce,

                                              NTB_PROTO_ARGUMENT_TIMESTAMP,
                                              &message.timestamp,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &message.pubkey.address_version,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &message.stream_number,

                                              NTB_PROTO_ARGUMENT_END);

        if (header_length == -1)
                goto error;

        data += header_length;
        message_length -= header_length;

        if (message.pubkey.address_version == 2) {
                if (!process_v2_pubkey_parts(data,
                                             message_length,
                                             &message))
                        goto error;
        } else if (message.pubkey.address_version == 3) {
                if (!process_v3_pubkey_parts(data,
                                             message_length,
                                             &message))
                        goto error;
        } else if (message.pubkey.address_version == 4) {
                if (!process_v4_pubkey_parts(data,
                                             message_length,
                                             &message))
                        goto error;
        } else {
                ntb_log("Unsupported pubkey version %" PRIu64 " from %s",
                        message.pubkey.address_version,
                        conn->remote_address_string);
                return true;
        }

        return emit_message(conn,
                            NTB_CONNECTION_MESSAGE_OBJECT,
                            &message.base);
error:
        ntb_log("Invalid pubkey message received from %s",
                conn->remote_address_string);
        set_error_state(conn);
        return false;
}

static bool
msg_command_handler(struct ntb_connection *conn,
                    const uint8_t *data,
                    uint32_t message_length)
{
        struct ntb_connection_object_message message;
        ssize_t header_length;

        header_length = ntb_proto_get_message(data,
                                              message_length,

                                              NTB_PROTO_ARGUMENT_64,
                                              &message.nonce,

                                              NTB_PROTO_ARGUMENT_TIMESTAMP,
                                              &message.timestamp,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &message.stream_number,

                                              NTB_PROTO_ARGUMENT_END);

        if (header_length == -1) {
                ntb_log("Invalid msg message received from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        message.type = NTB_BLOB_TYPE_MSG;
        message.object_data_length = message_length;
        message.object_data = data;

        message.msg.encrypted_data_length = message_length - header_length;
        message.msg.encrypted_data = data + header_length;

        return emit_message(conn,
                            NTB_CONNECTION_MESSAGE_OBJECT,
                            &message.base);
}

static bool
broadcast_command_handler(struct ntb_connection *conn,
                          const uint8_t *data,
                          uint32_t message_length)
{
        struct ntb_connection_object_message message;
        ssize_t header_length;

        message.type = NTB_BLOB_TYPE_BROADCAST;
        message.object_data_length = message_length;
        message.object_data = data;

        header_length = ntb_proto_get_message(data,
                                              message_length,

                                              NTB_PROTO_ARGUMENT_64,
                                              &message.nonce,

                                              NTB_PROTO_ARGUMENT_TIMESTAMP,
                                              &message.timestamp,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &message.broadcast.version,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &message.stream_number,

                                              NTB_PROTO_ARGUMENT_END);

        if (header_length == -1) {
                ntb_log("Invalid msg message received from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        if (message.broadcast.version < 2 ||
            message.broadcast.version > 3) {
                ntb_log("Received broadcast message with unsupported "
                        "version %" PRIu64 " from %s",
                        message.broadcast.version,
                        connection->remote_address_string);
                return true;
        }

        data += header_length;
        message_length -= header_length;

        if (message.broadcast.version >= 3) {
                if (message_length < 32) {
                        ntb_log("Invalid msg message received from %s",
                                conn->remote_address_string);
                        set_error_state(conn);
                        return false;
                }

                message.broadcast.tag = data;
                data += 32;
                message_length -= 32;
        } else {
                message.broadcast.tag = NULL;
        }

        message.broadcast.encrypted_data_length = message_length;
        message.broadcast.encrypted_data = data;

        return emit_message(conn,
                            NTB_CONNECTION_MESSAGE_OBJECT,
                            &message.base);
}

static bool
inv_command_handler(struct ntb_connection *conn,
                    const uint8_t *data,
                    uint32_t message_length)
{
        struct ntb_connection_inv_message message;

        if (!ntb_proto_get_var_int(&data,
                                   &message_length,
                                   &message.n_inventories) ||
            message_length < message.n_inventories * NTB_PROTO_HASH_LENGTH) {
                ntb_log("Invalid inv message received from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        message.inventories = data;

        return emit_message(conn,
                            NTB_CONNECTION_MESSAGE_INV,
                            &message.base);
}

static const struct {
        const char *command_name;
        bool (* func)(struct ntb_connection *conn,
                      const uint8_t *data,
                      uint32_t message_length);
} message_handlers[] = {
        { "getpubkey", getpubkey_command_handler },
        { "pubkey", pubkey_command_handler },
        { "msg", msg_command_handler },
        { "broadcast", broadcast_command_handler },
        { "inv", inv_command_handler },
        { "version", version_command_handler }
};

static bool
process_message(struct ntb_connection *conn,
                const uint8_t *data,
                uint32_t message_length)
{
        char hex_a[9], hex_b[9];
        uint8_t hash[SHA512_DIGEST_LENGTH];
        int i;

        if (memcmp(data, ntb_proto_magic, sizeof ntb_proto_magic)) {
                get_hex_string(data, sizeof ntb_proto_magic, hex_a);
                ntb_log("Invalid message magic from %s (%s)",
                        conn->remote_address_string, hex_a);
                set_error_state(conn);
                return false;
        }

        if (!check_command_string(data + 4)) {
                ntb_log("Invalid command string from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        SHA512(data + NTB_PROTO_HEADER_SIZE, message_length, hash);

        /* Compare the checksum */
        if (memcmp(hash, data + 20, 4)) {
                get_hex_string(data + 20, 4, hex_a);
                get_hex_string(hash, 4, hex_b);
                ntb_log("Invalid checksum received from %s (%s != %s)",
                        conn->remote_address_string,
                        hex_a,
                        hex_b);
                set_error_state(conn);
                return false;
        }

        for (i = 0; i < NTB_N_ELEMENTS(message_handlers); i++) {
                if (!strcmp((const char *) data + 4,
                            message_handlers[i].command_name))
                        return message_handlers[i].func(conn,
                                                        data +
                                                        NTB_PROTO_HEADER_SIZE,
                                                        message_length);
        }

        /* Unknown message which we'll just ignore */
        return true;
}

static void
process_messages(struct ntb_connection *conn)
{
        uint32_t message_length;
        uint8_t *data = conn->in_buf.data;
        size_t length = conn->in_buf.length;

        while (true) {
                if (length < NTB_PROTO_HEADER_SIZE)
                        break;

                message_length = ntb_proto_get_32(data + 16);

                /* Limit the length of a message or the client would
                 * be able to pretend it's going to send a really long
                 * message and we'd just keep growing the buffer
                 * until we run out of memory and abort */
                if (message_length > NTB_CONNECTION_MAX_MESSAGE_SIZE) {
                        ntb_log("Client %s sent a message that is too long "
                                "(%" PRIu32 ")",
                                conn->remote_address_string,
                                message_length);
                        set_error_state(conn);
                        return;
                }

                if (length < NTB_PROTO_HEADER_SIZE + message_length)
                        break;

                if (!process_message(conn, data, message_length))
                        return;

                data += message_length + NTB_PROTO_HEADER_SIZE;
                length -= message_length + NTB_PROTO_HEADER_SIZE;
        }

        memmove(conn->in_buf.data, data, length);
        conn->in_buf.length = length;
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

const struct ntb_netaddress *
ntb_connection_get_remote_address(struct ntb_connection *conn)
{
        return &conn->remote_address;
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
ntb_connection_send_verack(struct ntb_connection *conn)
{
        ntb_proto_add_command(&conn->out_buf,
                              "verack",
                              NTB_PROTO_ARGUMENT_END);

        update_poll_flags(conn);
}

void
ntb_connection_send_version(struct ntb_connection *conn,
                            uint64_t nonce,
                            const struct ntb_netaddress *local_address)
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
                              local_address,

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

void
ntb_connection_begin_getdata(struct ntb_connection *conn)
{
        conn->command_start = conn->out_buf.length;

        ntb_proto_begin_command(&conn->out_buf, "getdata");

        /* Reserve space for a 1-byte varint. If we need more than
         * this then we'll split the command up on the fly */
        ntb_buffer_ensure_size(&conn->out_buf, conn->out_buf.length + 1);
        conn->out_buf.length += 1;
}

static int
get_n_hashes_for_getdata(struct ntb_connection *conn)
{
        return (conn->out_buf.length -
                conn->command_start -
                1 -
                NTB_PROTO_HEADER_SIZE) / NTB_PROTO_HASH_LENGTH;
}

void
ntb_connection_add_getdata_hash(struct ntb_connection *conn,
                                const uint8_t *hash)
{
        int n_hashes = get_n_hashes_for_getdata(conn);

        /* If we can't fit further hashes into a 1-byte varint then
         * we'll start another command */
        if (n_hashes >= 0xfc) {
                ntb_connection_end_getdata(conn);
                ntb_connection_begin_getdata(conn);
        }

        ntb_buffer_append(&conn->out_buf, hash, NTB_PROTO_HASH_LENGTH);
}

void
ntb_connection_end_getdata(struct ntb_connection *conn)
{
        int n_hashes = get_n_hashes_for_getdata(conn);

        if (n_hashes == 0) {
                /* Abandon the command if there weren't any hashes */
                conn->out_buf.length = conn->command_start;
        } else {
                /* Update the number of hashes */
                conn->out_buf.data[conn->command_start +
                                   NTB_PROTO_HEADER_SIZE] = n_hashes;
                ntb_proto_end_command(&conn->out_buf, conn->command_start);
        }

        update_poll_flags(conn);
}
