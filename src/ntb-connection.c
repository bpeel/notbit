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
#include <assert.h>

#include "ntb-connection.h"
#include "ntb-proto.h"
#include "ntb-util.h"
#include "ntb-slice.h"
#include "ntb-main-context.h"
#include "ntb-buffer.h"
#include "ntb-log.h"
#include "ntb-store.h"
#include "ntb-file-error.h"
#include "ntb-socket.h"

#define NTB_CONNECTION_MAX_MESSAGE_SIZE (128 * 1024 * 1024)

/* Time in minutes between each check for whether we should send a pong
 * command and whether the remote end has gone silent */
#define NTB_CONNECTION_PONG_CHECK_INTERVAL 3

/* Minimum time in seconds between sending each pong command if no
 * other data has been sent */
#define NTB_CONNECTION_PONG_INTERVAL (5 * 60)

/* Time in seconds after which we will consider a remote connection to
 * be dead if we don't receive any data */
#define NTB_CONNECTION_TIMEOUT (10 * 60)

/* If this assert fails then notbit clients won't recognise the pongs
 * from each other correctly */
_Static_assert(NTB_CONNECTION_PONG_CHECK_INTERVAL * 60 +
               NTB_CONNECTION_PONG_INTERVAL < NTB_CONNECTION_TIMEOUT,
               "The pong check and timeout values aren't going to work");

struct ntb_connection {
        struct ntb_netaddress remote_address;
        char *remote_address_string;
        struct ntb_main_context_source *socket_source;
        struct ntb_main_context_source *timer_source;
        int sock;

        struct ntb_buffer in_buf;
        struct ntb_buffer out_buf;

        struct ntb_signal event_signal;

        bool connect_succeeded;

        /* Position in out_buf of the start of a command. Used for
         * functions that build up a command on the fly */
        size_t command_start;

        /* We only load one blob from the store at a time. If we are
         * currently loading a blob then this is its cookie */
        struct ntb_store_cookie *load_cookie;

        /* List of queued loads that already have a blob. This can be
         * directly copied into the out buffer next time we need to
         * write */
        struct ntb_list ready_objects;
        struct ntb_list objects_to_load;

        /* The last time we wrote anything to the socket. This is used
         * to determine when we need to send a pong event to keep the
         * connection alive */
        uint64_t last_write_time;
        /* Similarly for the last time we received anything. This is
         * used to detect peers that have gone silent */
        uint64_t last_read_time;
};

struct ntb_connection_queue_entry {
        struct ntb_list link;
        uint8_t hash[NTB_PROTO_HASH_LENGTH];
        struct ntb_blob *blob;
};

NTB_SLICE_ALLOCATOR(struct ntb_connection,
                    ntb_connection_allocator);
NTB_SLICE_ALLOCATOR(struct ntb_connection_queue_entry,
                    ntb_connection_queue_entry_allocator);

static bool
emit_event(struct ntb_connection *conn,
           enum ntb_connection_event_type type,
           struct ntb_connection_event *event)
{
        event->type = type;
        event->connection = conn;
        return ntb_signal_emit(&conn->event_signal, event);
}

static void
remove_sources(struct ntb_connection *conn)
{
        if (conn->socket_source) {
                ntb_main_context_remove_source(conn->socket_source);
                conn->socket_source = NULL;
        }
        if (conn->timer_source) {
                ntb_main_context_remove_source(conn->timer_source);
                conn->timer_source = NULL;
        }
}

static void
set_error_state(struct ntb_connection *conn)
{
        struct ntb_connection_event event;

        /* Stop polling for further events */
        remove_sources(conn);

        emit_event(conn,
                   conn->connect_succeeded ?
                   NTB_CONNECTION_EVENT_ERROR :
                   NTB_CONNECTION_EVENT_CONNECT_FAILED,
                   &event);
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
connection_is_ready_to_write(struct ntb_connection *conn)
{
        return (conn->out_buf.length > 0 ||
                !ntb_list_empty(&conn->ready_objects));
}

static void
update_poll_flags(struct ntb_connection *conn)
{
        enum ntb_main_context_poll_flags flags = NTB_MAIN_CONTEXT_POLL_IN;

        if (connection_is_ready_to_write(conn))
                flags |= NTB_MAIN_CONTEXT_POLL_OUT;

        ntb_main_context_modify_poll(conn->socket_source, flags);
}

static bool
addr_command_handler(struct ntb_connection *conn,
                     const uint8_t *data,
                     uint32_t command_length)
{
        struct ntb_connection_addr_event event;
        uint64_t n_addresses;
        ssize_t addr_length;

        if (!ntb_proto_get_var_int(&data, &command_length, &n_addresses))
                goto error;

        while (n_addresses--) {
                addr_length =
                        ntb_proto_get_command(data,
                                              command_length,

                                              NTB_PROTO_ARGUMENT_TIMESTAMP,
                                              &event.timestamp,

                                              NTB_PROTO_ARGUMENT_32,
                                              &event.stream,

                                              NTB_PROTO_ARGUMENT_64,
                                              &event.services,

                                              NTB_PROTO_ARGUMENT_NETADDRESS,
                                              &event.address,

                                              NTB_PROTO_ARGUMENT_END);

                if (addr_length == -1)
                        goto error;

                command_length -= addr_length;
                data += addr_length;

                if (!emit_event(conn,
                                NTB_CONNECTION_EVENT_ADDR,
                                &event.base))
                        return false;
        }

        return true;

error:
        ntb_log("Invalid addr command received from %s",
                conn->remote_address_string);
        set_error_state(conn);
        return false;
}

static bool
getdata_command_handler(struct ntb_connection *conn,
                        const uint8_t *data,
                        uint32_t command_length)
{
        struct ntb_connection_getdata_event event;

        if (!ntb_proto_get_var_int(&data, &command_length, &event.n_hashes))
                goto error;

        if (command_length < event.n_hashes * NTB_PROTO_HASH_LENGTH)
                goto error;

        event.hashes = data;

        return emit_event(conn,
                          NTB_CONNECTION_EVENT_GETDATA,
                          &event.base);

        return true;

error:
        ntb_log("Invalid addr command received from %s",
                conn->remote_address_string);
        set_error_state(conn);
        return false;
}

static bool
version_command_handler(struct ntb_connection *conn,
                        const uint8_t *data,
                        uint32_t command_length)
{
        struct ntb_connection_version_event event;
        uint64_t dummy_64;

        if (ntb_proto_get_command(data,
                                  command_length,

                                  NTB_PROTO_ARGUMENT_32,
                                  &event.version,

                                  NTB_PROTO_ARGUMENT_64,
                                  &event.services,

                                  NTB_PROTO_ARGUMENT_TIMESTAMP,
                                  &event.timestamp,

                                  NTB_PROTO_ARGUMENT_64,
                                  &dummy_64,
                                  NTB_PROTO_ARGUMENT_NETADDRESS,
                                  &event.addr_recv,

                                  NTB_PROTO_ARGUMENT_64,
                                  &dummy_64,
                                  NTB_PROTO_ARGUMENT_NETADDRESS,
                                  &event.addr_from,

                                  NTB_PROTO_ARGUMENT_64,
                                  &event.nonce,

                                  NTB_PROTO_ARGUMENT_VAR_STR,
                                  &event.user_agent,

                                  NTB_PROTO_ARGUMENT_VAR_INT_LIST,
                                  &event.stream_numbers,

                                  NTB_PROTO_ARGUMENT_END) == -1) {
                ntb_log("Invalid version command received from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        return emit_event(conn,
                          NTB_CONNECTION_EVENT_VERSION,
                          &event.base);
}

static bool
verack_command_handler(struct ntb_connection *conn,
                       const uint8_t *data,
                       uint32_t command_length)
{
        struct ntb_connection_event event;

        return emit_event(conn, NTB_CONNECTION_EVENT_VERACK, &event);
}

static bool
getpubkey_command_handler(struct ntb_connection *conn,
                          const uint8_t *data,
                          uint32_t command_length)
{
        struct ntb_connection_object_event event;
        ssize_t header_length;
        uint64_t address_version;

        event.type = NTB_PROTO_INV_TYPE_GETPUBKEY;
        event.object_data_length = command_length;
        event.object_data = data;

        header_length = ntb_proto_get_command(data,
                                              command_length,

                                              NTB_PROTO_ARGUMENT_64,
                                              &event.nonce,

                                              NTB_PROTO_ARGUMENT_TIMESTAMP,
                                              &event.timestamp,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &address_version,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &event.stream_number,

                                              NTB_PROTO_ARGUMENT_END);

        if (header_length == -1) {
                ntb_log("Invalid getpubkey command received from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        return emit_event(conn,
                          NTB_CONNECTION_EVENT_OBJECT,
                          &event.base);
}

static bool
pubkey_command_handler(struct ntb_connection *conn,
                       const uint8_t *data,
                       uint32_t command_length)
{
        struct ntb_connection_object_event event;
        ssize_t header_length;
        uint64_t address_version;

        event.type = NTB_PROTO_INV_TYPE_PUBKEY;
        event.object_data_length = command_length;
        event.object_data = data;

        header_length = ntb_proto_get_command(data,
                                              command_length,

                                              NTB_PROTO_ARGUMENT_64,
                                              &event.nonce,

                                              NTB_PROTO_ARGUMENT_TIMESTAMP,
                                              &event.timestamp,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &address_version,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &event.stream_number,

                                              NTB_PROTO_ARGUMENT_END);

        if (header_length == -1) {
                ntb_log("Invalid pubkey command received from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        return emit_event(conn,
                          NTB_CONNECTION_EVENT_OBJECT,
                          &event.base);
}

static bool
msg_command_handler(struct ntb_connection *conn,
                    const uint8_t *data,
                    uint32_t command_length)
{
        struct ntb_connection_object_event event;
        ssize_t header_length;

        event.type = NTB_PROTO_INV_TYPE_MSG;
        event.object_data_length = command_length;
        event.object_data = data;

        header_length = ntb_proto_get_command(data,
                                              command_length,

                                              NTB_PROTO_ARGUMENT_64,
                                              &event.nonce,

                                              NTB_PROTO_ARGUMENT_TIMESTAMP,
                                              &event.timestamp,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &event.stream_number,

                                              NTB_PROTO_ARGUMENT_END);

        if (header_length == -1) {
                ntb_log("Invalid msg command received from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        return emit_event(conn,
                          NTB_CONNECTION_EVENT_OBJECT,
                          &event.base);
}

static bool
broadcast_command_handler(struct ntb_connection *conn,
                          const uint8_t *data,
                          uint32_t command_length)
{
        struct ntb_connection_object_event event;
        ssize_t header_length;
        uint64_t broadcast_version;

        event.type = NTB_PROTO_INV_TYPE_BROADCAST;
        event.object_data_length = command_length;
        event.object_data = data;

        header_length = ntb_proto_get_command(data,
                                              command_length,

                                              NTB_PROTO_ARGUMENT_64,
                                              &event.nonce,

                                              NTB_PROTO_ARGUMENT_TIMESTAMP,
                                              &event.timestamp,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &broadcast_version,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &event.stream_number,

                                              NTB_PROTO_ARGUMENT_END);

        if (header_length == -1) {
                ntb_log("Invalid msg command received from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        return emit_event(conn,
                          NTB_CONNECTION_EVENT_OBJECT,
                          &event.base);
}

static bool
inv_command_handler(struct ntb_connection *conn,
                    const uint8_t *data,
                    uint32_t command_length)
{
        struct ntb_connection_inv_event event;

        if (!ntb_proto_get_var_int(&data,
                                   &command_length,
                                   &event.n_inventories) ||
            command_length < event.n_inventories * NTB_PROTO_HASH_LENGTH) {
                ntb_log("Invalid inv command received from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        event.inventories = data;

        return emit_event(conn,
                          NTB_CONNECTION_EVENT_INV,
                          &event.base);
}

static void
send_pong(struct ntb_connection *conn)
{
        ntb_proto_add_command(&conn->out_buf, "pong", NTB_PROTO_ARGUMENT_END);
        update_poll_flags(conn);
}

static bool
ping_command_handler(struct ntb_connection *conn,
                     const uint8_t *data,
                     uint32_t command_length)
{
        send_pong(conn);

        return true;
}

static const struct {
        const char *command_name;
        bool (* func)(struct ntb_connection *conn,
                      const uint8_t *data,
                      uint32_t command_length);
} command_handlers[] = {
        { "getpubkey", getpubkey_command_handler },
        { "pubkey", pubkey_command_handler },
        { "msg", msg_command_handler },
        { "broadcast", broadcast_command_handler },
        { "inv", inv_command_handler },
        { "version", version_command_handler },
        { "addr", addr_command_handler },
        { "getdata", getdata_command_handler },
        { "verack", verack_command_handler },
        { "ping", ping_command_handler }
};

static bool
process_command(struct ntb_connection *conn,
                const uint8_t *data,
                uint32_t command_length)
{
        char hex_a[9], hex_b[9];
        uint8_t hash[SHA512_DIGEST_LENGTH];
        int i;

        if (memcmp(data, ntb_proto_magic, sizeof ntb_proto_magic)) {
                get_hex_string(data, sizeof ntb_proto_magic, hex_a);
                ntb_log("Invalid command magic from %s (%s)",
                        conn->remote_address_string, hex_a);
                set_error_state(conn);
                return false;
        }

        if (!ntb_proto_check_command_string(data + 4)) {
                ntb_log("Invalid command string from %s",
                        conn->remote_address_string);
                set_error_state(conn);
                return false;
        }

        SHA512(data + NTB_PROTO_HEADER_SIZE, command_length, hash);

        /* Compare the checksum */
        if (memcmp(hash, data + 20, 4)) {
                get_hex_string(data + 20, 4, hex_a);
                get_hex_string(hash, 4, hex_b);
                ntb_log("Invalid checksum for %s command "
                        "received from %s (%s != %s)",
                        data + 4,
                        conn->remote_address_string,
                        hex_a,
                        hex_b);
                set_error_state(conn);
                return false;
        }

        for (i = 0; i < NTB_N_ELEMENTS(command_handlers); i++) {
                if (!strcmp((const char *) data + 4,
                            command_handlers[i].command_name))
                        return command_handlers[i].func(conn,
                                                        data +
                                                        NTB_PROTO_HEADER_SIZE,
                                                        command_length);
        }

        /* Unknown command which we'll just ignore */
        return true;
}

static void
process_commands(struct ntb_connection *conn)
{
        uint32_t command_length;
        uint8_t *data = conn->in_buf.data;
        size_t length = conn->in_buf.length;

        while (true) {
                if (length < NTB_PROTO_HEADER_SIZE)
                        break;

                command_length = ntb_proto_get_32(data + 16);

                /* Limit the length of a command or the client would
                 * be able to pretend it's going to send a really long
                 * message and we'd just keep growing the buffer
                 * until we run out of memory and abort */
                if (command_length > NTB_CONNECTION_MAX_MESSAGE_SIZE) {
                        ntb_log("Client %s sent a command that is too long "
                                "(%" PRIu32 ")",
                                conn->remote_address_string,
                                command_length);
                        set_error_state(conn);
                        return;
                }

                if (length < NTB_PROTO_HEADER_SIZE + command_length)
                        break;

                if (!process_command(conn, data, command_length))
                        return;

                data += command_length + NTB_PROTO_HEADER_SIZE;
                length -= command_length + NTB_PROTO_HEADER_SIZE;
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

        do {
                got = read(conn->sock,
                           conn->in_buf.data + conn->in_buf.length,
                           conn->in_buf.size - conn->in_buf.length);
        } while (got == -1 && errno == EINTR);

        if (got == 0) {
                ntb_log("Connection closed for %s",
                        conn->remote_address_string);
                set_error_state(conn);
        } else if (got == -1) {
                if (ntb_file_error_from_errno(errno) != NTB_FILE_ERROR_AGAIN) {
                        ntb_log("Error reading from socket for %s: %s",
                                conn->remote_address_string,
                                strerror(errno));
                        set_error_state(conn);
                }
        } else {
                conn->last_read_time =
                        ntb_main_context_get_monotonic_clock(NULL);
                conn->in_buf.length += got;
                process_commands(conn);
        }
}

static void
load_cb(struct ntb_blob *blob,
        void *user_data)
{
        struct ntb_connection *conn = user_data;
        struct ntb_connection_queue_entry *entry;

        assert(!ntb_list_empty(&conn->objects_to_load));

        entry = ntb_container_of(conn->objects_to_load.next, entry, link);

        assert(entry->blob == NULL);

        ntb_list_remove(&entry->link);
        entry->blob = ntb_blob_ref(blob);

        ntb_list_insert(conn->ready_objects.prev, &entry->link);

        conn->load_cookie = NULL;

        update_poll_flags(conn);
}

static void
maybe_queue_load(struct ntb_connection *conn)
{
        struct ntb_connection_queue_entry *entry;

        if (conn->load_cookie)
                return;

        /* We only want to load one blob at a time because we can
         * probably load items from the disk faster than we can write
         * to the socket so it we don't do this then it might end up
         * loading the whole database into memory if a peer requests
         * everything */
        if (!ntb_list_empty(&conn->ready_objects))
                return;

        if (ntb_list_empty(&conn->objects_to_load))
                return;

        entry = ntb_container_of(conn->objects_to_load.next, entry, link);
        conn->load_cookie = ntb_store_load_blob(NULL, /* default store */
                                                entry->hash,
                                                load_cb,
                                                conn);
}

void
ntb_connection_send_blob(struct ntb_connection *conn,
                         const uint8_t *hash,
                         struct ntb_blob *blob)
{
        struct ntb_connection_queue_entry *entry;

        entry = ntb_slice_alloc(&ntb_connection_queue_entry_allocator);

        memcpy(entry->hash, hash, NTB_PROTO_HASH_LENGTH);

        if (blob) {
                entry->blob = ntb_blob_ref(blob);
                ntb_list_insert(conn->ready_objects.prev, &entry->link);
                update_poll_flags(conn);
        } else {
                entry->blob = NULL;
                ntb_list_insert(conn->objects_to_load.prev, &entry->link);
                maybe_queue_load(conn);
        }
}

static void
free_queue_entry(struct ntb_connection_queue_entry *entry)
{
        if (entry->blob)
                ntb_blob_unref(entry->blob);
        ntb_list_remove(&entry->link);
        ntb_slice_free(&ntb_connection_queue_entry_allocator, entry);
}

static void
add_ready_objects(struct ntb_connection *conn)
{
        struct ntb_connection_queue_entry *entry;
        enum ntb_proto_inv_type type;
        const char *command_name;
        size_t command_start;

        /* Keep adding objects until we either run out or we've filled
         * 1024 bytes. We don't want to add too many in one go because
         * otherwise we'll just be pointlessly copying all of the data
         * to another buffer. The socket buffer wouldn't be large
         * enough to hold all of them */
        while (conn->out_buf.length < 1024 &&
               !ntb_list_empty(&conn->ready_objects)) {
                entry = ntb_container_of(conn->ready_objects.next, entry, link);
                type = entry->blob->type;
                command_name = ntb_proto_get_command_name_for_type(type);

                command_start = conn->out_buf.length;
                ntb_proto_begin_command(&conn->out_buf, command_name);
                ntb_buffer_append(&conn->out_buf,
                                  entry->blob->data,
                                  entry->blob->size);
                ntb_proto_end_command(&conn->out_buf, command_start);

                free_queue_entry(entry);

                maybe_queue_load(conn);
        }
}

static void
handle_write(struct ntb_connection *conn)
{
        int wrote;

        add_ready_objects(conn);

        do {
                wrote = write(conn->sock,
                              conn->out_buf.data,
                              conn->out_buf.length);
        } while (wrote == -1 && errno == EINTR);

        if (wrote == -1) {
                if (ntb_file_error_from_errno(errno) != NTB_FILE_ERROR_AGAIN) {
                        ntb_log("Error writing to socket for %s: %s",
                                conn->remote_address_string,
                                strerror(errno));
                        set_error_state(conn);
                }
        } else {
                memmove(conn->out_buf.data,
                        conn->out_buf.data + wrote,
                        conn->out_buf.length - wrote);
                conn->out_buf.length -= wrote;

                conn->last_write_time =
                        ntb_main_context_get_monotonic_clock(NULL);

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
        if ((flags & (NTB_MAIN_CONTEXT_POLL_OUT |
                      NTB_MAIN_CONTEXT_POLL_ERROR)) ==
            NTB_MAIN_CONTEXT_POLL_OUT &&
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

static void
pong_check_cb(struct ntb_main_context_source *source,
              void *user_data)
{
        struct ntb_connection *conn = user_data;
        uint64_t now = ntb_main_context_get_monotonic_clock(NULL);

        if ((now - conn->last_read_time) / 1000000 >= NTB_CONNECTION_TIMEOUT) {
                ntb_log("No data received from %s for %" PRIu64 " seconds. "
                        "Closing connection",
                        conn->remote_address_string,
                        (now - conn->last_read_time) / 1000000);
                set_error_state(conn);
                return;
        }

        if ((now - conn->last_write_time) / 1000000 >=
            NTB_CONNECTION_PONG_INTERVAL &&
            !connection_is_ready_to_write(conn))
                send_pong(conn);
}

static void
free_queue_entry_list(struct ntb_list *list)
{
        struct ntb_connection_queue_entry *entry, *tmp;

        ntb_list_for_each_safe(entry, tmp, list, link)
                free_queue_entry(entry);
}

void
ntb_connection_free(struct ntb_connection *conn)
{
        remove_sources(conn);

        free_queue_entry_list(&conn->ready_objects);
        free_queue_entry_list(&conn->objects_to_load);

        if (conn->load_cookie)
                ntb_store_cancel_task(conn->load_cookie);

        ntb_free(conn->remote_address_string);
        ntb_buffer_destroy(&conn->in_buf);
        ntb_buffer_destroy(&conn->out_buf);
        ntb_close(conn->sock);

        ntb_slice_free(&ntb_connection_allocator, conn);
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

        ntb_signal_init(&conn->event_signal);

        conn->socket_source =
                ntb_main_context_add_poll(NULL, /* context */
                                          sock,
                                          NTB_MAIN_CONTEXT_POLL_IN,
                                          connection_poll_cb,
                                          conn);
        conn->timer_source =
                ntb_main_context_add_timer(NULL,
                                           NTB_CONNECTION_PONG_CHECK_INTERVAL,
                                           pong_check_cb,
                                           conn);

        ntb_buffer_init(&conn->in_buf);
        ntb_buffer_init(&conn->out_buf);

        ntb_list_init(&conn->objects_to_load);
        ntb_list_init(&conn->ready_objects);
        conn->load_cookie = NULL;

        conn->last_write_time = ntb_main_context_get_monotonic_clock(NULL);
        conn->last_read_time = conn->last_write_time;

        return conn;
}

struct ntb_signal *
ntb_connection_get_event_signal(struct ntb_connection *conn)
{
        return &conn->event_signal;
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
        char *address_string;
        int sock;

        ntb_netaddress_to_native(address, &native_address);

        sock = socket(native_address.sockaddr.sa_family == AF_INET6 ?
                      PF_INET6 : PF_INET,
                      SOCK_STREAM,
                      0);
        if (sock == -1) {
                ntb_file_error_set(error,
                                   errno,
                                   "Failed to create socket: %s",
                                   strerror(errno));
                return NULL;
        }

        if (!ntb_socket_set_nonblock(sock, error)) {
                ntb_close(sock);
                return NULL;
        }

        if (connect(sock,
                    &native_address.sockaddr,
                    native_address.length) == -1 &&
            errno != EINPROGRESS) {
                address_string = ntb_netaddress_to_string(address);
                ntb_file_error_set(error,
                                   errno,
                                   "Failed to connect to %s: %s",
                                   address_string,
                                   strerror(errno));
                ntb_free(address_string);
                ntb_close(sock);
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

        native_address.length = sizeof native_address.sockaddr_in6;

        do {
                sock = accept(server_sock,
                              &native_address.sockaddr,
                              &native_address.length);
        } while (sock == -1 && errno == EINTR);

        if (sock == -1) {
                ntb_file_error_set(error,
                                   errno,
                                   "Error accepting connection: %s",
                                   strerror(errno));
                return NULL;
        }

        if (!ntb_socket_set_nonblock(sock, error)) {
                ntb_close(sock);
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
                            uint16_t local_port)
{
        struct ntb_netaddress local_address;

        /* The address part of the local address is ignored by the
         * peers because they can just use the public-facing remote
         * peer address instead. In order to avoid giving away
         * unnecessary information about the local network we'll send
         * zeroes here instead */
        memset(local_address.host, 0, sizeof(local_address.host));
        local_address.port = local_port;

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
                              &local_address,

                              NTB_PROTO_ARGUMENT_64,
                              nonce,

                              NTB_PROTO_ARGUMENT_VAR_STR,
                              "/notbit:" VERSION "/",

                              /* Number of streams */
                              NTB_PROTO_ARGUMENT_VAR_INT,
                              UINT64_C(1),

                              /* The one stream */
                              NTB_PROTO_ARGUMENT_VAR_INT,
                              UINT64_C(1),

                              NTB_PROTO_ARGUMENT_END);

        update_poll_flags(conn);
}

static int
get_n_hashes_for_command(struct ntb_connection *conn)
{
        return (conn->out_buf.length -
                conn->command_start -
                1 -
                NTB_PROTO_HEADER_SIZE) / NTB_PROTO_HASH_LENGTH;
}

static void
begin_hash_command(struct ntb_connection *conn,
                   const char *command)
{
        conn->command_start = conn->out_buf.length;

        ntb_proto_begin_command(&conn->out_buf, command);

        /* Reserve space for a 1-byte varint. If we need more than
         * this then we'll split the command up on the fly */
        ntb_buffer_ensure_size(&conn->out_buf, conn->out_buf.length + 1);
        conn->out_buf.length += 1;
}

static void
end_hash_command(struct ntb_connection *conn)
{
        int n_hashes = get_n_hashes_for_command(conn);

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

static void
add_hash_for_command(struct ntb_connection *conn,
                     const char *command,
                     const uint8_t *hash)
{
        int n_hashes = get_n_hashes_for_command(conn);

        /* If we can't fit further hashes into a 1-byte varint then
         * we'll start another command */
        if (n_hashes >= 0xfc) {
                end_hash_command(conn);
                begin_hash_command(conn, command);
        }

        ntb_buffer_append(&conn->out_buf, hash, NTB_PROTO_HASH_LENGTH);
}

void
ntb_connection_begin_getdata(struct ntb_connection *conn)
{
        begin_hash_command(conn, "getdata");
}

void
ntb_connection_add_getdata_hash(struct ntb_connection *conn,
                                const uint8_t *hash)
{
        add_hash_for_command(conn, "getdata", hash);
}

void
ntb_connection_end_getdata(struct ntb_connection *conn)
{
        end_hash_command(conn);
}

void
ntb_connection_begin_inv(struct ntb_connection *conn)
{
        begin_hash_command(conn, "inv");
}

void
ntb_connection_add_inv_hash(struct ntb_connection *conn,
                                const uint8_t *hash)
{
        add_hash_for_command(conn, "inv", hash);
}

void
ntb_connection_end_inv(struct ntb_connection *conn)
{
        end_hash_command(conn);
}

void
ntb_connection_begin_addr(struct ntb_connection *conn)
{
        conn->command_start = conn->out_buf.length;

        ntb_proto_begin_command(&conn->out_buf, "addr");

        /* Reserve space for a 1-byte varint. If we need more than
         * this then we'll split the command up on the fly */
        ntb_buffer_ensure_size(&conn->out_buf, conn->out_buf.length + 1);
        conn->out_buf.length += 1;
}

static int
get_n_hashes_for_addr(struct ntb_connection *conn)
{
        return (conn->out_buf.length -
                conn->command_start -
                1 -
                NTB_PROTO_HEADER_SIZE) /
                (sizeof (uint64_t) +
                 sizeof (uint32_t) +
                 sizeof (uint64_t) +
                 16 + 2);
}

void
ntb_connection_add_addr_address(struct ntb_connection *conn,
                                int64_t timestamp,
                                uint32_t stream,
                                uint64_t services,
                                const struct ntb_netaddress *address)
{
        int n_hashes = get_n_hashes_for_addr(conn);

        /* If we can't fit further hashes into a 1-byte varint then
         * we'll start another command */
        if (n_hashes >= 0xfc) {
                ntb_connection_end_addr(conn);
                ntb_connection_begin_addr(conn);
        }

        ntb_proto_add_64(&conn->out_buf, timestamp);
        ntb_proto_add_32(&conn->out_buf, stream);
        ntb_proto_add_64(&conn->out_buf, services);
        ntb_proto_add_netaddress(&conn->out_buf, address);
}

void
ntb_connection_end_addr(struct ntb_connection *conn)
{
        int n_hashes = get_n_hashes_for_addr(conn);

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
