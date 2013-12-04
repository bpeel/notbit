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
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <inttypes.h>

#include "ntb-util.h"
#include "ntb-slice.h"
#include "ntb-connection.h"
#include "ntb-log.h"
#include "ntb-list.h"
#include "ntb-network.h"
#include "ntb-hash-table.h"
#include "ntb-pow.h"

struct ntb_error_domain
ntb_network_error;

/* We will always try to keep at least this many connections open to
 * the network */
#define NTB_NETWORK_TARGET_NUM_PEERS 8

/* If an object is older than this in seconds then we won't bother
 * keeping it in memory. It will need to be retrieved from disk if
 * something requests it */
#define NTB_NETWORK_INV_CACHE_AGE (10 * 60)
/* If any objects claim to be created this far in the future then
 * we'll ignore them */
#define NTB_NETWORK_INV_FUTURE_AGE 60

struct ntb_network_peer {
        struct ntb_list link;
        struct ntb_netaddress address;
        struct ntb_connection *connection;
        struct ntb_listener message_listener;
        struct ntb_network *network;

        struct ntb_list requested_inventories;
};

struct ntb_network_listen_socket {
        struct ntb_list link;
        int sock;
};

struct ntb_network {
        struct ntb_list listen_sockets;
        struct ntb_list peers;
        int n_connected_peers;
        int n_unconnected_peers;

        struct ntb_store *store;

        struct ntb_main_context_source *connect_queue_source;
        bool connect_queue_source_is_idle;

        uint64_t nonce;

        struct ntb_hash_table *inventory_hash;

        struct ntb_list msgs;
        struct ntb_list rejected_inventories;
};

enum ntb_network_inventory_type {
        NTB_NETWORK_INVENTORY_TYPE_STUB,
        NTB_NETWORK_INVENTORY_TYPE_MSG,
        /* Rejected objects are those that we have received but that
         * we don't care about, such as those whose proof-of-work is
         * too low or that have a bad time stamp */
        NTB_NETWORK_INVENTORY_TYPE_REJECTED
};

struct ntb_network_inventory {
        enum ntb_network_inventory_type type;
        uint8_t hash[NTB_PROTO_HASH_LENGTH];

        /* Each inventory will be in a list. Which list that is
         * depends on the type. For stub types it will be within the
         * list of requested items for a peer. The other types each
         * have their list in ntb_network */
        struct ntb_list link;

        union {
                struct {
                        /* Monotonic time that we sent a request for
                         * this item */
                        uint64_t last_request_time;
                };

                struct ntb_blob *blob;
        };
};

NTB_SLICE_ALLOCATOR(struct ntb_network_inventory,
                    ntb_network_inventory_allocator);

NTB_SLICE_ALLOCATOR(struct ntb_network_peer,
                    ntb_network_peer_allocator);

static const struct {
        const char *address;
        int port;
} default_peers[] = {
#if 0
        /* These are the addresses from the official Python client */
        { "176.31.246.114", 8444 },
        { "109.229.197.133", 8444 },
        { "174.3.101.111", 8444 },
        { "90.188.238.79", 7829 },
        { "184.75.69.2", 8444 },
        { "60.225.209.243", 8444 },
        { "5.145.140.218", 8444 },
        { "5.19.255.216", 8444 },
        { "193.159.162.189", 8444 },
        { "86.26.15.171", 8444 },
#endif
        /* For testing, it'll only connect to localhost */
        { "127.0.0.1", 8444 }
};

static void
maybe_queue_connect(struct ntb_network *nw);

static bool
address_string_to_native(const char *address,
                         int port,
                         struct ntb_netaddress_native *native,
                         struct ntb_error **error)
{
        if (address == NULL || *address == '\0') {
                native->sockaddr_in.sin_family = AF_INET;
                native->sockaddr_in.sin_addr.s_addr = htonl(INADDR_ANY);
                native->sockaddr_in.sin_port = htons(port);
                native->length = sizeof native->sockaddr_in;
                return true;
        }

        if (strchr(address, ':')) {
                if (inet_pton(AF_INET6,
                              address,
                              &native->sockaddr_in6.sin6_addr) <= 0)
                        goto error;
                native->sockaddr_in6.sin6_family = AF_INET6;
                native->sockaddr_in6.sin6_port = htons(port);
                native->sockaddr_in6.sin6_flowinfo = 0;
                native->length = sizeof native->sockaddr_in6;
        } else {
                if (inet_pton(AF_INET,
                              address,
                              &native->sockaddr_in.sin_addr) <= 0)
                        goto error;
                native->sockaddr_in.sin_family = AF_INET;
                native->sockaddr_in.sin_port = htons(port);
                native->length = sizeof native->sockaddr_in;
        }

        return true;

error:
        ntb_set_error(error,
                      &ntb_network_error,
                      NTB_NETWORK_ERROR_INVALID_ADDRESS,
                      "Invalid IP address \"%s\"",
                      address);
        return false;
}

static void
remove_connect_queue_source(struct ntb_network *nw)
{
        if (nw->connect_queue_source) {
                ntb_main_context_remove_source(nw->connect_queue_source);
                nw->connect_queue_source = NULL;
        }
}

static void
free_inventory(struct ntb_network_inventory *inv)
{
        switch (inv->type) {
        case NTB_NETWORK_INVENTORY_TYPE_MSG:
                if (inv->blob)
                        ntb_blob_unref(inv->blob);
                break;
        case NTB_NETWORK_INVENTORY_TYPE_STUB:
        case NTB_NETWORK_INVENTORY_TYPE_REJECTED:
                break;
        }

        ntb_slice_free(&ntb_network_inventory_allocator, inv);
}

static void
close_connection(struct ntb_network *nw,
                 struct ntb_network_peer *peer)
{
        struct ntb_network_inventory *inventory, *tmp;

        if (peer->connection == NULL)
                return;

        ntb_list_for_each_safe(inventory, tmp,
                               &peer->requested_inventories,
                               link) {
                ntb_hash_table_remove(nw->inventory_hash, inventory);
                free_inventory(inventory);
        }

        ntb_connection_free(peer->connection);
        peer->connection = NULL;

        nw->n_unconnected_peers++;
        nw->n_connected_peers--;

        maybe_queue_connect(nw);
}

static void
remove_peer(struct ntb_network *nw,
            struct ntb_network_peer *peer)
{
        close_connection(nw, peer);
        nw->n_unconnected_peers--;
        ntb_list_remove(&peer->link);
        ntb_slice_free(&ntb_network_peer_allocator, peer);
}

static void
connect_queue_cb(struct ntb_main_context_source *source,
                 void *user_data)
{
        struct ntb_network *nw = user_data;
        struct ntb_network_peer *peer;
        struct ntb_error *error = NULL;
        struct ntb_signal *message_signal;
        int peer_num;

        /* If we've reached the number of connected peers then we can
         * stop trying to connect any more. There's also no point in
         * continuing if we've run out of unconnected peers */
        if (nw->n_connected_peers >= NTB_NETWORK_TARGET_NUM_PEERS ||
            nw->n_unconnected_peers <= 0) {
                remove_connect_queue_source(nw);
                return;
        }

        /* Pick a random peer so that we don't accidentally favour the
         * list we retrieve from any particular peer */
        peer_num = (uint64_t) rand() * nw->n_unconnected_peers / RAND_MAX;

        ntb_list_for_each(peer, &nw->peers, link) {
                if (peer_num-- <= 0)
                        break;
        }

        peer->connection = ntb_connection_connect(&peer->address, &error);

        if (peer->connection == NULL) {
                ntb_log("%s", error->message);
                ntb_error_clear(&error);

                /* If it's not possible to connect to this peer then
                 * we'll assume it's dead */
                remove_peer(nw, peer);
        } else {
                nw->n_connected_peers++;
                nw->n_unconnected_peers--;

                ntb_connection_send_version(peer->connection, nw->nonce);

                message_signal =
                        ntb_connection_get_message_signal(peer->connection);
                ntb_signal_add(message_signal, &peer->message_listener);

                /* Once we reach half the target number of peers then
                 * we'll switch to a minute timer for the remaining
                 * peers */
                if (nw->connect_queue_source_is_idle &&
                    nw->n_connected_peers >= NTB_NETWORK_TARGET_NUM_PEERS / 2) {
                        remove_connect_queue_source(nw);
                        maybe_queue_connect(nw);
                }
        }
}

static void
maybe_queue_connect(struct ntb_network *nw)
{
        /* If we've already got enough peers then we don't need to do
         * anything */
        if (nw->n_connected_peers >= NTB_NETWORK_TARGET_NUM_PEERS)
                return;

        /* Same if we've already queued a connect */
        if (nw->connect_queue_source != NULL)
                return;

        /* Or if we don't have any peers to connect to */
        if (nw->n_unconnected_peers <= 0)
                return;

        /* For the first half of the peers we'll connect on idle so
         * that we'll connect really quickly. Otherwise we'll use a 1
         * minute timer so that we have a chance to receive details of
         * other peers */
        if (nw->n_connected_peers < NTB_NETWORK_TARGET_NUM_PEERS / 2) {
                nw->connect_queue_source =
                        ntb_main_context_add_idle(NULL,
                                                  connect_queue_cb,
                                                  nw);
                nw->connect_queue_source_is_idle = true;
        } else {
                nw->connect_queue_source =
                        ntb_main_context_add_timer(NULL,
                                                   1, /* minutes */
                                                   connect_queue_cb,
                                                   nw);
                nw->connect_queue_source_is_idle = false;
        }
}

static bool
handle_version(struct ntb_network *nw,
               struct ntb_network_peer *peer,
               struct ntb_connection_version_message *message)
{
        const char *remote_address_string =
                ntb_connection_get_remote_address_string(peer->connection);

        if (message->nonce == nw->nonce) {
                ntb_log("Connected to self from %s", remote_address_string);
                close_connection(nw, peer);
                return false;
        }

        if (message->version != NTB_PROTO_VERSION) {
                ntb_log("Client %s is using unsupported protocol version "
                        "%" PRIu32,
                        remote_address_string,
                        message->version);
                remove_peer(nw, peer);
                return false;
        }

        ntb_connection_send_verack(peer->connection);

        return true;
}

static void
request_inventory(struct ntb_network *nw,
                  struct ntb_network_peer *peer,
                  const uint8_t *hash)
{
        struct ntb_network_inventory *inv;

        inv = ntb_slice_alloc(&ntb_network_inventory_allocator);

        inv->type = NTB_NETWORK_INVENTORY_TYPE_STUB;
        memcpy(inv->hash, hash, NTB_PROTO_HASH_LENGTH);

        inv->last_request_time = ntb_main_context_get_monotonic_clock(NULL);

        ntb_list_insert(&peer->requested_inventories, &inv->link);

        ntb_hash_table_set(nw->inventory_hash, inv);

        ntb_connection_add_getdata_hash(peer->connection, hash);
}

static bool
handle_inv(struct ntb_network *nw,
           struct ntb_network_peer *peer,
           struct ntb_connection_inv_message *message)
{
        struct ntb_network_inventory *inv;
        const uint8_t *hash;
        uint64_t i;

        ntb_connection_begin_getdata(peer->connection);

        for (i = 0; i < message->n_inventories; i++) {
                hash = message->inventories + i * NTB_PROTO_HASH_LENGTH;
                inv = ntb_hash_table_get(nw->inventory_hash, hash);

                if (inv == NULL)
                        request_inventory(nw, peer, hash);
        }

        ntb_connection_end_getdata(peer->connection);

        return true;
}

static bool
should_reject(struct ntb_network_peer *peer,
              const char *type,
              const uint8_t *payload,
              size_t payload_length,
              int64_t age)
{
        const char *remote_address_string =
                ntb_connection_get_remote_address_string(peer->connection);

        if (age <= -NTB_NETWORK_INV_FUTURE_AGE) {
                ntb_log("Rejecting %s from %s which was created "
                        "%" PRIi64 " seconds in the future",
                        type,
                        remote_address_string,
                        -age);
                return true;
        }

        if (age >= NTB_PROTO_MAX_INV_AGE) {
                ntb_log("Rejecting %s from %s which was created "
                        "%" PRIi64 " seconds ago",
                        type,
                        remote_address_string,
                        age);
                return true;
        }

        if (!ntb_pow_check(payload,
                           payload_length,
                           14000, /* payload extra bytes */
                           320 /* average trials per byte */)) {
                ntb_log("Rejecting %s from %s because the proof-of-work is "
                        "too low",
                        type,
                        remote_address_string);
                return true;
        }

        return false;
}

static bool
handle_msg(struct ntb_network *nw,
           struct ntb_network_peer *peer,
           struct ntb_connection_msg_message *message)
{
        struct ntb_network_inventory *inv;
        uint8_t hash[NTB_PROTO_HASH_LENGTH];
        int64_t age;

        ntb_proto_double_hash(message->object_data,
                              message->object_data_length,
                              hash);

        inv = ntb_hash_table_get(nw->inventory_hash, hash);

        if (inv == NULL) {
                inv = ntb_slice_alloc(&ntb_network_inventory_allocator);
                memcpy(inv->hash, hash, NTB_PROTO_HASH_LENGTH);
                ntb_hash_table_set(nw->inventory_hash, inv);
        } else if (inv->type == NTB_NETWORK_INVENTORY_TYPE_STUB) {
                ntb_list_remove(&inv->link);
        } else {
                /* We've already got this msg so we'll just ignore it */
                return true;
        }

        age = ntb_main_context_get_wall_clock(NULL) - message->timestamp;

        if (should_reject(peer,
                          "msg",
                          message->object_data,
                          message->object_data_length,
                          age)) {
                inv->type = NTB_NETWORK_INVENTORY_TYPE_REJECTED;
                ntb_list_insert(&nw->rejected_inventories, &inv->link);
        } else {
                inv->type = NTB_NETWORK_INVENTORY_TYPE_MSG;
                inv->blob = ntb_blob_new(NTB_BLOB_TYPE_MSG,
                                         message->object_data,
                                         message->object_data_length);

                ntb_store_save_blob(nw->store, hash, inv->blob);

                /* If the blob is not quite new then we won't bother
                 * keeping it in memory under the assumption that's
                 * less likely that a peer will request it. If
                 * something does request it we'll have to load it
                 * from disk */
                if (age >= NTB_NETWORK_INV_CACHE_AGE) {
                        ntb_blob_unref(inv->blob);
                        inv->blob = NULL;
                }

                ntb_list_insert(&nw->msgs, &inv->link);
        }

        return true;
}

static bool
connection_message_cb(struct ntb_listener *listener,
                      void *data)
{
        struct ntb_connection_message *message = data;
        struct ntb_network_peer *peer =
                ntb_container_of(listener, peer, message_listener);
        struct ntb_network *nw = peer->network;

        switch (message->type) {
        case NTB_CONNECTION_MESSAGE_ERROR:
                close_connection(nw, peer);
                return false;

        case NTB_CONNECTION_MESSAGE_CONNECT_FAILED:
                /* If we never actually managed to connect to the peer
                 * then we'll assume it's a bad address and we'll stop
                 * trying to connect to it */
                remove_peer(nw, peer);
                return false;

        case NTB_CONNECTION_MESSAGE_VERSION:
                return handle_version(nw,
                                      peer,
                                      (struct ntb_connection_version_message *)
                                      message);

        case NTB_CONNECTION_MESSAGE_INV:
                return handle_inv(nw,
                                  peer,
                                  (struct ntb_connection_inv_message *)
                                  message);

        case NTB_CONNECTION_MESSAGE_MSG:
                return handle_msg(nw,
                                  peer,
                                  (struct ntb_connection_msg_message *)
                                  message);
        }

        return true;
}

static struct ntb_network_peer *
new_peer(struct ntb_network *nw)
{
        struct ntb_network_peer *peer;

        peer = ntb_slice_alloc(&ntb_network_peer_allocator);

        ntb_list_insert(&nw->peers, &peer->link);
        peer->connection = NULL;
        nw->n_unconnected_peers++;

        peer->message_listener.notify = connection_message_cb;
        peer->network = nw;

        ntb_list_init(&peer->requested_inventories);

        return peer;
}

struct ntb_network *
ntb_network_new(struct ntb_store *store)
{
        struct ntb_network *nw = ntb_alloc(sizeof *nw);
        struct ntb_network_peer *peer;
        struct ntb_netaddress_native native_address;
        size_t hash_offset;
        bool convert_result;
        int i;

        ntb_list_init(&nw->listen_sockets);
        ntb_list_init(&nw->peers);
        ntb_list_init(&nw->msgs);
        ntb_list_init(&nw->rejected_inventories);

        nw->store = store;

        nw->n_connected_peers = 0;
        nw->n_unconnected_peers = 0;
        nw->connect_queue_source = NULL;

        hash_offset = NTB_STRUCT_OFFSET(struct ntb_network_inventory, hash);
        nw->inventory_hash = ntb_hash_table_new(hash_offset);

        /* For some reason OpenSSL adds the unitialised bytes of this
         * buffer as a source of entropy. This trips up Valgrind so we
         * can avoid the problem by clearing it first. I don't think
         * this will affect the entropy because if it wasn't cleared
         * it would probably end up with a repeatable value anyway.
         * This value doesn't need to be cryptographically secure. */
        memset(&nw->nonce, 0, sizeof nw->nonce);
        RAND_pseudo_bytes((unsigned char *) &nw->nonce, sizeof nw->nonce);

        /* Add a hard-coded list of initial nodes which we can use to
         * discover more */
        for (i = 0; i < NTB_N_ELEMENTS(default_peers); i++) {
                peer = new_peer(nw);
                convert_result =
                        address_string_to_native(default_peers[i].address,
                                                 default_peers[i].port,
                                                 &native_address,
                                                 NULL);
                /* These addresses are hard-coded so they should
                 * always work */
                assert(convert_result);

                ntb_netaddress_from_native(&peer->address,
                                           &native_address);
        }

        maybe_queue_connect(nw);

        return nw;
}

bool
ntb_network_add_listen_address(struct ntb_network *nw,
                               const char *address,
                               int port,
                               struct ntb_error **error)
{
        struct ntb_network_listen_socket *listen_socket;
        struct ntb_netaddress_native native_address;
        int sock;

        if (!address_string_to_native(address, port, &native_address, error))
                return false;

        sock = socket(native_address.sockaddr.sa_family == AF_INET6 ?
                      PF_INET6 : PF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
                ntb_set_error(error,
                              &ntb_network_error,
                              NTB_NETWORK_ERROR_SOCKET,
                              "Failed to create socket: %s",
                              strerror(errno));
                return false;
        }

        if (bind(sock, &native_address.sockaddr, native_address.length) == -1) {
                ntb_set_error(error,
                              &ntb_network_error,
                              NTB_NETWORK_ERROR_SOCKET,
                              "Failed to bind socket: %s",
                              strerror(errno));
                goto error;
        }

        if (listen(sock, 10) == -1) {
                ntb_set_error(error,
                              &ntb_network_error,
                              NTB_NETWORK_ERROR_SOCKET,
                              "Failed to make socket listen: %s",
                              strerror(errno));
                goto error;
        }

        listen_socket = ntb_alloc(sizeof *listen_socket);
        listen_socket->sock = sock;
        ntb_list_insert(&nw->listen_sockets, &listen_socket->link);

        return true;

error:
        close(sock);
        return false;
}

static void
remove_listen_socket(struct ntb_network_listen_socket *listen_socket)
{
        ntb_list_remove(&listen_socket->link);
        close(listen_socket->sock);
        free(listen_socket);
}

static void
free_listen_sockets(struct ntb_network *nw)
{
        struct ntb_network_listen_socket *listen_socket, *tmp;

        ntb_list_for_each_safe(listen_socket, tmp, &nw->listen_sockets, link)
                remove_listen_socket(listen_socket);
}

static void
free_peers(struct ntb_network *nw)
{
        struct ntb_network_peer *peer, *tmp;

        ntb_list_for_each_safe(peer, tmp, &nw->peers, link)
                remove_peer(nw, peer);
}

static void
free_inventories_in_list(struct ntb_list *list)
{
        struct ntb_network_inventory *inv, *tmp;

        ntb_list_for_each_safe(inv, tmp, list, link)
                free_inventory(inv);
}

void
ntb_network_free(struct ntb_network *nw)
{
        free_peers(nw);
        free_listen_sockets(nw);
        free_inventories_in_list(&nw->msgs);
        free_inventories_in_list(&nw->rejected_inventories);

        ntb_hash_table_free(nw->inventory_hash);

        remove_connect_queue_source(nw);

        assert(nw->n_connected_peers == 0);
        assert(nw->n_unconnected_peers == 0);

        free(nw);
}
