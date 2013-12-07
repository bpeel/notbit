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
#include "ntb-store.h"

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
#define NTB_NETWORK_INV_FUTURE_AGE (30 * 60)

/* Time in minutes between each garbage collection run */
#define NTB_NETWORK_GC_TIMEOUT 10

/* Time in seconds after which we'll delete a stub inventory so that
 * we could get it again if another peer advertised it */
#define NTB_NETWORK_MAX_STUB_INVENTORY_AGE (5 * 60)

/* Time in seconds after which we'll stop advertising an addr */
#define NTB_NETWORK_MAX_ADDR_AGE (2 * 60 * 60)

/* Time in seconds before we'll retry connecting to an addr */
#define NTB_NETWORK_MIN_RECONNECT_TIME 60

enum ntb_network_peer_state {
        /* If we initiated the connection then we will go through these
         * two steps before the connection is considered established.
         * First we will send a version command, then wait for the
         * verack and then finally wait for the version. At that point
         * we will post a verack and we are connected */
        NTB_NETWORK_PEER_STATE_AWAITING_VERACK_OUT,
        NTB_NETWORK_PEER_STATE_AWAITING_VERSION_OUT,

        /* If the peer initiated the connection then we will go
         * through these two steps instead. First we will wait for a
         * version, then we will send a verack and a version, then we
         * will wait for a verack. Once we receive that we are
         * connected */
        NTB_NETWORK_PEER_STATE_AWAITING_VERSION_IN,
        NTB_NETWORK_PEER_STATE_AWAITING_VERACK_IN,

        NTB_NETWORK_PEER_STATE_CONNECTED
};

struct ntb_network_addr {
        struct ntb_list link;
        struct ntb_netaddress address;

        int64_t advertise_time;
        uint32_t stream;
        uint64_t services;

        uint64_t last_connect_time;

        bool connected;
};

struct ntb_network_peer {
        struct ntb_list link;
        struct ntb_connection *connection;
        struct ntb_network_addr *addr;
        struct ntb_listener message_listener;
        struct ntb_network *network;

        struct ntb_list requested_inventories;

        enum ntb_network_peer_state state;
};

struct ntb_network_listen_socket {
        struct ntb_list link;
        struct ntb_netaddress address;
        int sock;
        struct ntb_main_context_source *source;
        struct ntb_network *nw;
};

struct ntb_network {
        struct ntb_main_context_source *gc_source;

        struct ntb_list listen_sockets;

        int n_peers;
        struct ntb_list peers;

        int n_unconnected_addrs;
        struct ntb_list addrs;

        struct ntb_main_context_source *connect_queue_source;
        bool connect_queue_source_is_idle;

        uint64_t nonce;

        struct ntb_hash_table *inventory_hash;

        struct ntb_list accepted_inventories;
        struct ntb_list rejected_inventories;
};

enum ntb_network_inv_state {
        /* Stub objects are those that we have sent a requested for
         * but haven't received yet. We don't know anything about the
         * details of the object yet */
        NTB_NETWORK_INV_STATE_STUB,
        /* Rejected objects are those that we have received but that
         * we don't care about, such as those whose proof-of-work is
         * too low or that have a bad time stamp */
        NTB_NETWORK_INV_STATE_REJECTED,
        /* Accepted objects are those that we are willing to
         * distribute. These will either be in memory or on the disk
         * cache */
        NTB_NETWORK_INV_STATE_ACCEPTED
};

struct ntb_network_inventory {
        enum ntb_network_inv_state state;
        enum ntb_proto_inv_type type;
        uint8_t hash[NTB_PROTO_HASH_LENGTH];

        /* Each inventory will be in a list. Which list that is
         * depends on the state. For stub objects it will be within
         * the list of requested items for a peer. The other states
         * each have their own list in ntb_network */
        struct ntb_list link;

        union {
                struct {
                        /* Monotonic time that we sent a request for
                         * this item */
                        uint64_t last_request_time;
                };

                struct {
                        /* All types apart from the stub type
                         * (including the rejected inventories) have a
                         * timestamp which we'll use to garbage
                         * collect when the item gets too old */
                        int64_t timestamp;

                        struct ntb_blob *blob;
                };
        };
};

NTB_SLICE_ALLOCATOR(struct ntb_network_inventory,
                    ntb_network_inventory_allocator);
NTB_SLICE_ALLOCATOR(struct ntb_network_peer,
                    ntb_network_peer_allocator);
NTB_SLICE_ALLOCATOR(struct ntb_network_addr,
                    ntb_network_addr_allocator);

static const struct {
        const char *address;
        int port;
} default_addrs[] = {
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
maybe_queue_connect(struct ntb_network *nw, bool use_idle);

static bool
connection_message_cb(struct ntb_listener *listener,
                      void *data);

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
        switch (inv->state) {
        case NTB_NETWORK_INV_STATE_ACCEPTED:
                if (inv->blob)
                        ntb_blob_unref(inv->blob);
                break;
        case NTB_NETWORK_INV_STATE_STUB:
        case NTB_NETWORK_INV_STATE_REJECTED:
                break;
        }

        ntb_slice_free(&ntb_network_inventory_allocator, inv);
}

static void
remove_peer(struct ntb_network *nw,
                 struct ntb_network_peer *peer)
{
        struct ntb_network_inventory *inventory, *tmp;

        ntb_list_for_each_safe(inventory, tmp,
                               &peer->requested_inventories,
                               link) {
                ntb_hash_table_remove(nw->inventory_hash, inventory);
                free_inventory(inventory);
        }

        ntb_connection_free(peer->connection);

        if (peer->addr) {
                nw->n_unconnected_addrs++;
                peer->addr->connected = false;
        }
        nw->n_peers--;

        ntb_list_remove(&peer->link);
        ntb_slice_free(&ntb_network_peer_allocator, peer);

        maybe_queue_connect(nw, true /* use_idle */);
}

static void
remove_addr(struct ntb_network *nw,
            struct ntb_network_addr *addr)
{
        assert(!addr->connected);

        ntb_list_remove(&addr->link);
        ntb_slice_free(&ntb_network_addr_allocator, addr);
        nw->n_unconnected_addrs--;
}

static void
remove_peer_and_addr(struct ntb_network *nw,
                     struct ntb_network_peer *peer)
{
        struct ntb_network_addr *addr = peer->addr;

        remove_peer(nw, peer);
        if (addr)
                remove_addr(nw, addr);
}

static bool
can_connect_to_addr(struct ntb_network_addr *addr)
{
        uint64_t now = ntb_main_context_get_monotonic_clock(NULL);

        if (addr->connected)
                return false;

        if (now - addr->last_connect_time <
            NTB_NETWORK_MIN_RECONNECT_TIME * UINT64_C(1000000))
                return false;

        return true;
}

static void
send_version_to_peer(struct ntb_network *nw,
                     struct ntb_network_peer *peer)
{
        static const struct ntb_netaddress dummy_local_address;
        const struct ntb_netaddress *local_address;
        struct ntb_network_listen_socket *listen_socket;

        if (ntb_list_empty(&nw->listen_sockets)) {
                local_address = &dummy_local_address;
        } else {
                listen_socket =
                        ntb_container_of(nw->listen_sockets.next,
                                         listen_socket,
                                         link);
                local_address = &listen_socket->address;
        }

        ntb_connection_send_version(peer->connection, nw->nonce, local_address);
}

static struct ntb_network_peer *
add_peer(struct ntb_network *nw,
         struct ntb_connection *conn)
{
        struct ntb_network_peer *peer;
        struct ntb_signal *message_signal;

        peer = ntb_slice_alloc(&ntb_network_peer_allocator);

        nw->n_peers++;

        peer->state = NTB_NETWORK_PEER_STATE_AWAITING_VERACK_OUT;

        message_signal = ntb_connection_get_message_signal(conn);
        ntb_signal_add(message_signal, &peer->message_listener);

        peer->message_listener.notify = connection_message_cb;
        peer->network = nw;
        peer->addr = NULL;
        peer->connection = conn;

        ntb_list_init(&peer->requested_inventories);

        ntb_list_insert(&nw->peers, &peer->link);

        return peer;
}

static bool
connect_to_addr(struct ntb_network *nw,
                struct ntb_network_addr *addr)
{
        struct ntb_connection *connection;
        struct ntb_network_peer *peer;
        struct ntb_error *error = NULL;

        connection = ntb_connection_connect(&addr->address, &error);

        if (connection == NULL) {
                ntb_log("%s", error->message);
                ntb_error_clear(&error);

                /* If it's not possible to connect to this addr then
                 * we'll assume it's dead */
                remove_addr(nw, addr);

                return false;
        }

        peer = add_peer(nw, connection);

        addr->last_connect_time = ntb_main_context_get_monotonic_clock(NULL);
        peer->addr = addr;

        send_version_to_peer(nw, peer);

        return true;
}

static void
connect_queue_cb(struct ntb_main_context_source *source,
                 void *user_data)
{
        struct ntb_network *nw = user_data;
        struct ntb_network_addr *addr;
        int n_addrs = 0;
        int addr_num;

        /* If we've reached the number of connected peers then we can
         * stop trying to connect any more. There's also no point in
         * continuing if we've run out of unconnected addrs */
        if (nw->n_peers >= NTB_NETWORK_TARGET_NUM_PEERS ||
            nw->n_unconnected_addrs <= 0) {
                remove_connect_queue_source(nw);
                return;
        }

        /* Count the number of addrs we can connect to */
        ntb_list_for_each(addr, &nw->addrs, link) {
                if (can_connect_to_addr(addr))
                        n_addrs++;
        }

        if (n_addrs <= 0) {
                /* Switch to a timeout source */
                maybe_queue_connect(nw, false /* use_idle */);
                return;
        }

        /* Pick a random addr so that we don't accidentally favour the
         * list we retrieve from any particular peer */
        addr_num = (uint64_t) rand() * n_addrs / RAND_MAX;

        ntb_list_for_each(addr, &nw->addrs, link) {
                if (can_connect_to_addr(addr) && addr_num-- <= 0)
                        break;
        }

        if (connect_to_addr(nw, addr)) {
                addr->connected = true;
                nw->n_unconnected_addrs--;
        }
}

static void
maybe_queue_connect(struct ntb_network *nw,
                    bool use_idle)
{
        /* If we've already got enough peers then we don't need to do
         * anything */
        if (nw->n_peers >= NTB_NETWORK_TARGET_NUM_PEERS)
                return;

        /* Or if we don't have any addrs to connect to */
        if (nw->n_unconnected_addrs <= 0)
                return;

        if (nw->connect_queue_source) {
                if (nw->connect_queue_source_is_idle == use_idle)
                        return;

                ntb_main_context_remove_source(nw->connect_queue_source);
        }

        if (use_idle) {
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

static struct ntb_network_addr *
new_addr(struct ntb_network *nw)
{
        struct ntb_network_addr *addr;

        addr = ntb_slice_alloc(&ntb_network_addr_allocator);

        ntb_list_insert(&nw->addrs, &addr->link);
        addr->connected = false;
        nw->n_unconnected_addrs++;

        addr->last_connect_time = 0;

        return addr;
}

static void
broadcast_addr(struct ntb_network *nw,
               struct ntb_network_addr *addr)
{
        struct ntb_network_peer *peer;

        ntb_list_for_each(peer, &nw->peers, link) {
                if (peer->state == NTB_NETWORK_PEER_STATE_CONNECTED) {
                        ntb_connection_begin_addr(peer->connection);
                        ntb_connection_add_addr_address(peer->connection,
                                                        addr->advertise_time,
                                                        addr->stream,
                                                        addr->services,
                                                        &addr->address);
                        ntb_connection_end_addr(peer->connection);
                }
        }
}

static struct ntb_network_addr *
add_addr(struct ntb_network *nw,
         int64_t timestamp,
         uint32_t stream,
         uint64_t services,
         const struct ntb_netaddress *address)
{
        int64_t now = ntb_main_context_get_wall_clock(NULL);
        struct ntb_network_addr *addr;

        /* Ignore old addresses */
        if (now - timestamp >= NTB_NETWORK_MAX_ADDR_AGE)
                return NULL;

        /* Don't let addresses be advertised in the future */
        if (timestamp > now)
                timestamp = now;

        /* Check if we already have this addr */
        ntb_list_for_each(addr, &nw->addrs, link) {
                if (!memcmp(addr->address.host,
                            address->host,
                            sizeof address->host) &&
                    addr->address.port == address->port) {
                        if (addr->advertise_time < timestamp) {
                                addr->advertise_time = timestamp;
                                broadcast_addr(nw, addr);
                        }
                        return addr;
                }
        }

        addr = new_addr(nw);
        addr->advertise_time = timestamp;
        addr->stream = stream;
        addr->services = services;
        addr->address = *address;

        broadcast_addr(nw, addr);

        maybe_queue_connect(nw, true /* use_idle */);

        return addr;
}

static void
send_addresses(struct ntb_network *nw,
               struct ntb_network_peer *peer)
{
        struct ntb_network_addr *addr;
        int64_t now = ntb_main_context_get_wall_clock(NULL);
        int64_t age;

        ntb_connection_begin_addr(peer->connection);

        ntb_list_for_each(addr, &nw->addrs, link) {
                age = now - addr->advertise_time;

                if (age > NTB_NETWORK_MAX_ADDR_AGE)
                        continue;

                ntb_connection_add_addr_address(peer->connection,
                                                addr->advertise_time,
                                                addr->stream,
                                                addr->services,
                                                &addr->address);
        }

        ntb_connection_end_addr(peer->connection);
}

static void
send_inventory(struct ntb_network *nw,
               struct ntb_network_peer *peer)
{
        struct ntb_network_inventory *inv;
        int64_t now = ntb_main_context_get_wall_clock(NULL);
        int64_t age;

        ntb_connection_begin_inv(peer->connection);

        ntb_list_for_each(inv, &nw->accepted_inventories, link) {
                age = now - inv->timestamp;

                if (age >= ntb_proto_get_max_age_for_type(inv->type))
                        continue;

                ntb_connection_add_inv_hash(peer->connection, inv->hash);
        }

        ntb_connection_end_inv(peer->connection);
}

static void
connection_established(struct ntb_network *nw,
                       struct ntb_network_peer *peer)
{
        peer->state = NTB_NETWORK_PEER_STATE_CONNECTED;
        send_addresses(nw, peer);
        send_inventory(nw, peer);
}

static bool
handle_version(struct ntb_network *nw,
               struct ntb_network_peer *peer,
               struct ntb_connection_version_message *message)
{
        const char *remote_address_string =
                ntb_connection_get_remote_address_string(peer->connection);
        struct ntb_network_addr *addr;
        struct ntb_netaddress remote_address;
        uint64_t stream = 1;
        const uint8_t *p;
        uint32_t length;

        if (message->nonce == nw->nonce) {
                ntb_log("Connected to self from %s", remote_address_string);
                remove_peer(nw, peer);
                return false;
        }

        if (message->version != NTB_PROTO_VERSION) {
                ntb_log("Client %s is using unsupported protocol version "
                        "%" PRIu32,
                        remote_address_string,
                        message->version);
                remove_peer_and_addr(nw, peer);
                return false;
        }

        if (message->stream_numbers.n_ints >= 1) {
                p = message->stream_numbers.values;
                length = 16;
                ntb_proto_get_var_int(&p, &length, &stream);
        }

        remote_address = *ntb_connection_get_remote_address(peer->connection);
        remote_address.port = message->addr_from.port;
        addr = add_addr(nw,
                        message->timestamp,
                        stream,
                        message->services,
                        &remote_address);

        if (addr && peer->addr == NULL && !addr->connected) {
                peer->addr = addr;
                addr->connected = true;
                nw->n_unconnected_addrs--;
        }

        ntb_connection_send_verack(peer->connection);

        switch (peer->state) {
        case NTB_NETWORK_PEER_STATE_AWAITING_VERACK_OUT:
        case NTB_NETWORK_PEER_STATE_AWAITING_VERACK_IN:
        case NTB_NETWORK_PEER_STATE_CONNECTED:
                break;

        case NTB_NETWORK_PEER_STATE_AWAITING_VERSION_OUT:
                connection_established(nw, peer);
                break;

        case NTB_NETWORK_PEER_STATE_AWAITING_VERSION_IN:
                send_version_to_peer(nw, peer);
                peer->state = NTB_NETWORK_PEER_STATE_AWAITING_VERACK_IN;
                break;
        }

        return true;
}

static bool
handle_verack(struct ntb_network *nw,
              struct ntb_network_peer *peer)
{
        switch (peer->state) {
        case NTB_NETWORK_PEER_STATE_AWAITING_VERACK_OUT:
                peer->state = NTB_NETWORK_PEER_STATE_AWAITING_VERSION_OUT;
                break;

        case NTB_NETWORK_PEER_STATE_AWAITING_VERACK_IN:
                connection_established(nw, peer);
                break;

        case NTB_NETWORK_PEER_STATE_AWAITING_VERSION_OUT:
        case NTB_NETWORK_PEER_STATE_AWAITING_VERSION_IN:
        case NTB_NETWORK_PEER_STATE_CONNECTED:
                break;
        }

        return true;
}

static void
request_inventory(struct ntb_network *nw,
                  struct ntb_network_peer *peer,
                  const uint8_t *hash)
{
        struct ntb_network_inventory *inv;

        inv = ntb_slice_alloc(&ntb_network_inventory_allocator);

        inv->state = NTB_NETWORK_INV_STATE_STUB;
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
              enum ntb_proto_inv_type type,
              const uint8_t *payload,
              size_t payload_length,
              int64_t age)
{
        const char *type_name;
        const char *remote_address_string =
                ntb_connection_get_remote_address_string(peer->connection);

        type_name = ntb_proto_get_command_name_for_type(type);

        if (age <= -NTB_NETWORK_INV_FUTURE_AGE) {
                ntb_log("Rejecting %s from %s which was created "
                        "%" PRIi64 " seconds in the future",
                        type_name,
                        remote_address_string,
                        -age);
                return true;
        }

        if (age >= ntb_proto_get_max_age_for_type(type)) {
                ntb_log("Rejecting %s from %s which was created "
                        "%" PRIi64 " seconds ago",
                        type_name,
                        remote_address_string,
                        age);
                return true;
        }

        if (!ntb_pow_check(payload,
                           payload_length,
                           NTB_PROTO_MIN_EXTRA_BYTES,
                           NTB_PROTO_MIN_NONCE_TRIALS_PER_BYTE)) {
                ntb_log("Rejecting %s from %s because the proof-of-work is "
                        "too low",
                        type_name,
                        remote_address_string);
                return true;
        }

        return false;
}

static bool
handle_addr(struct ntb_network *nw,
            struct ntb_network_peer *peer,
            struct ntb_connection_addr_message *message)
{
        add_addr(nw,
                 message->timestamp,
                 message->stream,
                 message->services,
                 &message->address);

        return true;
}

static bool
handle_getdata(struct ntb_network *nw,
               struct ntb_network_peer *peer,
               struct ntb_connection_getdata_message *message)
{
        struct ntb_network_inventory *inv;
        uint64_t i;

        for (i = 0; i < message->n_hashes; i++) {
                inv = ntb_hash_table_get(nw->inventory_hash,
                                         message->hashes + i *
                                         NTB_PROTO_HASH_LENGTH);
                if (inv && inv->state != NTB_NETWORK_INV_STATE_REJECTED) {
                        ntb_connection_send_blob(peer->connection,
                                                 inv->hash,
                                                 inv->blob);
                }
        }

        return true;
}

static void
broadcast_inv(struct ntb_network *nw,
              const uint8_t *hash)
{
        struct ntb_network_peer *peer;

        ntb_list_for_each(peer, &nw->peers, link) {
                if (peer->state == NTB_NETWORK_PEER_STATE_CONNECTED) {
                        ntb_connection_begin_inv(peer->connection);
                        ntb_connection_add_inv_hash(peer->connection, hash);
                        ntb_connection_end_inv(peer->connection);
                }
        }
}

static bool
handle_object(struct ntb_network *nw,
              struct ntb_network_peer *peer,
              struct ntb_connection_object_message *message)
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
        } else if (inv->state == NTB_NETWORK_INV_STATE_STUB) {
                ntb_list_remove(&inv->link);
        } else {
                /* We've already got this object so we'll just ignore it */
                return true;
        }

        age = ntb_main_context_get_wall_clock(NULL) - message->timestamp;

        inv->timestamp = message->timestamp;

        if (should_reject(peer,
                          message->type,
                          message->object_data,
                          message->object_data_length,
                          age)) {
                inv->state = NTB_NETWORK_INV_STATE_REJECTED;
                ntb_list_insert(&nw->rejected_inventories, &inv->link);
        } else {
                inv->blob = ntb_blob_new(message->type,
                                         message->object_data,
                                         message->object_data_length);

                ntb_store_save_blob(NULL, hash, inv->blob);

                /* If the blob is not quite new then we won't bother
                 * keeping it in memory under the assumption that's
                 * less likely that a peer will request it. If
                 * something does request it we'll have to load it
                 * from disk */
                if (age >= NTB_NETWORK_INV_CACHE_AGE) {
                        ntb_blob_unref(inv->blob);
                        inv->blob = NULL;
                }

                ntb_list_insert(&nw->accepted_inventories, &inv->link);
                inv->type = message->type;
                inv->state = NTB_NETWORK_INV_STATE_ACCEPTED;

                broadcast_inv(nw, hash);
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
                remove_peer(nw, peer);
                return false;

        case NTB_CONNECTION_MESSAGE_CONNECT_FAILED:
                /* If we never actually managed to connect to the peer
                 * then we'll assume it's a bad address and we'll stop
                 * trying to connect to it */
                remove_peer_and_addr(nw, peer);
                return false;

        case NTB_CONNECTION_MESSAGE_VERSION:
                return handle_version(nw,
                                      peer,
                                      (struct ntb_connection_version_message *)
                                      message);

        case NTB_CONNECTION_MESSAGE_VERACK:
                return handle_verack(nw, peer);

        case NTB_CONNECTION_MESSAGE_INV:
                return handle_inv(nw,
                                  peer,
                                  (struct ntb_connection_inv_message *)
                                  message);

        case NTB_CONNECTION_MESSAGE_ADDR:
                return handle_addr(nw,
                                   peer,
                                   (struct ntb_connection_addr_message *)
                                   message);

        case NTB_CONNECTION_MESSAGE_GETDATA:
                return handle_getdata(nw,
                                      peer,
                                      (struct ntb_connection_getdata_message *)
                                      message);

        case NTB_CONNECTION_MESSAGE_OBJECT:
                return handle_object(nw,
                                     peer,
                                     (struct ntb_connection_object_message *)
                                     message);
        }

        return true;
}

static void
gc_requested_inventories(struct ntb_network *nw,
                         struct ntb_network_peer *peer)
{
        struct ntb_network_inventory *inv, *tmp;
        uint64_t now = ntb_main_context_get_monotonic_clock(NULL);

        ntb_list_for_each_safe(inv, tmp, &peer->requested_inventories, link) {
                if (now - inv->last_request_time >=
                    NTB_NETWORK_MAX_STUB_INVENTORY_AGE * UINT64_C(1000000)) {
                        ntb_list_remove(&inv->link);
                        ntb_hash_table_remove(nw->inventory_hash, inv);
                        free_inventory(inv);
                }
        }
}

static void
gc_inventories(struct ntb_network *nw,
               struct ntb_list *list)
{
        struct ntb_network_inventory *inv, *tmp;
        int64_t now = ntb_main_context_get_wall_clock(NULL);
        int64_t age;

        ntb_list_for_each_safe(inv, tmp, list, link) {
                age = now - inv->timestamp;

                if (age <= -NTB_NETWORK_INV_FUTURE_AGE ||
                    age >= (ntb_proto_get_max_age_for_type(inv->type) +
                            NTB_PROTO_EXTRA_AGE)) {
                        if (inv->state != NTB_NETWORK_INV_STATE_REJECTED)
                                ntb_store_delete_object(NULL, inv->hash);
                        ntb_list_remove(&inv->link);
                        ntb_hash_table_remove(nw->inventory_hash, inv);
                        free_inventory(inv);
                } else if (age >= NTB_NETWORK_INV_CACHE_AGE &&
                           inv->blob &&
                           inv->state != NTB_NETWORK_INV_STATE_REJECTED) {
                        ntb_blob_unref(inv->blob);
                        inv->blob = NULL;
                }
        }
}

static void
gc_addrs(struct ntb_network *nw)
{
        struct ntb_network_addr *addr, *tmp;
        int64_t now = ntb_main_context_get_wall_clock(NULL);

        ntb_list_for_each_safe(addr, tmp, &nw->addrs, link) {
                if (now - addr->advertise_time >= NTB_NETWORK_MAX_ADDR_AGE &&
                    !addr->connected)
                        remove_addr(nw, addr);
        }
}

static void
gc_timeout_cb(struct ntb_main_context_source *source,
              void *user_data)
{
        struct ntb_network *nw = user_data;
        struct ntb_network_peer *peer;

        ntb_list_for_each(peer, &nw->peers, link)
                gc_requested_inventories(nw, peer);

        gc_inventories(nw, &nw->accepted_inventories);
        gc_inventories(nw, &nw->rejected_inventories);

        gc_addrs(nw);
}

static void
store_for_each_cb(enum ntb_proto_inv_type type,
                  const uint8_t *hash,
                  int64_t timestamp,
                  void *user_data)
{
        struct ntb_network *nw = user_data;
        struct ntb_network_inventory *inv;

        inv = ntb_hash_table_get(nw->inventory_hash, hash);

        /* Presumably this could only happen if somehow the store
         * reported the same hash twice. However it's probably better
         * to be safe */
        if (inv)
                return;

        inv = ntb_slice_alloc(&ntb_network_inventory_allocator);
        memcpy(inv->hash, hash, NTB_PROTO_HASH_LENGTH);
        inv->timestamp = timestamp;
        inv->blob = NULL;
        ntb_hash_table_set(nw->inventory_hash, inv);
        ntb_list_insert(&nw->accepted_inventories, &inv->link);
        inv->type = type;
        inv->state = NTB_NETWORK_INV_STATE_ACCEPTED;
}

void
ntb_network_load_store(struct ntb_network *nw)
{
        ntb_store_for_each(NULL, store_for_each_cb, nw);
}

static void
remove_listen_socket(struct ntb_network_listen_socket *listen_socket)
{
        ntb_main_context_remove_source(listen_socket->source);
        ntb_list_remove(&listen_socket->link);
        close(listen_socket->sock);
        free(listen_socket);
}

static void
listen_socket_source_cb(struct ntb_main_context_source *source,
                        int fd,
                        enum ntb_main_context_poll_flags flags,
                        void *user_data)
{
        struct ntb_network_listen_socket *listen_socket = user_data;
        struct ntb_network *nw = listen_socket->nw;
        struct ntb_connection *conn;
        struct ntb_error *error = NULL;
        struct ntb_network_peer *peer;

        conn = ntb_connection_accept(fd, &error);

        if (conn == NULL) {
                ntb_log("%s", error->message);
                ntb_error_free(error);
                remove_listen_socket(listen_socket);
                return;
        }

        peer = add_peer(nw, conn);
        peer->state = NTB_NETWORK_PEER_STATE_AWAITING_VERSION_IN;
}

struct ntb_network *
ntb_network_new(void)
{
        struct ntb_network *nw = ntb_alloc(sizeof *nw);
        struct ntb_network_addr *addr;
        struct ntb_netaddress_native native_address;
        size_t hash_offset;
        bool convert_result;
        int i;

        ntb_list_init(&nw->listen_sockets);
        ntb_list_init(&nw->peers);
        ntb_list_init(&nw->addrs);
        ntb_list_init(&nw->accepted_inventories);
        ntb_list_init(&nw->rejected_inventories);

        nw->n_peers = 0;
        nw->n_unconnected_addrs = 0;
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
        for (i = 0; i < NTB_N_ELEMENTS(default_addrs); i++) {
                addr = new_addr(nw);
                convert_result =
                        address_string_to_native(default_addrs[i].address,
                                                 default_addrs[i].port,
                                                 &native_address,
                                                 NULL);
                /* These addresses are hard-coded so they should
                 * always work */
                assert(convert_result);

                ntb_netaddress_from_native(&addr->address,
                                           &native_address);

                addr->advertise_time = ntb_main_context_get_wall_clock(NULL);
                addr->stream = 1;
                addr->services = NTB_PROTO_SERVICES;
        }

        maybe_queue_connect(nw, true /* use idle */);

        nw->gc_source = ntb_main_context_add_timer(NULL,
                                                   NTB_NETWORK_GC_TIMEOUT,
                                                   gc_timeout_cb,
                                                   nw);

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
        const int true_value = true;
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

        setsockopt(sock,
                   SOL_SOCKET, SO_REUSEADDR,
                   &true_value, sizeof true_value);

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
        listen_socket->nw = nw;
        ntb_list_insert(&nw->listen_sockets, &listen_socket->link);

        ntb_netaddress_from_native(&listen_socket->address, &native_address);

        listen_socket->source =
                ntb_main_context_add_poll(NULL,
                                          sock,
                                          NTB_MAIN_CONTEXT_POLL_IN,
                                          listen_socket_source_cb,
                                          listen_socket);

        return true;

error:
        close(sock);
        return false;
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
free_addrs(struct ntb_network *nw)
{
        struct ntb_network_addr *addr, *tmp;

        ntb_list_for_each_safe(addr, tmp, &nw->addrs, link)
                remove_addr(nw, addr);
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
        ntb_main_context_remove_source(nw->gc_source);

        free_peers(nw);
        free_addrs(nw);
        free_listen_sockets(nw);
        free_inventories_in_list(&nw->accepted_inventories);
        free_inventories_in_list(&nw->rejected_inventories);

        ntb_hash_table_free(nw->inventory_hash);

        remove_connect_queue_source(nw);

        assert(nw->n_peers == 0);
        assert(nw->n_unconnected_addrs == 0);

        free(nw);
}
