/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013, 2017  Neil Roberts
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting documentation, and
 * that the name of the copyright holders not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  The copyright holders make no representations
 * about the suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
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
#include "ntb-file-error.h"
#include "ntb-socket.h"
#include "ntb-dns-bootstrap.h"

struct ntb_error_domain
ntb_network_error;

/* We will always try to keep at least this many connections open to
 * the network. These only count the outgoing connections and not the
 * incoming ones because otherwise it would be easy for someone to
 * connect to this node 8 times simultaneously in order to prevent it
 * from talking to any one else. */
#define NTB_NETWORK_NUM_OUTGOING_PEERS 8

/* Amount of memory to use in bytes for in-memory cached objects. If
 * this gets full then the least-recently used ones will be removed
 * from memory. If they are needed again they will have to requested
 * from the disk cache. */
#define NTB_NETWORK_MEMORY_CACHE_SIZE (64 * 1024 * 1024)

/* Time in minutes between each garbage collection run */
#define NTB_NETWORK_GC_TIMEOUT 10

/* Time in seconds after which we'll delete a stub inventory so that
 * we could get it again if another peer advertised it */
#define NTB_NETWORK_MAX_STUB_INVENTORY_AGE (5 * 60)

/* Time in seconds after which we'll stop advertising an addr */
#define NTB_NETWORK_MAX_ADDR_AGE (2 * 60 * 60)

/* Time in seconds before we'll retry connecting to an addr */
#define NTB_NETWORK_MIN_RECONNECT_TIME 60

/* Frequency in minutes which we'll save the address list. This is
 * only triggered when the address list changes. This is set to the
 * same as the GC timeout so that it will use the same bucket */
#define NTB_NETWORK_SAVE_ADDR_LIST_TIMEOUT NTB_NETWORK_GC_TIMEOUT

/* If we end up with this many incoming connections then we'll stop accepting
 * new ones */
#define NTB_NETWORK_MAX_INCOMING_PEERS 8

/* We only keep track of up to this many rejected inventories. If we
 * end up with more then we'll delete the older ones. This is intended
 * to reduce the possibility of using the rejected inventories as a
 * DOS vector */
#define NTB_NETWORK_MAX_REJECTED_INVENTORIES 16384

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

enum ntb_network_direction {
        /* Outgoing means we actively made the connection and incoming
         * means we accepted the connection from a listening
         * socket. */
        NTB_NETWORK_OUTGOING,
        NTB_NETWORK_INCOMING
};

enum ntb_network_addr_type {
        /* The addr is in the hard-coded list of default addresses */
        NTB_NETWORK_ADDR_DEFAULT,
        /* The addr was explicitly added by a command line option */
        NTB_NETWORK_ADDR_EXPLICITLY_ADDED,
        /* The addr was discovered by a peer */
        NTB_NETWORK_ADDR_DISCOVERED
};

struct ntb_network_addr {
        struct ntb_list link;
        struct ntb_netaddress address;

        int64_t advertise_time;
        uint32_t stream;
        uint64_t services;

        uint64_t last_connect_time;

        bool connected;

        enum ntb_network_addr_type type;
};

struct ntb_network_peer {
        struct ntb_list link;
        struct ntb_connection *connection;
        struct ntb_network_addr *addr;
        struct ntb_listener event_listener;
        struct ntb_network *network;

        struct ntb_list requested_inventories;

        enum ntb_network_peer_state state;
        enum ntb_network_direction direction;
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

        int n_outgoing_peers;
        int n_incoming_peers;
        struct ntb_list peers;

        int n_unconnected_addrs;
        struct ntb_list addrs;
        bool only_use_explicit_addresses;
        bool allow_private_addresses;

        struct ntb_main_context_source *connect_queue_source;
        bool connect_queue_source_is_idle;

        uint64_t nonce;

        struct ntb_hash_table *inventory_hash;

        size_t in_memory_cache_size;

        struct ntb_list in_memory_inventories;
        struct ntb_list on_disk_inventories;
        struct ntb_list rejected_inventories;
        int n_rejected_inventories;

        struct ntb_signal new_object_signal;

        struct ntb_main_context_source *save_addr_list_source;

        struct ntb_list delayed_broadcasts;

        struct ntb_netaddress proxy_address;
        bool use_proxy;
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

        /* The next two states represent those that we are willing to
         * distribute */

        /* Stored in the disk cache and will need to be retrieved */
        NTB_NETWORK_INV_STATE_ON_DISK,
        /* Stored in the in-memory cache */
        NTB_NETWORK_INV_STATE_IN_MEMORY
};

struct ntb_network_inventory {
        enum ntb_network_inv_state state;
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
                         * expiry time which we'll use to garbage
                         * collect when the item gets too old */
                        int64_t expires_time;

                        struct ntb_blob *blob;
                };
        };
};

struct ntb_network_delayed_broadcast {
        struct ntb_list link;
        uint8_t hash[NTB_PROTO_HASH_LENGTH];
        struct ntb_main_context_source *source;
        struct ntb_network *nw;
};

NTB_SLICE_ALLOCATOR(struct ntb_network_inventory,
                    ntb_network_inventory_allocator);
NTB_SLICE_ALLOCATOR(struct ntb_network_peer,
                    ntb_network_peer_allocator);
NTB_SLICE_ALLOCATOR(struct ntb_network_addr,
                    ntb_network_addr_allocator);

static const char *
default_addrs[] = {
        /* These are the addresses from the official Python client */
        "176.31.246.114:8444",
        "109.229.197.133:8444",
        "174.3.101.111:8444",
        "90.188.238.79:7829",
        "184.75.69.2:8444",
        "60.225.209.243:8444",
        "5.145.140.218:8444",
        "5.19.255.216:8444",
        "193.159.162.189:8444",
        "86.26.15.171:8444"
};

static void
maybe_queue_connect(struct ntb_network *nw, bool use_idle);

static void
update_all_listen_socket_sources(struct ntb_network *nw);

static bool
connection_event_cb(struct ntb_listener *listener,
                    void *data);

static void
save_addr_list_cb(struct ntb_main_context_source *source,
                  void *user_data)
{
        struct ntb_network *nw = user_data;
        struct ntb_buffer buffer;
        struct ntb_network_addr *addr;
        struct ntb_store_addr *store_addr;
        int n_addrs = 0;
        int64_t now = ntb_main_context_get_wall_clock(NULL);
        int64_t age;

        ntb_buffer_init(&buffer);

        ntb_list_for_each(addr, &nw->addrs, link) {
                age = now - addr->advertise_time;

                if (age > NTB_NETWORK_MAX_ADDR_AGE)
                        continue;

                ntb_buffer_ensure_size(&buffer,
                                       buffer.length + sizeof *store_addr);
                store_addr =
                        (struct ntb_store_addr *) (buffer.data + buffer.length);
                store_addr->timestamp = addr->advertise_time;
                store_addr->stream = addr->stream;
                store_addr->services = addr->services;
                store_addr->address = addr->address;
                buffer.length += sizeof *store_addr;
                n_addrs++;
        }

        /* This function takes ownership of the buffer */
        ntb_store_save_addr_list(NULL, /* default store */
                                 (struct ntb_store_addr *) buffer.data,
                                 n_addrs);

        ntb_main_context_remove_source(source);
        nw->save_addr_list_source = NULL;
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
        case NTB_NETWORK_INV_STATE_IN_MEMORY:
                assert(inv->blob);
                ntb_blob_unref(inv->blob);
                break;
        case NTB_NETWORK_INV_STATE_ON_DISK:
                assert(inv->blob == NULL);
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
        switch (peer->direction) {
        case NTB_NETWORK_OUTGOING:
                nw->n_outgoing_peers--;
                break;
        case NTB_NETWORK_INCOMING:
                nw->n_incoming_peers--;
                break;
        }

        ntb_list_remove(&peer->link);
        ntb_slice_free(&ntb_network_peer_allocator, peer);

        maybe_queue_connect(nw, true /* use_idle */);
        update_all_listen_socket_sources(nw);
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

static bool
can_connect_to_addr(struct ntb_network *nw,
                    struct ntb_network_addr *addr)
{
        uint64_t now = ntb_main_context_get_monotonic_clock(NULL);

        if (addr->connected)
                return false;

        if (now - addr->last_connect_time <
            NTB_NETWORK_MIN_RECONNECT_TIME * UINT64_C(1000000))
                return false;

        if (nw->only_use_explicit_addresses &&
            addr->type != NTB_NETWORK_ADDR_EXPLICITLY_ADDED)
                return false;

        return true;
}

static void
send_version_to_peer(struct ntb_network *nw,
                     struct ntb_network_peer *peer)
{
        uint16_t local_port;
        struct ntb_network_listen_socket *listen_socket;

        if (ntb_list_empty(&nw->listen_sockets)) {
                local_port = NTB_PROTO_DEFAULT_PORT;
        } else {
                listen_socket =
                        ntb_container_of(nw->listen_sockets.next,
                                         struct ntb_network_listen_socket,
                                         link);
                local_port = listen_socket->address.port;
        }

        ntb_connection_send_version(peer->connection, nw->nonce, local_port);
}

static struct ntb_network_peer *
add_peer(struct ntb_network *nw,
         struct ntb_connection *conn)
{
        struct ntb_network_peer *peer;
        struct ntb_signal *command_signal;

        peer = ntb_slice_alloc(&ntb_network_peer_allocator);

        peer->state = NTB_NETWORK_PEER_STATE_AWAITING_VERACK_OUT;

        command_signal = ntb_connection_get_event_signal(conn);
        ntb_signal_add(command_signal, &peer->event_listener);

        peer->event_listener.notify = connection_event_cb;
        peer->network = nw;
        peer->addr = NULL;
        peer->connection = conn;

        ntb_list_init(&peer->requested_inventories);

        ntb_list_insert(&nw->peers, &peer->link);

        update_all_listen_socket_sources(nw);

        return peer;
}

static bool
connect_to_addr(struct ntb_network *nw,
                struct ntb_network_addr *addr)
{
        struct ntb_connection *connection;
        struct ntb_network_peer *peer;
        struct ntb_error *error = NULL;

        addr->last_connect_time = ntb_main_context_get_monotonic_clock(NULL);

        if (nw->use_proxy) {
                connection = ntb_connection_connect_proxy(&nw->proxy_address,
                                                          &addr->address,
                                                          &error);
        } else {
                connection = ntb_connection_connect(&addr->address, &error);
        }

        if (connection == NULL) {
                ntb_log("%s", error->message);
                ntb_error_clear(&error);

                return false;
        }

        peer = add_peer(nw, connection);

        peer->addr = addr;

        peer->direction = NTB_NETWORK_OUTGOING;
        nw->n_outgoing_peers++;

        if (!nw->use_proxy)
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

        /* If we've reached the number of outgoing peers then we can
         * stop trying to connect any more. There's also no point in
         * continuing if we've run out of unconnected addrs */
        if (nw->n_outgoing_peers >= NTB_NETWORK_NUM_OUTGOING_PEERS ||
            nw->n_unconnected_addrs <= 0) {
                remove_connect_queue_source(nw);
                return;
        }

        /* Count the number of addrs we can connect to */
        ntb_list_for_each(addr, &nw->addrs, link) {
                if (can_connect_to_addr(nw, addr))
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
                if (can_connect_to_addr(nw, addr) && addr_num-- <= 0)
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
        /* If we've already got enough outgoing peers then we don't
         * need to do anything */
        if (nw->n_outgoing_peers >= NTB_NETWORK_NUM_OUTGOING_PEERS)
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
        addr->type = NTB_NETWORK_ADDR_DISCOVERED;
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

static void
queue_save_addr_list(struct ntb_network *nw)
{
        if (nw->save_addr_list_source)
                return;

        nw->save_addr_list_source =
                ntb_main_context_add_timer(NULL,
                                           NTB_NETWORK_SAVE_ADDR_LIST_TIMEOUT,
                                           save_addr_list_cb,
                                           nw);
}

static struct ntb_network_addr *
find_address(struct ntb_network *nw,
             const struct ntb_netaddress *address)
{
        struct ntb_network_addr *addr;

        ntb_list_for_each(addr, &nw->addrs, link) {
                if (!memcmp(addr->address.host,
                            address->host,
                            sizeof address->host) &&
                    addr->address.port == address->port)
                        return addr;
        }

        return NULL;
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
        addr = find_address(nw, address);
        if (addr) {
                if (addr->advertise_time < timestamp) {
                        addr->advertise_time = timestamp;
                        queue_save_addr_list(nw);
                        broadcast_addr(nw, addr);
                }
                return addr;
        }

        addr = new_addr(nw);
        addr->advertise_time = timestamp;
        addr->stream = stream;
        addr->services = services;
        addr->address = *address;

        queue_save_addr_list(nw);

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
send_inventory_list(int64_t now,
                    struct ntb_list *list,
                    struct ntb_network_peer *peer)
{
        struct ntb_network_inventory *inv;

        ntb_list_for_each(inv, list, link) {
                if (inv->expires_time <= now)
                        continue;

                ntb_connection_add_inv_hash(peer->connection, inv->hash);
        }
}

static void
send_inventory(struct ntb_network *nw,
               struct ntb_network_peer *peer)
{
        int64_t now = ntb_main_context_get_wall_clock(NULL);

        ntb_connection_begin_inv(peer->connection);

        send_inventory_list(now, &nw->in_memory_inventories, peer);
        send_inventory_list(now, &nw->on_disk_inventories, peer);

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
               struct ntb_connection_version_event *event)
{
        const char *remote_address_string =
                ntb_connection_get_remote_address_string(peer->connection);
        struct ntb_network_addr *addr;
        struct ntb_netaddress remote_address;
        char user_agent_buf[64];
        uint64_t stream = 1;
        const uint8_t *p;
        uint32_t length;
        int i;

        /* Sanitize the user agent by stripping dodgy-looking
         * characters and cropping to a maximum length */
        for (i = 0;
             i < MIN(event->user_agent.length, sizeof user_agent_buf - 1);
             i++) {
                if (event->user_agent.data[i] < ' ' ||
                    event->user_agent.data[i] > 0x7f)
                        user_agent_buf[i] = '?';
                else
                        user_agent_buf[i] = event->user_agent.data[i];
        }
        user_agent_buf[i] = '\0';

        ntb_log("Received version command from %s with user agent %s",
                remote_address_string,
                user_agent_buf);

        if (event->nonce == nw->nonce) {
                ntb_log("Connected to self from %s", remote_address_string);
                remove_peer(nw, peer);
                return false;
        }

        if (event->version != NTB_PROTO_VERSION) {
                ntb_log("Client %s is using unsupported protocol version "
                        "%" PRIu32,
                        remote_address_string,
                        event->version);
                remove_peer(nw, peer);
                return false;
        }

        if (event->stream_numbers.n_ints >= 1) {
                p = event->stream_numbers.values;
                length = 16;
                ntb_proto_get_var_int(&p, &length, &stream);
        }

        remote_address = *ntb_connection_get_remote_address(peer->connection);
        remote_address.port = event->addr_from.port;
        addr = add_addr(nw,
                        event->timestamp,
                        stream,
                        event->services,
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
           struct ntb_connection_inv_event *event)
{
        struct ntb_network_inventory *inv;
        const uint8_t *hash;
        uint64_t i;

        ntb_connection_begin_getdata(peer->connection);

        for (i = 0; i < event->n_inventories; i++) {
                hash = event->inventories + i * NTB_PROTO_HASH_LENGTH;
                inv = ntb_hash_table_get(nw->inventory_hash, hash);

                if (inv == NULL)
                        request_inventory(nw, peer, hash);
        }

        ntb_connection_end_getdata(peer->connection);

        return true;
}

static bool
should_reject(const uint8_t *payload,
              size_t payload_length,
              int64_t expires_time,
              const char *source_note)
{
        int64_t now = ntb_main_context_get_wall_clock(NULL);
        int64_t remaining_time;

        if (expires_time + NTB_PROTO_EXTRA_AGE <= now) {
                ntb_log("Rejecting object from %s which already expired "
                        "%" PRIi64 " seconds ago",
                        source_note,
                        now - expires_time);
                return true;
        }

        remaining_time = expires_time - now;

        if (remaining_time >= NTB_PROTO_MAX_AGE) {
                ntb_log("Rejecting object from %s which expires "
                        "in %" PRIi64 " seconds",
                        source_note,
                        expires_time - now);
                return true;
        }

        if (!ntb_pow_check(payload,
                           payload_length,
                           NTB_PROTO_MIN_POW_PER_BYTE,
                           NTB_PROTO_MIN_POW_EXTRA_BYTES,
                           remaining_time)) {
                ntb_log("Rejecting object from %s because the proof-of-work is "
                        "too low",
                        source_note);
                return true;
        }

        return false;
}

static bool
handle_addr(struct ntb_network *nw,
            struct ntb_network_peer *peer,
            struct ntb_connection_addr_event *event)
{
        if (ntb_netaddress_is_allowed(&event->address,
                                      nw->allow_private_addresses)) {
                add_addr(nw,
                         event->timestamp,
                         event->stream,
                         event->services,
                         &event->address);
        }

        return true;
}

static void
use_inventory(struct ntb_network *nw,
              struct ntb_network_inventory *inv)
{
        if (inv->state != NTB_NETWORK_INV_STATE_IN_MEMORY)
                return;

        /* Move the item to the beginning of the list to make it the
         * last thing to be removed when the cache is full. */
        ntb_list_remove(&inv->link);
        ntb_list_insert(&nw->in_memory_inventories, &inv->link);
}

static bool
handle_getdata(struct ntb_network *nw,
               struct ntb_network_peer *peer,
               struct ntb_connection_getdata_event *event)
{
        struct ntb_network_inventory *inv;
        uint64_t i;

        for (i = 0; i < event->n_hashes; i++) {
                inv = ntb_hash_table_get(nw->inventory_hash,
                                         event->hashes + i *
                                         NTB_PROTO_HASH_LENGTH);
                if (inv && inv->state != NTB_NETWORK_INV_STATE_REJECTED) {
                        use_inventory(nw, inv);
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

static void
free_delayed_broadcast(struct ntb_network_delayed_broadcast *data)
{
        ntb_list_remove(&data->link);
        ntb_main_context_remove_source(data->source);
        ntb_free(data);
}

static void
broadcast_delayed_inv_cb(struct ntb_main_context_source *source,
                         void *user_data)
{
        struct ntb_network_delayed_broadcast *data = user_data;

        broadcast_inv(data->nw, data->hash);
        free_delayed_broadcast(data);
}

static void
broadcast_delayed_inv(struct ntb_network *nw,
                      const uint8_t *hash)
{
        struct ntb_network_delayed_broadcast *data;
        int delay = rand() % 3 + 1;

        data = ntb_alloc(sizeof *data);

        memcpy(data->hash, hash, NTB_PROTO_HASH_LENGTH);
        data->nw = nw;
        ntb_list_insert(&nw->delayed_broadcasts, &data->link);
        data->source = ntb_main_context_add_timer(NULL,
                                                  delay,
                                                  broadcast_delayed_inv_cb,
                                                  data);
}

static void
reject_inventory(struct ntb_network *nw,
                 struct ntb_network_inventory *inv)
{
        struct ntb_network_inventory *old_inv;

        inv->state = NTB_NETWORK_INV_STATE_REJECTED;

        if (nw->n_rejected_inventories >=
            NTB_NETWORK_MAX_REJECTED_INVENTORIES) {
                /* Remove the rejected inventory that was added the
                 * earliest */
                old_inv = ntb_container_of(nw->rejected_inventories.prev,
                                           struct ntb_network_inventory,
                                           link);
                ntb_list_remove(&old_inv->link);
                ntb_hash_table_remove(nw->inventory_hash, old_inv->hash);
                free_inventory(old_inv);
        } else {
                nw->n_rejected_inventories++;
        }

        ntb_list_insert(&nw->rejected_inventories, &inv->link);
}

static void
add_in_memory_inventory(struct ntb_network *nw,
                        struct ntb_network_inventory *inv)
{
        struct ntb_network_inventory *last_inv;

        assert(inv->blob);

        nw->in_memory_cache_size += inv->blob->size;
        ntb_list_insert(&nw->in_memory_inventories, &inv->link);
        inv->state = NTB_NETWORK_INV_STATE_IN_MEMORY;

        /* Prune the cache. Keep removing the last entry (ie, the
         * least-recently used) until the cache size is again below
         * the threshold or there is only one item left. */
        while (nw->in_memory_cache_size > NTB_NETWORK_MEMORY_CACHE_SIZE) {
                last_inv = ntb_container_of(nw->in_memory_inventories.prev,
                                            struct ntb_network_inventory,
                                            link);

                if (last_inv == inv)
                        break;

                assert(last_inv->blob);

                nw->in_memory_cache_size -= last_inv->blob->size;
                ntb_blob_unref(last_inv->blob);
                last_inv->blob = NULL;
                ntb_list_remove(&last_inv->link);
                ntb_list_insert(&nw->on_disk_inventories, &last_inv->link);
                last_inv->state = NTB_NETWORK_INV_STATE_ON_DISK;
        }
}

static void
add_object(struct ntb_network *nw,
           const uint8_t *object_data,
           size_t object_data_length,
           struct ntb_blob *blob,
           enum ntb_network_add_object_flags flags,
           const char *source_note)
{
        struct ntb_network_inventory *inv;
        uint8_t hash[NTB_PROTO_HASH_LENGTH];
        struct ntb_proto_object_header header;
        ssize_t header_size;

        header_size = ntb_proto_get_object_header(object_data,
                                                  object_data_length,
                                                  &header);

        if (header_size == -1) {
                ntb_log("Invalid object command received from %s",
                        source_note);
                return;
        }

        ntb_proto_double_hash(object_data,
                              object_data_length,
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
                return;
        }

        inv->expires_time = header.expires_time;

        if (!(flags & NTB_NETWORK_SKIP_VALIDATION) &&
            should_reject(object_data,
                          object_data_length,
                          header.expires_time,
                          source_note)) {
                reject_inventory(nw, inv);
        } else {
                if (blob) {
                        inv->blob = ntb_blob_ref(blob);
                } else {
                        inv->blob = ntb_blob_new(object_data,
                                                 object_data_length);
                }

                ntb_store_save_blob(NULL, hash, inv->blob);

                add_in_memory_inventory(nw, inv);

                if ((flags & NTB_NETWORK_DELAY))
                        broadcast_delayed_inv(nw, hash);
                else
                        broadcast_inv(nw, hash);

                ntb_signal_emit(&nw->new_object_signal, inv->blob);
        }
}

static bool
handle_object(struct ntb_network *nw,
              struct ntb_network_peer *peer,
              struct ntb_connection_object_event *event)
{
        add_object(nw,
                   event->object_data,
                   event->object_data_length,
                   NULL, /* let add_object create the blob */
                   0, /* no flags */
                   ntb_connection_get_remote_address_string(peer->connection));

        return true;
}

static bool
connection_event_cb(struct ntb_listener *listener,
                    void *data)
{
        struct ntb_connection_event *event = data;
        struct ntb_network_peer *peer =
                ntb_container_of(listener,
                                 struct ntb_network_peer,
                                 event_listener);
        struct ntb_network *nw = peer->network;

        switch (event->type) {
        case NTB_CONNECTION_EVENT_ERROR:
        case NTB_CONNECTION_EVENT_CONNECT_FAILED:
                remove_peer(nw, peer);
                return false;

        case NTB_CONNECTION_EVENT_PROXY_CONNECTED:
                send_version_to_peer(nw, peer);
                return true;

        case NTB_CONNECTION_EVENT_VERSION:
                return handle_version(nw,
                                      peer,
                                      (struct ntb_connection_version_event *)
                                      event);

        case NTB_CONNECTION_EVENT_VERACK:
                return handle_verack(nw, peer);

        case NTB_CONNECTION_EVENT_INV:
                return handle_inv(nw,
                                  peer,
                                  (struct ntb_connection_inv_event *)
                                  event);

        case NTB_CONNECTION_EVENT_ADDR:
                return handle_addr(nw,
                                   peer,
                                   (struct ntb_connection_addr_event *)
                                   event);

        case NTB_CONNECTION_EVENT_GETDATA:
                return handle_getdata(nw,
                                      peer,
                                      (struct ntb_connection_getdata_event *)
                                      event);

        case NTB_CONNECTION_EVENT_OBJECT:
                return handle_object(nw,
                                     peer,
                                     (struct ntb_connection_object_event *)
                                     event);
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

        ntb_list_for_each_safe(inv, tmp, list, link) {
                if (inv->expires_time + NTB_PROTO_EXTRA_AGE <= now) {
                        if (inv->state == NTB_NETWORK_INV_STATE_REJECTED)
                                nw->n_rejected_inventories--;
                        else
                                ntb_store_delete_object(NULL, inv->hash);
                        ntb_list_remove(&inv->link);
                        ntb_hash_table_remove(nw->inventory_hash, inv);
                        free_inventory(inv);
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
                    addr->type == NTB_NETWORK_ADDR_DISCOVERED &&
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

        gc_inventories(nw, &nw->in_memory_inventories);
        gc_inventories(nw, &nw->on_disk_inventories);
        gc_inventories(nw, &nw->rejected_inventories);

        gc_addrs(nw);
}

void
ntb_network_add_blob(struct ntb_network *nw,
                     struct ntb_blob *blob,
                     enum ntb_network_add_object_flags flags,
                     const char *source_note)
{
        add_object(nw,
                   blob->data,
                   blob->size,
                   blob,
                   flags,
                   source_note);
}

void
ntb_network_add_object_from_data(struct ntb_network *nw,
                                 const uint8_t *object_data,
                                 size_t object_data_length,
                                 enum ntb_network_add_object_flags flags,
                                 const char *source_note)
{
        add_object(nw,
                   object_data,
                   object_data_length,
                   NULL, /* let add_object create the blob */
                   flags,
                   source_note);
}

static void
store_for_each_blob_cb(const uint8_t *hash,
                       int64_t expires_time,
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
        inv->expires_time = expires_time;
        inv->blob = NULL;
        ntb_hash_table_set(nw->inventory_hash, inv);
        ntb_list_insert(&nw->on_disk_inventories, &inv->link);
        inv->state = NTB_NETWORK_INV_STATE_ON_DISK;
}

static void
store_for_each_addr_cb(const struct ntb_store_addr *addr,
                       void *user_data)
{
        struct ntb_network *nw = user_data;

        add_addr(nw,
                 addr->timestamp,
                 addr->stream,
                 addr->services,
                 &addr->address);
}

static void
dns_bootstrap_cb(const struct ntb_netaddress *net_address,
                 void *user_data)
{
        struct ntb_network *nw = user_data;
        struct ntb_network_addr *addr;

        if (!ntb_netaddress_is_allowed(net_address,
                                       nw->allow_private_addresses) ||
            find_address(nw, net_address) != NULL)
                return;

        addr = new_addr(nw);

        addr->address = *net_address;
        addr->advertise_time = 0;
        addr->stream = 1;
        addr->services = NTB_PROTO_SERVICES;
        addr->type = NTB_NETWORK_ADDR_DEFAULT;
}

void
ntb_network_load_store(struct ntb_network *nw, bool bootstrap)
{
        ntb_store_for_each_blob(NULL, store_for_each_blob_cb, nw);
        ntb_store_for_each_addr(NULL, store_for_each_addr_cb, nw);
        if (bootstrap)
                ntb_dns_bootstrap(dns_bootstrap_cb, nw);
        maybe_queue_connect(nw, true /* use_idle */);
}

static void
remove_listen_socket(struct ntb_network_listen_socket *listen_socket)
{
        if (listen_socket->source)
                ntb_main_context_remove_source(listen_socket->source);
        ntb_list_remove(&listen_socket->link);
        ntb_close(listen_socket->sock);
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
                if (error->domain != &ntb_file_error ||
                    error->code != NTB_FILE_ERROR_AGAIN) {
                        ntb_log("%s", error->message);
                        remove_listen_socket(listen_socket);
                }
                ntb_error_free(error);
                return;
        }

        ntb_log("Accepted connection from %s",
                ntb_connection_get_remote_address_string(conn));

        peer = add_peer(nw, conn);
        peer->state = NTB_NETWORK_PEER_STATE_AWAITING_VERSION_IN;

        peer->direction = NTB_NETWORK_INCOMING;
        nw->n_incoming_peers++;
}

static void
update_listen_socket_source(struct ntb_network *nw,
                            struct ntb_network_listen_socket *listen_socket)
{
        if (nw->n_incoming_peers >= NTB_NETWORK_MAX_INCOMING_PEERS) {
                if (listen_socket->source) {
                        ntb_main_context_remove_source(listen_socket->source);
                        listen_socket->source = NULL;
                }
        } else if (listen_socket->source == NULL) {
                listen_socket->source =
                        ntb_main_context_add_poll(NULL,
                                                  listen_socket->sock,
                                                  NTB_MAIN_CONTEXT_POLL_IN,
                                                  listen_socket_source_cb,
                                                  listen_socket);
        }
}

static void
update_all_listen_socket_sources(struct ntb_network *nw)
{
        struct ntb_network_listen_socket *listen_socket;

        ntb_list_for_each(listen_socket, &nw->listen_sockets, link)
                update_listen_socket_source(nw, listen_socket);
}

static struct ntb_network_addr *
add_addr_string(struct ntb_network *nw,
                const char *address,
                struct ntb_error **error)
{
        struct ntb_network_addr *addr;

        addr = new_addr(nw);

        if (!ntb_netaddress_from_string(&addr->address,
                                        address,
                                        NTB_PROTO_DEFAULT_PORT)) {
                ntb_set_error(error,
                              &ntb_network_error,
                              NTB_NETWORK_ERROR_INVALID_ADDRESS,
                              "Peer address %s is invalid",
                              address);
                remove_addr(nw, addr);

                return NULL;
        }

        addr->advertise_time = 0;
        addr->stream = 1;
        addr->services = NTB_PROTO_SERVICES;

        return addr;
}

struct ntb_network *
ntb_network_new(bool add_default_nodes)
{
        struct ntb_network *nw = ntb_alloc(sizeof *nw);
        struct ntb_network_addr *addr;
        size_t hash_offset;
        int i;

        ntb_list_init(&nw->listen_sockets);
        ntb_list_init(&nw->peers);
        ntb_list_init(&nw->addrs);
        ntb_list_init(&nw->on_disk_inventories);
        ntb_list_init(&nw->in_memory_inventories);
        ntb_list_init(&nw->rejected_inventories);
        nw->in_memory_cache_size = 0;
        nw->n_rejected_inventories = 0;
        ntb_list_init(&nw->delayed_broadcasts);

        ntb_signal_init(&nw->new_object_signal);

        nw->n_outgoing_peers = 0;
        nw->n_incoming_peers = 0;
        nw->n_unconnected_addrs = 0;
        nw->connect_queue_source = NULL;
        nw->only_use_explicit_addresses = false;
        nw->allow_private_addresses = false;

        nw->save_addr_list_source = NULL;

        nw->use_proxy = false;

        hash_offset = NTB_STRUCT_OFFSET(struct ntb_network_inventory, hash);
        nw->inventory_hash = ntb_hash_table_new(hash_offset);

        /* For some reason OpenSSL adds the unitialised bytes of this
         * buffer as a source of entropy. This trips up Valgrind so we
         * can avoid the problem by clearing it first. I don't think
         * this will affect the entropy because if it wasn't cleared
         * it would probably end up with a repeatable value anyway.
         * This value doesn't need to be cryptographically secure. */
        memset(&nw->nonce, 0, sizeof nw->nonce);
        RAND_bytes((unsigned char *) &nw->nonce, sizeof nw->nonce);

        /* Add a hard-coded list of initial nodes which we can use to
         * discover more */
        if (add_default_nodes) {
                for (i = 0; i < NTB_N_ELEMENTS(default_addrs); i++) {
                        addr = add_addr_string(nw, default_addrs[i], NULL);
                        /* These addresses are hard-coded so they should
                         * always work */
                        assert(addr);
                        addr->type = NTB_NETWORK_ADDR_DEFAULT;
                }
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
                               struct ntb_error **error)
{
        struct ntb_network_listen_socket *listen_socket;
        struct ntb_netaddress netaddress;
        struct ntb_netaddress_native native_address;
        const int true_value = true;
        int sock;

        if (!ntb_netaddress_from_string(&netaddress,
                                        address,
                                        NTB_PROTO_DEFAULT_PORT)) {
                ntb_set_error(error,
                              &ntb_network_error,
                              NTB_NETWORK_ERROR_INVALID_ADDRESS,
                              "The listen address %s is invalid", address);
                return false;
        }

        ntb_netaddress_to_native(&netaddress, &native_address);

        sock = socket(native_address.sockaddr.sa_family == AF_INET6 ?
                      PF_INET6 : PF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
                ntb_file_error_set(error,
                                   errno,
                                   "Failed to create socket: %s",
                                   strerror(errno));
                return false;
        }

        setsockopt(sock,
                   SOL_SOCKET, SO_REUSEADDR,
                   &true_value, sizeof true_value);

        if (!ntb_socket_set_nonblock(sock, error))
                goto error;

        if (bind(sock, &native_address.sockaddr, native_address.length) == -1) {
                ntb_file_error_set(error,
                                   errno,
                                   "Failed to bind socket: %s",
                                   strerror(errno));
                goto error;
        }

        if (listen(sock, 10) == -1) {
                ntb_file_error_set(error,
                                   errno,
                                   "Failed to make socket listen: %s",
                                   strerror(errno));
                goto error;
        }

        listen_socket = ntb_alloc(sizeof *listen_socket);
        listen_socket->sock = sock;
        listen_socket->nw = nw;
        ntb_list_insert(&nw->listen_sockets, &listen_socket->link);

        ntb_netaddress_from_native(&listen_socket->address, &native_address);

        listen_socket->source = NULL;

        update_listen_socket_source(nw, listen_socket);

        return true;

error:
        ntb_close(sock);
        return false;
}

bool
ntb_network_add_peer_address(struct ntb_network *nw,
                             const char *address,
                             struct ntb_error **error)
{
        struct ntb_network_addr *addr;

        addr = add_addr_string(nw, address, error);

        if (addr == NULL)
                return false;

        addr->type = NTB_NETWORK_ADDR_EXPLICITLY_ADDED;

        return true;
}

struct ntb_signal *
ntb_network_get_new_object_signal(struct ntb_network *nw)
{
        return &nw->new_object_signal;
}

void
ntb_network_set_only_use_explicit_addresses(struct ntb_network *nw,
                                            bool value)
{
        nw->only_use_explicit_addresses = value;
        maybe_queue_connect(nw, true /* use idle */);
}

void
ntb_network_set_allow_private_addresses(struct ntb_network *nw,
                                        bool value)
{
        nw->allow_private_addresses = value;
        maybe_queue_connect(nw, true /* use idle*/);
}

void
ntb_network_set_proxy_address(struct ntb_network *nw,
                              const struct ntb_netaddress *addr)
{
        nw->use_proxy = true;
        nw->proxy_address = *addr;
}

enum ntb_network_object_location
ntb_network_get_object(struct ntb_network *nw,
                       const uint8_t *hash,
                       struct ntb_blob **blob)
{
        struct ntb_network_inventory *inv;

        inv = ntb_hash_table_get(nw->inventory_hash, hash);

        if (inv == NULL)
                return NTB_NETWORK_OBJECT_LOCATION_NOWHERE;

        switch (inv->state) {
        case NTB_NETWORK_INV_STATE_ON_DISK:
                if (blob)
                        *blob = NULL;
                return NTB_NETWORK_OBJECT_LOCATION_STORE;
        case NTB_NETWORK_INV_STATE_IN_MEMORY:
                assert(inv->blob);
                if (blob)
                        *blob = inv->blob;
                return NTB_NETWORK_OBJECT_LOCATION_MEMORY;
        default:
                return NTB_NETWORK_OBJECT_LOCATION_NOWHERE;
        }
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

static void
free_delayed_broadcasts(struct ntb_list *list)
{
        struct ntb_network_delayed_broadcast *data, *tmp;

        ntb_list_for_each_safe(data, tmp, list, link)
                free_delayed_broadcast(data);
}

void
ntb_network_free(struct ntb_network *nw)
{
        if (nw->save_addr_list_source) {
                /* Make sure the list is saved before we quit. This
                 * will also remove the source */
                save_addr_list_cb(nw->save_addr_list_source, nw);
                assert(nw->save_addr_list_source == NULL);
        }

        ntb_main_context_remove_source(nw->gc_source);

        free_peers(nw);
        free_addrs(nw);
        free_listen_sockets(nw);
        free_inventories_in_list(&nw->in_memory_inventories);
        free_inventories_in_list(&nw->on_disk_inventories);
        free_inventories_in_list(&nw->rejected_inventories);

        free_delayed_broadcasts(&nw->delayed_broadcasts);

        ntb_hash_table_free(nw->inventory_hash);

        remove_connect_queue_source(nw);

        assert(nw->n_outgoing_peers == 0);
        assert(nw->n_incoming_peers == 0);
        assert(nw->n_unconnected_addrs == 0);

        free(nw);
}
