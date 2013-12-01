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

#include "ntb-util.h"
#include "ntb-slice.h"
#include "ntb-connection.h"
#include "ntb-log.h"
#include "ntb-list.h"
#include "ntb-network.h"

struct ntb_error_domain
ntb_network_error;

/* We will always try to keep at least this many connections open to
 * the network */
#define NTB_NETWORK_TARGET_NUM_PEERS 8

struct ntb_network_peer {
        struct ntb_list link;
        struct ntb_netaddress address;
        struct ntb_connection *connection;
        struct ntb_listener message_listener;
        struct ntb_network *network;
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

        struct ntb_main_context_source *connect_queue_source;
};

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
close_connection(struct ntb_network *nw,
                 struct ntb_network_peer *peer)
{
        if (peer->connection) {
                ntb_connection_free(peer->connection);
                peer->connection = NULL;

                nw->n_unconnected_peers++;
                nw->n_connected_peers--;

                maybe_queue_connect(nw);
        }
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
connect_timer_cb(struct ntb_main_context_source *source,
                 void *user_data)
{
        struct ntb_network *nw = user_data;
        struct ntb_network_peer *peer;
        struct ntb_error *error = NULL;
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

        nw->connect_queue_source =
                ntb_main_context_add_timer(NULL,
                                           1, /* minutes */
                                           connect_timer_cb,
                                           nw);
}

static void
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
                break;

        case NTB_CONNECTION_MESSAGE_CONNECT_FAILED:
                /* If we never actually managed to connect to the peer
                 * then we'll assume it's a bad address and we'll stop
                 * trying to connect to it */
                remove_peer(nw, peer);
                break;
        }
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

        return peer;
}

struct ntb_network *
ntb_network_new(void)
{
        struct ntb_network *nw = ntb_alloc(sizeof *nw);
        struct ntb_network_peer *peer;
        struct ntb_netaddress_native native_address;
        bool convert_result;
        int i;

        ntb_list_init(&nw->listen_sockets);
        ntb_list_init(&nw->peers);

        nw->n_connected_peers = 0;
        nw->n_unconnected_peers = 0;

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

void
ntb_network_free(struct ntb_network *nw)
{
        free_peers(nw);
        free_listen_sockets(nw);

        remove_connect_queue_source(nw);

        assert(nw->n_connected_peers == 0);
        assert(nw->n_unconnected_peers == 0);

        free(nw);
}
