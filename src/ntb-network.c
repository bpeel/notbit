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

#include "ntb-util.h"
#include "ntb-slice.h"
#include "ntb-connection.h"
#include "ntb-log.h"
#include "ntb-list.h"
#include "ntb-network.h"

struct ntb_error_domain
ntb_network_error;

struct ntb_network_peer {
        struct ntb_list link;
        struct ntb_netaddress address;
        struct ntb_connection *connection;
};

struct ntb_network_listen_socket {
        struct ntb_list link;
        int sock;
};

struct ntb_network {
        struct ntb_list listen_sockets;
        struct ntb_list peers;
};

NTB_SLICE_ALLOCATOR(struct ntb_network_peer,
                    ntb_network_peer_allocator);

struct ntb_network *
ntb_network_new(void)
{
        struct ntb_network *nw = ntb_alloc(sizeof *nw);

        ntb_list_init(&nw->listen_sockets);
        ntb_list_init(&nw->peers);

        return nw;
}

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
close_connection(struct ntb_network_peer *peer)
{
        if (peer->connection) {
                ntb_connection_free(peer->connection);
                peer->connection = NULL;
        }
}

static void
remove_peer(struct ntb_network_peer *peer)
{
        close_connection(peer);
        ntb_list_remove(&peer->link);
        ntb_slice_free(&ntb_network_peer_allocator, peer);
}

static void
free_peers(struct ntb_network *nw)
{
        struct ntb_network_peer *peer, *tmp;

        ntb_list_for_each_safe(peer, tmp, &nw->peers, link)
                remove_peer(peer);
}

void
ntb_network_free(struct ntb_network *nw)
{
        free_peers(nw);
        free_listen_sockets(nw);
        free(nw);
}
