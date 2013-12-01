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

#include <string.h>
#include <inttypes.h>

#include "ntb-netaddress.h"

static const uint8_t
ipv4_magic[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff
};

static void
ntb_netaddress_to_native_ipv4(const struct ntb_netaddress *address,
                              struct sockaddr_in *native)
{
        native->sin_family = AF_INET;
        memcpy(&native->sin_addr.s_addr,
               address->host + sizeof ipv4_magic,
               sizeof (uint32_t));
        native->sin_port = htons(address->port);
}

static void
ntb_netaddress_to_native_ipv6(const struct ntb_netaddress *address,
                              struct sockaddr_in6 *native)
{
        native->sin6_family = AF_INET6;
        memcpy(&native->sin6_addr, address->host, sizeof address->host);
        native->sin6_flowinfo = 0;
        native->sin6_port = htons(address->port);
}

void
ntb_netaddress_to_native(const struct ntb_netaddress *address,
                         struct ntb_netaddress_native *native)
{
        if (!memcmp(address->host, ipv4_magic, sizeof ipv4_magic)) {
                ntb_netaddress_to_native_ipv4(address, &native->sockaddr_in);
                native->length = sizeof native->sockaddr_in;
        } else {
                ntb_netaddress_to_native_ipv6(address, &native->sockaddr_in6);
                native->length = sizeof native->sockaddr_in6;
        }
}

static void
ntb_netaddress_from_native_ipv4(struct ntb_netaddress *address,
                                const struct sockaddr_in *native)
{
        memcpy(address->host, ipv4_magic, sizeof ipv4_magic);
        memcpy(address->host + sizeof ipv4_magic,
               &native->sin_addr,
               sizeof native->sin_addr);
        address->port = ntohs(native->sin_port);
}

static void
ntb_netaddress_from_native_ipv6(struct ntb_netaddress *address,
                                const struct sockaddr_in6 *native)
{
        memcpy(address->host, &native->sin6_addr, sizeof native->sin6_addr);
        address->port = ntohs(native->sin6_port);
}

void
ntb_netaddress_from_native(struct ntb_netaddress *address,
                           const struct ntb_netaddress_native *native)
{
        switch (native->sockaddr.sa_family) {
        case AF_INET:
                ntb_netaddress_from_native_ipv4(address,
                                                &native->sockaddr_in);
                break;

        case AF_INET6:
                ntb_netaddress_from_native_ipv6(address,
                                                &native->sockaddr_in6);
                break;

        default:
                memset(&address, 0, sizeof *address);
                break;
        }
}

char *
ntb_netaddress_to_string(const struct ntb_netaddress *address)
{
        const int buffer_length = (8 * 5 + /* length of ipv6 address */
                                   2 + /* square brackets */
                                   1 + /* colon separator */
                                   5 + /* port number */
                                   1 + /* null terminator */
                                   16 /* ... and one for the pot */);
        char *buf = ntb_alloc(buffer_length);
        int len;

        if (memcmp(address->host, ipv4_magic, sizeof(ipv4_magic))) {
                buf[0] = '[';
                inet_ntop(AF_INET6,
                          address->host,
                          buf + 1,
                          buffer_length - 1);
                len = strlen(buf);
                buf[len++] = ']';
        } else {
                inet_ntop(AF_INET,
                          address->host + sizeof ipv4_magic,
                          buf,
                          buffer_length);
                len = strlen(buf);
        }

        snprintf(buf + len, buffer_length - len,
                 ":%" PRIu16,
                 address->port);

        return buf;
}
