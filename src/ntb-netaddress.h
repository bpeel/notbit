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

#ifndef NTB_NETADDRESS_H
#define NTB_NETADDRESS_H

#include <stdint.h>
#include <netinet/in.h>

struct ntb_netaddress {
        /* This is in network byte order. It is the same format as in
         * the Bitmessage protocol, ie, if it is an IPv4 address then
         * it will begin with the 12 bytes 00 00 00 00 00 00 00 00 00
         * 00 FF FF followed by the 4 byte address */
        uint8_t host[16];
        /* In native byte order */
        uint16_t port;
};

struct ntb_netaddress_native {
        union {
                struct sockaddr sockaddr;
                struct sockaddr_in sockaddr_in;
                struct sockaddr_in6 sockaddr_in6;
        };
        socklen_t length;
};

void
ntb_netaddress_to_native(const struct ntb_netaddress *address,
                         struct ntb_netaddress_native *native);

void
ntb_netaddress_from_native(struct ntb_netaddress *address,
                           const struct ntb_netaddress_native *native);

char *
ntb_netaddress_to_string(const struct ntb_netaddress *address);

bool
ntb_netaddress_from_string(struct ntb_netaddress *address,
                           const char *str);

#endif /* NTB_NETADDRESS_H */
