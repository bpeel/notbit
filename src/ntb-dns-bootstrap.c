/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2014  Neil Roberts
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

#include <netdb.h>
#include <string.h>

#include "ntb-dns-bootstrap.h"
#include "ntb-buffer.h"
#include "ntb-netaddress.h"
#include "ntb-main-context.h"
#include "ntb-log.h"

static void
lookup_address(const char *node,
               int port,
               ntb_dns_bootstrap_func callback,
               void *user_data)
{
        struct ntb_netaddress_native native_address;
        struct ntb_netaddress address;
        struct addrinfo *addrinfo, *a;
        int ret;

        ret = getaddrinfo(node,
                          NULL, /* service */
                          NULL, /* hints */
                          &addrinfo);

        if (ret) {
                ntb_log("Resolving %s failed: %s",
                        node,
                        gai_strerror(ret));
                return;
        }

        for (a = addrinfo; a; a = a->ai_next) {
                switch (a->ai_family) {
                case AF_INET:
                        if (a->ai_addrlen != sizeof (struct sockaddr_in))
                                continue;
                        break;
                case AF_INET6:
                        if (a->ai_addrlen != sizeof (struct sockaddr_in6))
                                continue;
                        break;
                default:
                        continue;
                }

                memcpy(&native_address.sockaddr, a->ai_addr, a->ai_addrlen);
                native_address.length = a->ai_addrlen;

                ntb_netaddress_from_native(&address, &native_address);
                address.port = port;

                callback(&address, user_data);
        }

        freeaddrinfo(addrinfo);
}

void
ntb_dns_bootstrap(ntb_dns_bootstrap_func callback,
                  void *user_data)
{
        ntb_log("Doing DNS bootstrap");

        lookup_address("bootstrap8080.bitmessage.org",
                       8080,
                       callback,
                       user_data);
        lookup_address("bootstrap8444.bitmessage.org",
                       8444,
                       callback,
                       user_data);
}
