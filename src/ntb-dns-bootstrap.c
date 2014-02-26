/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2014  Neil Roberts
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
