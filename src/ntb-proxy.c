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

#include <string.h>

#include "ntb-proxy.h"
#include "ntb-slice.h"

struct ntb_error_domain
ntb_proxy_error;

enum ntb_proxy_state {
        NTB_PROXY_STATE_AWAITING_METHOD,
        NTB_PROXY_STATE_AWAITING_REPLY,
        NTB_PROXY_STATE_CONNECTED
};

struct ntb_proxy {
        enum ntb_proxy_state state;
        struct ntb_netaddress dst_addr;
        struct ntb_buffer *in_buf;
        struct ntb_buffer *out_buf;
};

NTB_SLICE_ALLOCATOR(struct ntb_proxy, ntb_proxy_allocator);

struct ntb_proxy *
ntb_proxy_new(const struct ntb_netaddress *dst_addr,
              struct ntb_buffer *in_buf,
              struct ntb_buffer *out_buf)
{
        struct ntb_proxy *proxy = ntb_slice_alloc(&ntb_proxy_allocator);

        proxy->dst_addr = *dst_addr;
        proxy->in_buf = in_buf;
        proxy->out_buf = out_buf;
        proxy->state = NTB_PROXY_STATE_AWAITING_METHOD;

        /* Add the version identifier */
        ntb_buffer_append(out_buf,
                          "\x5" /* version 5 */
                          "\x1" /* one authentication method */
                          "\x0", /* no authentication required */
                          3);

        return proxy;
}

static ssize_t
handle_method(struct ntb_proxy *proxy,
              const uint8_t *in_buf,
              size_t in_length,
              struct ntb_error **error)
{
        uint16_t port;

        if (in_length < 2)
                return 0;

        /* The proxy server should probably reply with the same
         * version we requested */
        if (in_buf[0] != 5) {
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_BAD_PROTOCOL,
                              "Proxy server replied with an invalid version");
                return -1;
        }

        if (in_buf[1] == 0xff) {
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_NO_AUTHENTICATION_UNSUPPORTED,
                              "Proxy server doesn't support no "
                              "authentication");
                return -1;
        }

        if (in_buf[1] != 0) {
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_BAD_PROTOCOL,
                              "Invalid authentication method selected "
                              "by proxy server");
                return -1;
        }

        proxy->state = NTB_PROXY_STATE_AWAITING_REPLY;

        ntb_buffer_append(proxy->out_buf,
                          "\x5" /* version 5 */
                          "\x1" /* connect */
                          "\x0", /* reserved */
                          3);

        if (ntb_netaddress_is_ipv6(&proxy->dst_addr)) {
                ntb_buffer_append_c(proxy->out_buf, 4 /* ipv6 address */);
                ntb_buffer_append(proxy->out_buf,
                                  proxy->dst_addr.host,
                                  16);
        } else {
                ntb_buffer_append_c(proxy->out_buf, 1 /* ipv4 address */);
                ntb_buffer_append(proxy->out_buf,
                                  proxy->dst_addr.host + 12,
                                  4);
        }

        port = NTB_UINT16_TO_BE(proxy->dst_addr.port);
        ntb_buffer_append(proxy->out_buf, &port, sizeof port);

        return 2;
}

static ssize_t
handle_reply(struct ntb_proxy *proxy,
             const uint8_t *in_buf,
             size_t in_length,
             struct ntb_error **error)
{
        int addr_len;

        if (in_length < 4)
                return 0;

        switch (in_buf[3]) {
        case 1:
                addr_len = 4;
                break;
        case 2:
                addr_len = 16;
                break;
        default:
                /* Reported as an error later */
                addr_len = 0;
                break;
        }

        if (in_length < 4 + addr_len + 2)
                return 0;

        if (in_buf[0] != 5) {
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_BAD_PROTOCOL,
                              "Proxy server replied with an invalid version");
                return -1;
        }

        switch (in_buf[1]) {
        case 0:
                break;
        case 1:
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_GENERAL_SOCKS_SERVER_FAILURE,
                              "General SOCKS server failure");
                return -1;
        case 2:
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_CONNECTION_NOT_ALLOWED_BY_RULESET,
                              "Connection not allowed by ruleset");
                return -1;
        case 3:
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_NETWORK_UNREACHABLE,
                              "Network unreachable");
                return -1;
        case 4:
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_HOST_UNREACHABLE,
                              "Host unreachable");
                return -1;
        case 5:
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_CONNECTION_REFUSED,
                              "Connection refused");
                return -1;
        case 6:
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_TTL_EXPIRED,
                              "TTL expired");
                return -1;
        case 7:
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_COMMAND_NOT_SUPPORTED,
                              "Command not supported");
                return -1;
        case 8:
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_ADDRESS_TYPE_NOT_SUPPORTED,
                              "Address type not supported");
                return -1;
        default:
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_UNKNOWN,
                              "Proxy reported an unknown error code");
                return -1;
        }

        if (addr_len == 0) {
                ntb_set_error(error,
                              &ntb_proxy_error,
                              NTB_PROXY_ERROR_BAD_PROTOCOL,
                              "Proxy replied wit an unknown address type");
                return -1;
        }

        proxy->state = NTB_PROXY_STATE_CONNECTED;

        return 4 + addr_len + 2;
}

bool
ntb_proxy_process_commands(struct ntb_proxy *proxy,
                           struct ntb_error **error)
{
        const uint8_t *in_buf = proxy->in_buf->data;
        size_t in_length = proxy->in_buf->length;
        ssize_t command_size = -1;

        while (true) {
                switch (proxy->state) {
                case NTB_PROXY_STATE_AWAITING_METHOD:
                        command_size = handle_method(proxy,
                                                     in_buf, in_length,
                                                     error);
                        break;

                case NTB_PROXY_STATE_AWAITING_REPLY:
                        command_size = handle_reply(proxy,
                                                    in_buf, in_length,
                                                    error);
                        break;

                case NTB_PROXY_STATE_CONNECTED:
                        goto done;
                }

                if (command_size == 0)
                        goto done;
                else if (command_size < 0)
                        return false;

                in_buf += command_size;
                in_length -= command_size;
        }

done:

        /* Move the data we've processed to the beginning of the buffer */
        memmove(proxy->in_buf->data, in_buf, in_length);
        proxy->in_buf->length = in_length;

        return true;
}

bool
ntb_proxy_is_connected(struct ntb_proxy *proxy)
{
        return proxy->state == NTB_PROXY_STATE_CONNECTED;
}

void
ntb_proxy_free(struct ntb_proxy *proxy)
{
        ntb_slice_free(&ntb_proxy_allocator, proxy);
}
