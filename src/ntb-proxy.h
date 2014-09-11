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

#ifndef NTB_PROXY_H
#define NTB_PROXY_H

#include "ntb-error.h"
#include "ntb-netaddress.h"
#include "ntb-buffer.h"

struct ntb_proxy;

extern struct ntb_error_domain
ntb_proxy_error;

enum ntb_proxy_error {
        NTB_PROXY_ERROR_BAD_PROTOCOL,
        NTB_PROXY_ERROR_NO_AUTHENTICATION_UNSUPPORTED,
        NTB_PROXY_ERROR_GENERAL_SOCKS_SERVER_FAILURE,
        NTB_PROXY_ERROR_CONNECTION_NOT_ALLOWED_BY_RULESET,
        NTB_PROXY_ERROR_NETWORK_UNREACHABLE,
        NTB_PROXY_ERROR_HOST_UNREACHABLE,
        NTB_PROXY_ERROR_CONNECTION_REFUSED,
        NTB_PROXY_ERROR_TTL_EXPIRED,
        NTB_PROXY_ERROR_COMMAND_NOT_SUPPORTED,
        NTB_PROXY_ERROR_ADDRESS_TYPE_NOT_SUPPORTED,
        NTB_PROXY_ERROR_UNKNOWN
};

struct ntb_proxy *
ntb_proxy_new(const struct ntb_netaddress *dst_addr,
              struct ntb_buffer *in_buf,
              struct ntb_buffer *out_buf);

bool
ntb_proxy_process_commands(struct ntb_proxy *proxy,
                           struct ntb_error **error);

bool
ntb_proxy_is_connected(struct ntb_proxy *proxy);

void
ntb_proxy_free(struct ntb_proxy *proxy);

#endif /* NTB_PROXY_H */
