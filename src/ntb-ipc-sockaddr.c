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

#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>

#include "ntb-ipc-sockaddr.h"
#include "ntb-util.h"

struct ntb_error_domain
ntb_ipc_sockaddr_error;

bool
ntb_ipc_sockaddr_create(struct sockaddr **sockaddr_out,
                        socklen_t *sockaddr_len_out,
                        struct ntb_error **error)
{
        const char *runtime_dir;
        int runtime_dir_len;
        socklen_t addr_len;
        static const char socket_name[] = "/notbit/notbit-ipc";
        struct sockaddr_un *sockaddr;

        runtime_dir = getenv("XDG_RUNTIME_DIR");

        if (runtime_dir == NULL) {
                ntb_set_error(error,
                              &ntb_ipc_sockaddr_error,
                              NTB_IPC_SOCKADDR_ERROR_XDG,
                              "XDG_RUNTIME_DIR is not set");
                return false;
        }

        runtime_dir_len = strlen(runtime_dir);

        while (runtime_dir_len > 0 &&
               runtime_dir[runtime_dir_len - 1] == '/')
                runtime_dir_len--;

        addr_len = (NTB_STRUCT_OFFSET(struct sockaddr_un, sun_path) +
                    runtime_dir_len +
                    sizeof socket_name);
        sockaddr = ntb_alloc(addr_len);

        sockaddr->sun_family = AF_LOCAL;

        memcpy(sockaddr->sun_path, runtime_dir, runtime_dir_len);
        memcpy(sockaddr->sun_path + runtime_dir_len,
               socket_name,
               sizeof socket_name);

        *sockaddr_out = (struct sockaddr *) sockaddr;
        *sockaddr_len_out = addr_len;

        return true;
}
