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
#include <sys/types.h>
#include <unistd.h>
#include <stddef.h>

#include "ntb-ipc-sockaddr.h"
#include "ntb-util.h"
#include "ntb-buffer.h"

void
ntb_ipc_sockaddr_create(struct sockaddr **sockaddr_out,
                        socklen_t *sockaddr_len_out)
{
        const char *runtime_dir;
        struct ntb_buffer buffer;
        struct sockaddr_un *sockaddr;

        ntb_buffer_init(&buffer);

        ntb_buffer_set_length(&buffer, offsetof(struct sockaddr_un, sun_path));

        runtime_dir = getenv("XDG_RUNTIME_DIR");

        if (runtime_dir) {
                ntb_buffer_append_string(&buffer, runtime_dir);

                while (buffer.length > offsetof(struct sockaddr_un, sun_path) &&
                       buffer.data[buffer.length - 1] == '/')
                        buffer.length--;

                ntb_buffer_append_string(&buffer, "/notbit/notbit-ipc");
        } else {
                ntb_buffer_append_printf(&buffer,
                                         "/tmp/notbit-%i/notbit-ipc",
                                         (int) getuid());
        }

        sockaddr = (struct sockaddr_un *) buffer.data;

        sockaddr->sun_family = AF_LOCAL;

        *sockaddr_out = (struct sockaddr *) sockaddr;
        *sockaddr_len_out = buffer.length;
}
