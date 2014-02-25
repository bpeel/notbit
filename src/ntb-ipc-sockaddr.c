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

#include <sys/socket.h>
#include <sys/un.h>

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
