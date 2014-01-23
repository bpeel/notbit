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

#ifndef NTB_IPC_SOCKADDR_H
#define NTB_IPC_SOCKADDR_H

#include <sys/socket.h>
#include <stdbool.h>

#include "ntb-error.h"

extern struct ntb_error_domain
ntb_ipc_sockaddr_error;

enum ntb_ipc_sockaddr_error {
        NTB_IPC_SOCKADDR_ERROR_XDG
};

bool
ntb_ipc_sockaddr_create(struct sockaddr **sockaddr_out,
                        socklen_t *sockaddr_len_out,
                        struct ntb_error **error);

#endif /* NTB_IPC_SOCKADDR_H */
