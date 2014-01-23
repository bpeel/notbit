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

#ifndef NTB_IPC_PROTO_H
#define NTB_IPC_PROTO_H

enum ntb_ipc_proto_status {
        NTB_IPC_PROTO_STATUS_SUCCESS = 0,
        NTB_IPC_PROTO_STATUS_INVALID_COMMAND,
        NTB_IPC_PROTO_STATUS_FD_ERROR
};

#endif /* NTB_IPC_PROTO_H */
