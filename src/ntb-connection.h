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

#ifndef NTB_CONNECTION_H
#define NTB_CONNECTION_H

#include <stdint.h>
#include <stdbool.h>

#include "ntb-error.h"
#include "ntb-netaddress.h"
#include "ntb-buffer.h"
#include "ntb-main-context.h"
#include "ntb-signal.h"
#include "ntb-proto.h"
#include "ntb-blob.h"

extern struct ntb_error_domain
ntb_connection_error;

enum ntb_connection_error {
        NTB_CONNECTION_ERROR_SOCKET,
        NTB_CONNECTION_ERROR_CONNECT,
        NTB_CONNECTION_ERROR_ACCEPT
};

enum ntb_connection_message_type {
        NTB_CONNECTION_MESSAGE_CONNECT_FAILED,
        NTB_CONNECTION_MESSAGE_ERROR,

        NTB_CONNECTION_MESSAGE_VERSION,
        NTB_CONNECTION_MESSAGE_INV,
        NTB_CONNECTION_MESSAGE_OBJECT
};

struct ntb_connection_message {
        enum ntb_connection_message_type type;
        struct ntb_connection *connection;
};

struct ntb_connection_version_message {
        struct ntb_connection_message base;

        uint32_t version;
        uint64_t services;
        int64_t timestamp;

        struct ntb_netaddress addr_recv;
        struct ntb_netaddress addr_from;

        uint64_t nonce;
        struct ntb_proto_var_str user_agent;
        struct ntb_proto_var_int_list stream_numbers;
};

struct ntb_connection_object_message {
        struct ntb_connection_message base;

        enum ntb_blob_type type;

        uint64_t nonce;
        int64_t timestamp;
        uint64_t stream_number;

        const uint8_t *object_data;
        size_t object_data_length;

        union {
                struct {
                        const uint8_t *ripe;
                        const uint8_t *tag;
                        uint64_t address_version;
                } getpubkey;

                struct {
                        uint64_t address_version;
                        uint32_t behaviours;

                        const uint8_t *public_signing_key;
                        const uint8_t *public_encryption_key;

                        uint64_t nonce_trials_per_byte;
                        uint64_t extra_bytes;

                        uint64_t signature_length;
                        const uint8_t *signature;

                        const uint8_t *tag;

                        size_t encrypted_data_length;
                        const uint8_t *encrypted_data;
                } pubkey;

                struct {
                        const uint8_t *encrypted_data;
                        size_t encrypted_data_length;
                } msg;

                struct {
                        uint64_t version;

                        const uint8_t *tag;

                        const uint8_t *encrypted_data;
                        size_t encrypted_data_length;
                } broadcast;
        };
};

struct ntb_connection_inv_message {
        struct ntb_connection_message base;

        uint64_t n_inventories;
        const uint8_t *inventories;
};

struct ntb_connection *connection;

struct ntb_connection *
ntb_connection_connect(const struct ntb_netaddress *address,
                       struct ntb_error **error);

struct ntb_connection *
ntb_connection_accept(int server_sock,
                      struct ntb_error **error);

void
ntb_connection_free(struct ntb_connection *conn);

struct ntb_signal *
ntb_connection_get_message_signal(struct ntb_connection *conn);

const char *
ntb_connection_get_remote_address_string(struct ntb_connection *conn);

const struct ntb_netaddress *
ntb_connection_get_remote_address(struct ntb_connection *conn);

void
ntb_connection_send_verack(struct ntb_connection *conn);

void
ntb_connection_send_version(struct ntb_connection *conn,
                            uint64_t nonce,
                            const struct ntb_netaddress *local_address);

void
ntb_connection_begin_getdata(struct ntb_connection *conn);

void
ntb_connection_add_getdata_hash(struct ntb_connection *conn,
                                const uint8_t *hash);

void
ntb_connection_end_getdata(struct ntb_connection *conn);

#endif /* NTB_CONNECTION_H */
