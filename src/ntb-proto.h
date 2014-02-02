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

#ifndef NTB_PROTO_H
#define NTB_PROTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>

#include "ntb-buffer.h"
#include "ntb-netaddress.h"

extern struct ntb_error_domain
ntb_proto_error;

enum ntb_proto_error {
        NTB_PROTO_ERROR_PROTOCOL
};

enum ntb_proto_inv_type {
        NTB_PROTO_INV_TYPE_GETPUBKEY,
        NTB_PROTO_INV_TYPE_PUBKEY,
        NTB_PROTO_INV_TYPE_MSG,
        NTB_PROTO_INV_TYPE_BROADCAST
};

enum ntb_proto_argument {
        NTB_PROTO_ARGUMENT_8,
        NTB_PROTO_ARGUMENT_16,
        NTB_PROTO_ARGUMENT_32,
        NTB_PROTO_ARGUMENT_64,
        NTB_PROTO_ARGUMENT_BOOL,
        NTB_PROTO_ARGUMENT_VAR_INT,
        NTB_PROTO_ARGUMENT_TIMESTAMP,
        NTB_PROTO_ARGUMENT_NETADDRESS,
        NTB_PROTO_ARGUMENT_VAR_STR,
        NTB_PROTO_ARGUMENT_VAR_INT_LIST,
        NTB_PROTO_ARGUMENT_END
};

struct ntb_proto_var_str {
        uint64_t length;
        const char *data;
};

struct ntb_proto_var_int_list {
        uint64_t n_ints;
        const uint8_t *values;
};

struct ntb_proto_decrypted_msg {
        const uint8_t *sender_signing_key;
        const uint8_t *sender_encryption_key;
        uint64_t message_version;
        uint64_t sender_address_version;
        uint64_t sender_stream_number;
        uint32_t sender_behaviors;
        uint64_t nonce_trials_per_byte;
        uint64_t extra_bytes;
        const uint8_t *destination_ripe;
        uint64_t encoding;
        const uint8_t *message, *ack, *sig;
        uint64_t message_length, ack_length, sig_length;
        size_t signed_data_length;
};

struct ntb_proto_pubkey {
        uint64_t nonce;
        int64_t timestamp;

        uint64_t stream;
        uint64_t version;

        uint64_t address_version;
        uint32_t behaviours;

        const uint8_t *public_signing_key;
        const uint8_t *public_encryption_key;

        uint64_t nonce_trials_per_byte;
        uint64_t extra_bytes;

        uint64_t signature_length;
        const uint8_t *signature;

        size_t signed_data_length;
        const uint8_t *signed_data;

        const uint8_t *tag;

        size_t encrypted_data_length;
        const uint8_t *encrypted_data;
};

#define NTB_PROTO_HEADER_SIZE (4 + 12 + 4 + 4)

#define NTB_PROTO_VERSION UINT32_C(2)

#define NTB_PROTO_NETWORK_NODE UINT64_C(1)
#define NTB_PROTO_SERVICES (NTB_PROTO_NETWORK_NODE)

/* The hashes in Bitmessage are an SHA512 digest but only the first 32
 * bytes are used */
#define NTB_PROTO_HASH_LENGTH (SHA512_DIGEST_LENGTH / 2)

#define NTB_PROTO_MIN_NONCE_TRIALS_PER_BYTE 320
#define NTB_PROTO_MIN_EXTRA_BYTES 14000

/* In addition to the maximum age of an object defined by the
 * protocol, we won't delete objects on disk for this amount of extra
 * time so that we can cope with clocks that are a bit different and
 * won't request objects from peers */
#define NTB_PROTO_EXTRA_AGE (6 * 60 * 60 /* 6 hours */)

#define NTB_PROTO_DEFAULT_PORT 8444

/* We send acknowledgements */
#define NTB_PROTO_PUBKEY_BEHAVIORS UINT32_C(0x00000001)

extern const uint8_t
ntb_proto_magic[4];

void
ntb_proto_double_hash(const void *data,
                      int length,
                      uint8_t *hash);

void
ntb_proto_address_hash(const void *data,
                       int length,
                       uint8_t *hash);

bool
ntb_proto_check_command_string(const uint8_t *command_string);

int64_t
ntb_proto_get_max_age_for_type(enum ntb_proto_inv_type type);

const char *
ntb_proto_get_command_name_for_type(enum ntb_proto_inv_type type);

static inline uint8_t
ntb_proto_get_8(const uint8_t *p)
{
        return *p;
}

uint16_t
ntb_proto_get_16(const uint8_t *p);

uint32_t
ntb_proto_get_32(const uint8_t *p);

uint64_t
ntb_proto_get_64(const uint8_t *p);

bool
ntb_proto_get_var_int(const uint8_t **p_ptr,
                      uint32_t *length_ptr,
                      uint64_t *result);

bool
ntb_proto_get_timestamp(const uint8_t **p_ptr,
                        uint32_t *length_ptr,
                        int64_t *result);

bool
ntb_proto_get_var_str(const uint8_t **p_ptr,
                      uint32_t *length_ptr,
                      struct ntb_proto_var_str *result);

bool
ntb_proto_get_var_int_list(const uint8_t **p_ptr,
                           uint32_t *length_ptr,
                           struct ntb_proto_var_int_list *result);

ssize_t
ntb_proto_get_command_va_list(const uint8_t *data,
                              uint32_t length,
                              va_list ap);

ssize_t
ntb_proto_get_command(const uint8_t *data,
                      uint32_t length,
                      ...);

bool
ntb_proto_get_decrypted_msg(const uint8_t *data,
                            uint32_t length,
                            struct ntb_proto_decrypted_msg *msg);

bool
ntb_proto_get_pubkey(bool decrypted,
                     const uint8_t *data,
                     uint32_t length,
                     struct ntb_proto_pubkey *pubkey);

static inline void
ntb_proto_add_8(struct ntb_buffer *buf,
                uint8_t value)
{
        ntb_buffer_append_c(buf, value);
}

static inline void
ntb_proto_add_16(struct ntb_buffer *buf,
                 uint16_t value)
{
        value = NTB_UINT16_TO_BE(value);
        ntb_buffer_append(buf, (uint8_t *) &value, sizeof value);
}

static inline void
ntb_proto_add_32(struct ntb_buffer *buf,
                 uint32_t value)
{
        value = NTB_UINT32_TO_BE(value);
        ntb_buffer_append(buf, (uint8_t *) &value, sizeof value);
}

static inline void
ntb_proto_add_64(struct ntb_buffer *buf,
                 uint64_t value)
{
        value = NTB_UINT64_TO_BE(value);
        ntb_buffer_append(buf, (uint8_t *) &value, sizeof value);
}

static inline void
ntb_proto_add_bool(struct ntb_buffer *buf,
                   int value)
{
        ntb_proto_add_8(buf, !!value);
}

void
ntb_proto_add_var_int(struct ntb_buffer *buf,
                      uint64_t value);

void
ntb_proto_add_timestamp(struct ntb_buffer *buf);

void
ntb_proto_add_netaddress(struct ntb_buffer *buf,
                         const struct ntb_netaddress *address);

void
ntb_proto_add_var_str(struct ntb_buffer *buf,
                      const char *str);

void
ntb_proto_add_public_key(struct ntb_buffer *buf,
                         const EC_KEY *key);

void
ntb_proto_begin_command(struct ntb_buffer *buf,
                        const char *command);

void
ntb_proto_end_command(struct ntb_buffer *buf,
                      size_t command_start);

void
ntb_proto_add_command(struct ntb_buffer *buf,
                      const char *command,
                      ...);

void
ntb_proto_add_command_va_list(struct ntb_buffer *buf,
                              const char *command,
                              va_list ap);

#endif /* NTB_PROTO_H */
